package llm

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/zeroseal/shared/catalog"
)

// httpClient 故意不设 Client.Timeout —— 那是请求全程上限，会砍断 SSE 长连接。
// 超时靠 Transport 分段控制 + 传入的 ctx。
var httpClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext, // DNS + TCP 握手总时间
		ResponseHeaderTimeout: 60 * time.Second,                                     // 等上游第一个响应头，不限制 body 读取
		MaxIdleConnsPerHost:   32,
	},
}

// ImageTimeout 是图像生成的整体上限，调用方的 ctx 用它。
const ImageTimeout = 10 * time.Minute

// imageClient 跟 httpClient 只差一个 ResponseHeaderTimeout。
//
// 图像生成是同步接口：上游要把图画完才回第一个响应头，「等首头」就等于
// 「等全程」，chat 那个 60 秒当场就不够（实测 1K 单图直接超）。这里放到跟
// 整体上限一样，真正的兜底交给调用方的 ctx。
var imageClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: ImageTimeout,
		MaxIdleConnsPerHost:   8,
	},
}

// Response 是上游返回的结果。header 只保留 Content-Type，其余按约定丢弃。
type Response struct {
	Status      int
	ContentType string
	Body        []byte
}

type requester interface {
	Path() string
	SetHeaders(h http.Header, key string)
}

// buildRequest 拼上游请求。upBody 必须是已经过 adapter 改写的请求体。
func buildRequest(ctx context.Context, r requester, p catalog.Provider, key string, upBody []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+r.Path(), bytes.NewReader(upBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	r.SetHeaders(req.Header, key)
	return req, nil
}

// readAll 用指定的 client 发请求并读满响应。
func readAll(client *http.Client, req *http.Request) (*Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // 应用层的资源归还（把这次响应占用的那条底层 TCP 连接的控制权还给 Transport，让它决定复用还是关闭。），并非 TCP 层的关连接

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}

	return &Response{
		Status:      resp.StatusCode,
		ContentType: ct,
		Body:        respBody,
	}, nil
}

// Forward 把对话请求转到上游并读满响应。不校验、不计费 —— 这些在调用侧按需要挂。
func Forward(ctx context.Context, a Adapter, p catalog.Provider, key string, body []byte) (*Response, error) {
	upBody, err := a.RewriteRequest(body, p, false)
	if err != nil {
		return nil, err
	}
	req, err := buildRequest(ctx, a, p, key, upBody)
	if err != nil {
		return nil, err
	}
	return readAll(httpClient, req)
}

// ForwardImage 把图像生成请求转到上游。seedream 是同步接口，一次往返拿到结果，
// 但那一次往返要等上游把图画完，所以走 imageClient 而不是 httpClient。
func ForwardImage(ctx context.Context, a ImageAdapter, p catalog.Provider, key string, body []byte) (*Response, error) {
	upBody, err := a.RewriteRequest(body, p)
	if err != nil {
		return nil, err
	}
	req, err := buildRequest(ctx, a, p, key, upBody)
	if err != nil {
		return nil, err
	}
	return readAll(imageClient, req)
}

// StreamResult 是流式转发的结果。Usage 为空表示没扫到（上游中途断、或没带回 usage）。
type StreamResult struct {
	Usage      catalog.Usage
	ClientGone bool // 客户端中途断连（写失败），但上游仍读完了
}

// ForwardStream 转发流式请求。
// readCtx 控制读上游（用独立 ctx，客户端断也读完）；
// w/flusher 是写给客户端的通道，写失败说明客户端走了，标记 ClientGone 但继续读上游拿 usage。
func ForwardStream(
	readCtx context.Context,
	a Adapter, p catalog.Provider, key string, body []byte,
	w io.Writer, flush func(),
) (*StreamResult, error) {
	upBody, err := a.RewriteRequest(body, p, true)
	if err != nil {
		return nil, err
	}
	req, err := buildRequest(readCtx, a, p, key, upBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 上游非 2xx：不是流，读满错误体返回，让 handler 决定退款。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, &UpstreamError{Status: resp.StatusCode, Body: errBody}
	}

	result := &StreamResult{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 单行上限 1MB，长 chunk 够用

	for sc.Scan() {
		line := sc.Bytes()

		// 原样写给客户端（连同换行）。写失败=客户端断连，标记后继续读上游。
		if !result.ClientGone {
			if _, werr := w.Write(append(line, '\n')); werr != nil {
				result.ClientGone = true
			} else {
				flush()
			}
		}

		// 扫 usage：只认 data: 开头、非 [DONE] 的行，解析交给 adapter。
		payload, ok := bytes.CutPrefix(line, []byte("data: "))
		if !ok || bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) {
			continue
		}
		if u, ok := a.ParseUsage(payload); ok {
			result.Usage = u
		}
	}
	if err := sc.Err(); err != nil {
		// 上游流中途断（读错误）。已扫到的 usage 可能为 nil。
		return result, err
	}
	return result, nil
}

// UpstreamError 上游返回非 2xx。
type UpstreamError struct {
	Status int
	Body   []byte
}

func (e *UpstreamError) Error() string { return "upstream status " + http.StatusText(e.Status) }
