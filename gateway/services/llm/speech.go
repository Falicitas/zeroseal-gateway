package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/zeroseal/shared/catalog"
)

// SpeechAdapter 是语音合成 surface 的适配器。
//
// 这是第一个真正需要「翻译」的 surface：上游 DashScope 的请求体把参数嵌在
// input 对象里，跟 OpenAI 那套平铺的 /v1/audio/speech 结构完全不同；响应也
// 不是裸音频，而是 SSE 流里一段段 base64。两边的形状都要转。
type SpeechAdapter interface {
	Path() string

	// SetHeaders 除了鉴权还要开上游的流式开关 —— 我们对外返裸音频字节，
	// 只有流式模式才能边收边写，非流式只会给一个 OSS 链接。
	SetHeaders(h http.Header, key string)

	RewriteRequest(body []byte, p catalog.Provider) ([]byte, error)

	// EstimateUsage 数请求文本的字符数，用来预扣。
	EstimateUsage(body []byte) (catalog.Usage, error)

	// ContentType 返给客户端的音频 MIME，由请求里的格式决定。
	ContentType(body []byte) string

	// ScanChunk 从一个 SSE data 事件里取音频字节和用量。两者都可能为空：
	// sentence-begin 那类事件只有文本没有音频。
	ScanChunk(payload []byte) (audio []byte, usage catalog.Usage, ok bool)
}

// speechAdapters 按 provider 索引。语音这条路目前只有百炼。
var speechAdapters = map[string]SpeechAdapter{
	"bailian": bailianSpeech{},
}

// SpeechFor 取 provider 的语音适配器。
func SpeechFor(provider string) (SpeechAdapter, bool) {
	a, ok := speechAdapters[provider]
	return a, ok
}

// SpeechTimeout 是语音合成的整体上限，调用方的 ctx 用它。
// 首包很快（流式），这个上限管的是长文本一路合成完的总时长。
const SpeechTimeout = 5 * time.Minute

// defaultVoice 是客户没指定音色时用的。DashScope 的 voice 是必填参数，
// 而 OpenAI 那边可以不传，所以得有个兜底。
const defaultVoice = "longanhuan_v3.6"

// defaultFormat 跟 OpenAI 的默认值对齐。不显式指定的话上游实测返 wav，
// 跟它自己文档写的 mp3 不一致，那就没法照请求推断该报什么 Content-Type。
const defaultFormat = "mp3"

type bailianSpeech struct{}

func (bailianSpeech) Path() string { return "/services/audio/tts/SpeechSynthesizer" }

func (bailianSpeech) SetHeaders(h http.Header, key string) {
	h.Set("Authorization", "Bearer "+key)
	h.Set("X-DashScope-SSE", "enable")
}

// speechReq 是 OpenAI /v1/audio/speech 的请求形状。
// Bailian 是非标参数的命名空间，里面的键原样合进上游的 input 对象 ——
// sample_rate、instruction、hot_fix、enable_ssml 这些 OpenAI 没有的能力
// 走这里，不然客户就用不上。
type speechReq struct {
	Input          string         `json:"input"`
	Voice          string         `json:"voice"`
	ResponseFormat string         `json:"response_format"`
	Speed          float64        `json:"speed"`
	Bailian        map[string]any `json:"bailian"`
}

// RewriteRequest 把平铺的 OpenAI 请求折成 DashScope 的 {model, input:{...}}。
func (bailianSpeech) RewriteRequest(body []byte, p catalog.Provider) ([]byte, error) {
	var r speechReq
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if r.Input == "" {
		return nil, errors.New("input 为空")
	}

	voice := r.Voice
	if voice == "" {
		voice = defaultVoice
	}

	// 文档说上游 format 默认 mp3，但 qwen-audio-3.0-tts-plus 实测默认返 wav。
	// 显式填上，好让 ContentType 报的跟客户实际拿到的一致。
	format := r.ResponseFormat // OpenAI 的 response_format 对应上游的 format
	if format == "" {
		format = defaultFormat
	}

	input := map[string]any{"text": r.Input, "voice": voice, "format": format}
	if r.Speed > 0 {
		input["rate"] = r.Speed // OpenAI 的 speed 对应上游的 rate，取值区间都是 [0.5, 2.0]
	}
	// 非标参数后合并，允许客户覆盖上面翻译出来的值
	for k, v := range r.Bailian {
		input[k] = v
	}

	return json.Marshal(map[string]any{
		"model": p.UpstreamID,
		"input": input,
	})
}

func (bailianSpeech) EstimateUsage(body []byte) (catalog.Usage, error) {
	var r speechReq
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	n := countBillingChars(r.Input)
	if n == 0 {
		return nil, errors.New("input 为空")
	}
	return catalog.Usage{{Tier: catalog.TierDefault, Input: n}}, nil
}

// countBillingChars 按上游的计费口径数字符，用来预扣。真实账单以响应里的
// usage.characters 为准。
//
// 实测百炼是「中文算 2、ASCII 算 1」，不是简单的字符数：
//
//	好                   → 2       abcdefghij           → 10
//	你好世界             → 8       一二三四五六七八九十 → 20
//
// 全角标点实测算 1（「我家的后面有一个很大的花园。」13 字 + 句号报 27 而不是
// 28），这里不区分，一律非 ASCII 算 2 —— 预扣宁可多一点也别少。
func countBillingChars(s string) int64 {
	var n int64
	for _, r := range s {
		if r > 127 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func (bailianSpeech) ContentType(body []byte) string {
	var r speechReq
	_ = json.Unmarshal(body, &r) // 解不出就按上游默认的 mp3 算
	switch r.ResponseFormat {
	case "wav":
		return "audio/wav"
	case "pcm":
		return "audio/pcm"
	case "opus":
		return "audio/opus"
	default:
		return "audio/mpeg" // 上游 format 默认 mp3
	}
}

// speechChunk 是一个 SSE 事件里我们关心的部分。
type speechChunk struct {
	Output *struct {
		Audio *struct {
			Data string `json:"data"` // 流式时是 base64 音频块
		} `json:"audio"`
	} `json:"output"`
	Usage *struct {
		Characters int64 `json:"characters"`
	} `json:"usage"`
}

func (bailianSpeech) ScanChunk(payload []byte) ([]byte, catalog.Usage, bool) {
	var c speechChunk
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, nil, false
	}

	var audio []byte
	if c.Output != nil && c.Output.Audio != nil && c.Output.Audio.Data != "" {
		b, err := base64.StdEncoding.DecodeString(c.Output.Audio.Data)
		if err != nil {
			return nil, nil, false
		}
		audio = b
	}

	var u catalog.Usage
	if c.Usage != nil && c.Usage.Characters > 0 {
		u = catalog.Usage{{Tier: catalog.TierDefault, Input: c.Usage.Characters}}
	}
	return audio, u, true
}

// SpeechResult 是流式合成的结果。
type SpeechResult struct {
	Usage      catalog.Usage
	ClientGone bool // 客户端中途断连，但上游仍读完了
	// Bytes 是上游产出的音频字节数，不是送达客户端的字节数。它唯一的用途
	// 是判断上游到底合成了没有，跟客户端断没断连无关。
	Bytes int64
}

// ForwardSpeech 流式转发语音合成：上游走 SSE，逐块解 base64，把裸音频字节
// 写给客户端。
//
// onStart 在确认上游 2xx 之后、写第一个字节之前调一次，让调用方来定响应头。
// 上游非 2xx 时一个字节都不会写，调用方还能正常返 JSON 错误。
func ForwardSpeech(
	readCtx context.Context,
	a SpeechAdapter, p catalog.Provider, key string, body []byte,
	onStart func(), w io.Writer, flush func(),
) (*SpeechResult, error) {
	upBody, err := a.RewriteRequest(body, p)
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, &UpstreamError{Status: resp.StatusCode, Body: errBody}
	}

	onStart()

	result := &SpeechResult{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // 音频块比文本 chunk 大，缓冲给到 4MB

	for sc.Scan() {
		// DashScope 的 SSE 是 `data:{...}`，中间不一定有空格
		payload, ok := bytes.CutPrefix(bytes.TrimSpace(sc.Bytes()), []byte("data:"))
		if !ok {
			continue
		}
		audio, u, ok := a.ScanChunk(bytes.TrimSpace(payload))
		if !ok {
			continue
		}
		if len(u) > 0 {
			result.Usage = u // 上游每个事件都带累计字符数，末尾那个才是最终值
		}
		if len(audio) == 0 {
			continue
		}
		// 先记账再写。记成「送达量」的话，客户端在第一个音频块就断连会让
		// Bytes 停在 0，被 handler 误判成「上游没产出」而全额退款——可上游
		// 那边活已经干完、钱已经花了。断连的账按真实用量结算，跟 chat 一致。
		result.Bytes += int64(len(audio))
		if result.ClientGone {
			continue
		}
		if _, werr := w.Write(audio); werr != nil {
			result.ClientGone = true // 客户端走了，但继续读上游把 usage 拿全
			continue
		}
		flush()
	}
	if err := sc.Err(); err != nil {
		return result, err
	}
	return result, nil
}
