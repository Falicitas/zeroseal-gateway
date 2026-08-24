package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroseal/shared/catalog"
)

// TaskState 是我们对上游任务状态的归一化。
//
// 给客户的响应体是上游原文（保持透传），归一化只用于内部决策：这个任务该不该
// 结算、还要不要接着轮询。认不出的状态一律当 TaskRunning —— 多轮询一次没有
// 代价，把还在跑的任务误判成失败去退款则收不回来。
type TaskState string

const (
	TaskRunning   TaskState = "running"
	TaskSucceeded TaskState = "succeeded"
	TaskFailed    TaskState = "failed"
)

// VideoAdapter 是视频生成 surface 的适配器。
//
// 跟前三个 surface 的根本区别是它有两段：提交拿任务 ID、轮询取结果。预扣发生
// 在第一段，结算发生在第二段，中间隔着几分钟和至少一次独立的 HTTP 往返 ——
// 这也是唯一一个需要把中间状态落库的 surface。
type VideoAdapter interface {
	Path() string
	SetHeaders(h http.Header, key string)
	RewriteRequest(body []byte, p catalog.Provider) ([]byte, error)

	// EstimateUsage 从请求参数推最坏情况用量，喂给 billing.Settle 就是预扣额。
	EstimateUsage(body []byte) (catalog.Usage, error)

	// ParseSubmit 从提交响应里取上游任务 ID。取不到就没法结算了，调用方必须退款。
	ParseSubmit(body []byte) (string, bool)

	// PollPath 是查某个任务的相对路径。
	PollPath(upstreamID string) string

	// ParseTask 解析轮询响应。ok=false 表示响应体根本解析不了，什么都别做；
	// ok=true 时 state 可信，而 Usage 只在 TaskSucceeded 且上游确实给了用量时非空。
	ParseTask(body []byte) (state TaskState, usage catalog.Usage, ok bool)
}

// videoAdapters 按 provider 索引，跟其他三张表同形。
var videoAdapters = map[string]VideoAdapter{
	"volc":    volcVideo{},
	"minimax": minimaxVideo{},
}

// VideoFor 取 provider 的视频适配器。
func VideoFor(provider string) (VideoAdapter, bool) {
	a, ok := videoAdapters[provider]
	return a, ok
}

// SubmitVideo 提交生成任务。提交本身很快（上游只是入队就返回任务 ID），
// 不需要图像那种加长的 client。
func SubmitVideo(ctx context.Context, a VideoAdapter, p catalog.Provider, key string, body []byte) (*Response, error) {
	upBody, err := a.RewriteRequest(body, p)
	if err != nil {
		return nil, err
	}
	req, err := buildRequest(ctx, a, p, key, upBody)
	if err != nil {
		return nil, err
	}
	return readAll(httpClient, req)
}

// PollVideo 查任务状态。是 GET 而且路径带任务 ID，所以走不了 buildRequest。
func PollVideo(ctx context.Context, a VideoAdapter, p catalog.Provider, key, upstreamID string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+a.PollPath(upstreamID), nil)
	if err != nil {
		return nil, err
	}
	a.SetHeaders(req.Header, key)
	return readAll(httpClient, req)
}

type volcVideo struct{}

func (volcVideo) Path() string { return "/contents/generations/tasks" }

func (volcVideo) PollPath(upstreamID string) string {
	return "/contents/generations/tasks/" + url.PathEscape(upstreamID)
}

func (volcVideo) SetHeaders(h http.Header, key string) {
	h.Set("Authorization", "Bearer "+key)
}

// RewriteRequest 只换 model。请求里那个 content 数组（text / image_url /
// video_url / audio_url 各带自己的 role）原样透传 —— 那是上游自己的形状，
// 我们不认识也不需要认识，认了反而会在上游加新 part 类型时挡住客户。
func (volcVideo) RewriteRequest(body []byte, p catalog.Provider) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // 同 chat/image：别把客户的大整数参数（seed 之类）用 float64 改了值
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	m["model"] = p.UpstreamID
	return json.Marshal(m)
}

// videoReq 是预扣要看的请求字段，其余原样透传。
// resolution 和 duration 客户都可以不传，上游有自己的默认值，所以缺省要跟上游对齐。
type videoReq struct {
	Duration   int64  `json:"duration"`
	Resolution string `json:"resolution"`
	Content    []struct {
		Type string `json:"type"`
	} `json:"content"`
}

// tierOfVideo 按「分辨率 × 有无视频输入」定档。
//
// 有无视频输入是请求的属性，轮询响应里查不到，所以整个档位在提交时就定下来
// 存进 video_tasks，结算时从那儿取。分辨率认不出时落最贵那档 —— 预扣宁可多，
// 而且那种请求上游本来就会拒。
func tierOfVideo(r videoReq) string {
	edit := false
	for _, part := range r.Content {
		if part.Type == "video_url" {
			edit = true
			break
		}
	}

	res := strings.ToLower(strings.TrimSpace(r.Resolution))
	if res == "" {
		res = videoDefaultResolution
	}
	low := res == "480p" || res == "720p"

	switch {
	case low && edit:
		return catalog.TierVideoLowEdit
	case low:
		return catalog.TierVideoLowGen
	case edit:
		return catalog.TierVideoHighEdit
	default:
		return catalog.TierVideoHighGen
	}
}

// videoTokensPerSecond 是各分辨率每秒的 token 数，**只用于预扣**。
//
// 两个实测点（2026-08-19，均 24fps 带音频）：
//
//	720p  11 秒 411300 token → 每秒 37391
//	480p   4 秒  86867 token → 每秒 21717
//
// 按像素线性外推是错的：480p 的像素只有 720p 的 44%，token 却有 58%。
// 两点拟合出每秒约 0.0309×像素 + 8900，那个常数项跟分辨率无关，大概是音轨。
// 我一开始按纯像素比例估的 480p（16700）比实测低 23%，每发都要补扣。
//
// 1080p 仍是外推值：线性模型给 73000，这里留 84200 不往下调 —— 预扣宁可多，
// 多了结算时退，少了要从余额补扣。有实测数据再改。
//
// 估偏只影响预扣多少，结算永远以轮询响应里的 completion_tokens 为准。
var videoTokensPerSecond = map[string]int64{
	"480p":  21_800, // 实测 21717，向上取整
	"720p":  37_400, // 实测 37391
	"1080p": 84_200, // 外推，故意偏高
}

const (
	// videoDefaultResolution 是上游的默认分辨率（实测），客户不传时按它估。
	videoDefaultResolution = "720p"

	// videoDefaultDuration 是客户不传时假定的秒数。比常见的 5/10 秒留一档余量，
	// 预扣宁可多一点 —— 少了要在结算时从余额补扣。
	videoDefaultDuration = 12

	// videoMaxTokensPerSec 是认不出分辨率时的兜底，按比 1080p 更高一档估。
	videoMaxTokensPerSec = 300_000

	// videoMaxDuration 是上游允许的最长时长（文档写 4-30 秒）。预扣按它封顶：
	// 客户手滑传个 duration=1000 的话，不封顶会算出上千元的预扣、当场 402，
	// 而这个请求本来该由上游返 400。封顶之后预扣不足也无所谓——上游会拒，
	// 我们照常退款。
	videoMaxDuration = 30
)

func (volcVideo) EstimateUsage(body []byte) (catalog.Usage, error) {
	var r videoReq
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	dur := r.Duration
	if dur <= 0 {
		dur = videoDefaultDuration
	}
	if dur > videoMaxDuration {
		dur = videoMaxDuration
	}

	res := strings.ToLower(strings.TrimSpace(r.Resolution))
	if res == "" {
		res = videoDefaultResolution
	}
	perSec, ok := videoTokensPerSecond[res]
	if !ok {
		perSec = videoMaxTokensPerSec
	}

	return catalog.Usage{{Tier: tierOfVideo(r), Output: dur * perSec}}, nil
}

func (volcVideo) ParseSubmit(body []byte) (string, bool) {
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.ID == "" {
		return "", false
	}
	return r.ID, true
}

// taskResp 是轮询响应里我们要看的部分。video_url、resolution、seed 那些
// 全部原样透传给客户，这里只取状态和用量。
type taskResp struct {
	Status string `json:"status"`
	Usage  *struct {
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
}

func (volcVideo) ParseTask(body []byte) (TaskState, catalog.Usage, bool) {
	var r taskResp
	if err := json.Unmarshal(body, &r); err != nil {
		return TaskRunning, nil, false
	}

	switch r.Status {
	case "succeeded":
		if r.Usage == nil || r.Usage.CompletionTokens <= 0 {
			// 说成功却没给用量。state 仍然可信（任务确实终态了），但没法按量结算，
			// 交给调用方决定 —— 见 video.Finish。
			return TaskSucceeded, nil, true
		}
		return TaskSucceeded, catalog.Usage{{
			Tier:   catalog.TierDefault,
			Output: r.Usage.CompletionTokens,
		}}, true

	case "failed", "cancelled", "canceled":
		return TaskFailed, nil, true

	default:
		// queued / running / 以及任何我们没见过的状态，一律当还在跑。
		return TaskRunning, nil, true
	}
}
