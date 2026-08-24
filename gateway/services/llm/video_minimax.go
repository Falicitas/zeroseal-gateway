package llm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroseal/shared/catalog"
)

// minimaxVideo 是 MiniMax 的视频适配器。
//
// 跟火山那套处处不一样，一条条列出来免得以后有人以为能合并：
//   - 提交响应的 key 是 task_id，火山是 id
//   - 轮询路径换了前缀（/query/video_generation/...），不是在提交路径后面接 ID
//   - 轮询响应整个包在 task 对象里，火山是平铺的
//   - 任务还在跑时 usage 是空对象 {} 而不是缺失，所以判空不能只判 nil
//   - 出错时返回的是 {"type":"error","error":{...}}，里面根本没有 task
//   - 计费按秒不按 token（响应里那个 total_tokens 是统计，不是账单依据）
type minimaxVideo struct{}

func (minimaxVideo) Path() string { return "/video_generation" }

func (minimaxVideo) PollPath(upstreamID string) string {
	return "/query/video_generation/" + url.PathEscape(upstreamID)
}

func (minimaxVideo) SetHeaders(h http.Header, key string) {
	h.Set("Authorization", "Bearer "+key)
}

// RewriteRequest 只换 model，其余原样透传，同 volc。
func (minimaxVideo) RewriteRequest(body []byte, p catalog.Provider) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	m["model"] = p.UpstreamID
	return json.Marshal(m)
}

// minimaxFreeInputImages 是免费的输入图张数，超出的部分才计费。
// 跟 seedream「首张免费」是同一个套路，只是免费额度不同。
const minimaxFreeInputImages = 5

// minimaxDefaultResolution 是客户不传 resolution 时我们假定的分辨率。
//
// 取便宜那档：上游的默认值没有实测过，而 MiniMax-H3-Regeneration 的定位是
// 「把已生成的 768P 升成 2K」，说明 768P 才是基础输出。猜错的方向也可控 ——
// 少收是我们自己亏，多收是坑客户，后者在「单价=上游刊例价不加价」这个承诺下
// 不能碰。待实测确认。
const minimaxDefaultResolution = "768p"

// minimaxSecondTier 按生成分辨率选秒单价的档。输出秒和输入视频秒同价，
// 所以两者共用这一档。
func minimaxSecondTier(resolution string) string {
	res := strings.ToLower(strings.TrimSpace(resolution))
	if res == "" {
		res = minimaxDefaultResolution
	}
	if res == "2k" {
		return catalog.TierVideoMinimax2K
	}
	return catalog.TierVideoMinimax768P
}

// minimaxBillableImages 扣掉免费额度后剩下的计费张数。
func minimaxBillableImages(count int64) int64 {
	if n := count - minimaxFreeInputImages; n > 0 {
		return n
	}
	return 0
}

func (minimaxVideo) EstimateUsage(body []byte) (catalog.Usage, error) {
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

	var images int64
	for _, part := range r.Content {
		if part.Type == "image_url" {
			images++
		}
	}

	// 按秒计，所以 Output 装的是秒数不是 token —— 字段的量纲由上游决定，
	// Settle 的公式不用为此改动。
	//
	// 预扣只按 duration 算，不含输入视频的时长：那是一个 URL，不下载就不知道
	// 多长。少估的部分在结算时从余额补扣，所以预扣低于实际用量是可接受的。
	u := catalog.Usage{{Tier: minimaxSecondTier(r.Resolution), Output: dur}}
	if n := minimaxBillableImages(images); n > 0 {
		u = append(u, catalog.TierUsage{Tier: catalog.TierVideoMinimaxImage, Input: n})
	}
	return u, nil
}

func (minimaxVideo) ParseSubmit(body []byte) (string, bool) {
	var r struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.TaskID == "" {
		return "", false
	}
	return r.TaskID, true
}

// minimaxTaskResp 是轮询响应。整个结果包在 task 里，出错时这个字段直接不存在。
type minimaxTaskResp struct {
	Task *struct {
		Status     string `json:"status"`
		Resolution string `json:"resolution"`
		Usage      *struct {
			OutputSeconds   int64 `json:"output_seconds"`
			InputSeconds    int64 `json:"input_seconds"`
			InputImageCount int64 `json:"input_image_count"`
		} `json:"usage"`
	} `json:"task"`
}

func (minimaxVideo) ParseTask(body []byte) (TaskState, catalog.Usage, bool) {
	var r minimaxTaskResp
	if err := json.Unmarshal(body, &r); err != nil || r.Task == nil {
		// 解析不了，或者返回的是 {"type":"error",...} 那种没有 task 的错误信封。
		// 一律什么都不做：这可能只是上游一次抖动，不该拿它去动账。
		return TaskRunning, nil, false
	}

	switch r.Task.Status {
	case "succeeded", "Success", "success":
		// 任务在跑的时候 usage 是空对象 {}，不是缺失 —— 指针非 nil 但字段全 0。
		// 所以这里判的是秒数而不是指针。
		if r.Task.Usage == nil || r.Task.Usage.OutputSeconds <= 0 {
			return TaskSucceeded, nil, true
		}
		// 分辨率和图片数轮询响应里都有，所以这里自己就能定档，不用 video.Task
		// 存的那个 —— 那是给火山用的（它的响应里查不到当初带没带视频输入）。
		//
		// 输入视频的秒数跟输出秒同价，并进同一档累加。
		usage := catalog.Usage{{
			Tier:   minimaxSecondTier(r.Task.Resolution),
			Output: r.Task.Usage.OutputSeconds + r.Task.Usage.InputSeconds,
		}}
		if n := minimaxBillableImages(r.Task.Usage.InputImageCount); n > 0 {
			usage = append(usage, catalog.TierUsage{
				Tier: catalog.TierVideoMinimaxImage, Input: n,
			})
		}
		return TaskSucceeded, usage, true

	case "failed", "Fail", "fail":
		return TaskFailed, nil, true

	default:
		// preparing / queueing / running / 以及任何没见过的，一律当还在跑。
		return TaskRunning, nil, true
	}
}
