package llm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/zeroseal/shared/catalog"
)

// ImageAdapter 是图像生成 surface 的适配器。
//
// 比 chat 的 Adapter 多两件事。一是预扣要从请求参数推（出几张、多大、是不是
// 图层拆分），不能像 chat 那样按 body 长度估。二是结算要同时看请求和响应：
// 「单图生成」和「图层拆分」两个场景单价差一倍，而这个区别只有请求里有。
type ImageAdapter interface {
	Path() string
	SetHeaders(h http.Header, key string)
	RewriteRequest(body []byte, p catalog.Provider) ([]byte, error)

	// EstimateUsage 从请求参数推最坏情况用量，喂给 billing.Settle 就是预扣额。
	EstimateUsage(body []byte) (catalog.Usage, error)

	// ParseUsage 算结算用量。产物可能跨多个像素档，返回的 Usage 会有多条。
	ParseUsage(reqBody, respBody []byte) (catalog.Usage, bool)
}

// imageAdapters 按 provider 索引。图像这条路目前只有火山。
var imageAdapters = map[string]ImageAdapter{
	"volc": volcImage{},
}

// ImageFor 取 provider 的图像适配器。
func ImageFor(provider string) (ImageAdapter, bool) {
	a, ok := imageAdapters[provider]
	return a, ok
}

// pixelThreshold 是 seedream 的像素分档线：261 万像素，
// 火山文档的说法是「分辨率 1.5K 及以下 / 以上」。
const pixelThreshold = 2_610_000

// maxLayerEstimate 是图层拆分场景预扣时假定的产物张数。
// 请求发出去之前算不出会拆几层 —— 图里有几个可分离元素就出几张。
// 实测一张海报出了 8 张（1 底图 + 7 图层），16 留了一倍余量。
// 真超了就是预扣不足，结算时从余额补扣。
const maxLayerEstimate = 16

type volcImage struct{}

func (volcImage) Path() string { return "/images/generations" }

func (volcImage) SetHeaders(h http.Header, key string) {
	h.Set("Authorization", "Bearer "+key)
}

// RewriteRequest 只换 model。特别地**不碰** response_format：客户想要 url
// 还是 b64_json 由他自己定 —— 两条路都是上游直接返，我们只是原样转发，
// 选 b64_json 时图片字节自然就走了 TD。
func (volcImage) RewriteRequest(body []byte, p catalog.Provider) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // 同 chat：别把客户的大整数参数用 float64 改了值
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	m["model"] = p.UpstreamID
	return json.Marshal(m)
}

// imageReq 是计费要看的请求字段，其余原样透传。
type imageReq struct {
	Size               string          `json:"size"`
	N                  int64           `json:"n"`
	LayerDecomposition bool            `json:"layer_decomposition"`
	Image              json.RawMessage `json:"image"` // 可能是字符串，也可能是字符串数组
}

func (volcImage) EstimateUsage(body []byte) (catalog.Usage, error) {
	var r imageReq
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	count := r.N
	if count <= 0 {
		count = 1
	}
	if r.LayerDecomposition {
		count = maxLayerEstimate
	}

	u := catalog.Usage{{
		Tier:   tierOf(r.LayerDecomposition, pixelsOf(r.Size)),
		Output: count,
	}}
	if n := countInputImages(r.Image) - 1; n > 0 { // 输入图首张免费
		u = append(u, catalog.TierUsage{Tier: catalog.TierDefault, Input: n})
	}
	return u, nil
}

// imageResp 是结算要看的响应字段。data 里每条的 size 决定它落哪个像素档 ——
// 火山明确写了图层拆分时各图层分别落档、单独计费。
type imageResp struct {
	Data []struct {
		Size string `json:"size"`
	} `json:"data"`
	Usage *struct {
		InputImages     int64 `json:"input_images"`
		GeneratedImages int64 `json:"generated_images"`
	} `json:"usage"`
}

func (volcImage) ParseUsage(reqBody, respBody []byte) (catalog.Usage, bool) {
	var resp imageResp
	if err := json.Unmarshal(respBody, &resp); err != nil || resp.Usage == nil {
		return nil, false
	}

	// 请求体在入口已经解析成功过一次，这里再解只为拿场景标志；
	// 真失败了 layer 就是 false，退化成按单图档计价。
	var req imageReq
	_ = json.Unmarshal(reqBody, &req)

	// 按档位归并张数。data 缺失时退回 usage.generated_images，
	// 像素数当 0 处理（tierOf 会给高档），宁可多收也不白送。
	byTier := map[string]int64{}
	if len(resp.Data) > 0 {
		for _, d := range resp.Data {
			byTier[tierOf(req.LayerDecomposition, pixelsOf(d.Size))]++
		}
	} else if resp.Usage.GeneratedImages > 0 {
		byTier[tierOf(req.LayerDecomposition, 0)] = resp.Usage.GeneratedImages
	}

	tiers := make([]string, 0, len(byTier))
	for t := range byTier {
		tiers = append(tiers, t)
	}
	sort.Strings(tiers) // 定序，免得同一次调用两次跑出来的 Usage 顺序不一样

	u := make(catalog.Usage, 0, len(tiers)+1)
	for _, t := range tiers {
		u = append(u, catalog.TierUsage{Tier: t, Output: byTier[t]})
	}
	if n := resp.Usage.InputImages - 1; n > 0 { // 输入图首张免费
		u = append(u, catalog.TierUsage{Tier: catalog.TierDefault, Input: n})
	}

	if len(u) == 0 {
		return nil, false
	}
	return u, true
}

// tierOf 按场景和像素数选档位。像素数为 0 表示没认出尺寸，按高档算 ——
// 预扣宁可多，而结算那边拿的是产物实际尺寸，正常不会落到这个分支。
func tierOf(layer bool, pixels int64) string {
	low := pixels > 0 && pixels <= pixelThreshold
	switch {
	case layer && low:
		return catalog.TierImageLayerLow
	case layer:
		return catalog.TierImageLayerHigh
	case low:
		return catalog.TierImageSingleLow
	default:
		return catalog.TierImageSingleHigh
	}
}

// pixelsOf 把 size 串换算成像素数。认 "2048x2048" 这种，也认 "1K"/"2K"/"4K"。
// 认不出返回 0。
func pixelsOf(size string) int64 {
	s := strings.ToLower(strings.TrimSpace(size))
	if w, h, ok := strings.Cut(s, "x"); ok {
		wi, e1 := strconv.ParseInt(w, 10, 64)
		hi, e2 := strconv.ParseInt(h, 10, 64)
		if e1 == nil && e2 == nil && wi > 0 && hi > 0 {
			return wi * hi
		}
	}
	switch s {
	case "1k":
		return 1024 * 1024
	case "2k":
		return 2048 * 2048
	case "4k":
		return 4096 * 4096
	}
	return 0
}

// countInputImages 数请求里带了几张输入图。image 字段可能是单个字符串，
// 也可能是字符串数组。
func countInputImages(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return 0
		}
		return 1
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return int64(len(many))
	}
	return 0
}
