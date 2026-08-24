// Package catalog 是模型白名单和定价表
// 请求怎么翻译、用量怎么解析是 gateway 那边 adapter 的事
package catalog

import "time"

// Surface 是模型的输出模态，决定它挂在哪个对外端点。
// video 的端点还没做，先占位。
type Surface string

const (
	SurfaceChat   Surface = "chat"   // POST /v1/chat/completions
	SurfaceImage  Surface = "image"  // POST /v1/images/generations
	SurfaceSpeech Surface = "speech" // POST /v1/audio/speech
	SurfaceVideo  Surface = "video"  // POST /v1/videos，异步
)

// Valid 报告 s 是不是一个已定义的 surface。外部传进来的字符串（/v1/models
// 的 ?surface=）先过这里，免得拼错时静默返回一个空列表当正常结果。
func (s Surface) Valid() bool {
	switch s {
	case SurfaceChat, SurfaceImage, SurfaceSpeech, SurfaceVideo:
		return true
	}
	return false
}

// Pricing 单价（纳元，10⁻⁹ 元）。由所属 Model 的 Surface 决定：
// chat 每 token
// image 每张
// speech 每字符
// video 每秒或每 token（各家不同）
// X 元/百万 token = X×1000 纳元/token。
type Pricing struct {
	InputHit int64 // 缓存命中的输入单价，目前只有 chat 用得上
	Input    int64 // 输入单价
	Output   int64 // 输出单价
}

// 档位 key。有图像按质量区分，有 chat 按时段区分
const (
	TierDefault = ""

	// seedream 图像：单价按「场景 × 像素档」四种组合，261 万像素为界
	// （火山文档的说法是「分辨率 1.5K 及以下 / 以上」）。
	// 输入图单价放在 TierDefault 上。
	TierImageSingleLow  = "single-low"
	TierImageSingleHigh = "single-high"
	TierImageLayerLow   = "layer-low"
	TierImageLayerHigh  = "layer-high"

	// 视频按「分辨率 × 有无视频输入」分四档，两个维度都进单价：
	//   分辨率——480p/720p 同价，1080p 贵一档（用量也更大，两头都涨）
	//   视频输入——带了是视频编辑/延长，比纯生成便宜近四成
	// 后者是**请求**的属性，轮询响应里查不到，所以提交时就要定档并落库。
	TierVideoLowEdit  = "video-low-edit"  // 480p/720p，含视频输入
	TierVideoLowGen   = "video-low-gen"   // 480p/720p，纯文图生视频
	TierVideoHighEdit = "video-high-edit" // 1080p，含视频输入
	TierVideoHighGen  = "video-high-gen"  // 1080p，纯文图生视频

	// MiniMax 的结构跟火山不一样：按秒计，而且一次请求有三种计费项、两种单位
	// （输出秒 / 输入视频秒 / 输入图张数），一个 Pricing 的三个字段装不下三种
	// 单价，所以按「秒」和「张」拆成两档，各自用自己的字段。
	// 输入视频秒和输出秒同价（都按生成视频的分辨率），所以能并进同一档。
	TierVideoMinimax768P  = "mm-768p"  // 0.50 元/秒
	TierVideoMinimax2K    = "mm-2k"    // 0.80 元/秒
	TierVideoMinimaxImage = "mm-image" // 0.20 元/张，超出 5 张免费额度的部分

	// 分时档：按计价时刻落档，跟产物规格无关。DeepSeek 2026-08 起这么收，
	// 空闲价是高峰价的一半。只有定价表里给了这两个 key 的 provider 才走分时。
	TierPeak    = "peak"
	TierOffPeak = "off-peak"
)

// TierAtTimeFunc 按计价时刻算分时档。每家上游的时段表不一样，各写一个，
// 挂到自己的 Provider 上——PriceOf 因此不认识任何一家。
type TierAtTimeFunc func(at time.Time) string

// 计价时区写死 UTC+8，不用 time.Local：TD 里跑的是 mkosi 出的镜像，
// 时区不保证是 Asia/Shanghai（没有确认），拿本地时区算会整体偏 8 小时
var beijingTimeZone = time.FixedZone("UTC+8", 8*60*60)

// tierAtByDeepseek 算 at 那一刻的分时档。高峰是北京时间 9:00–12:00、14:00–18:00，
// 其余为空闲。边界左闭右开：9:00:00 算高峰，12:00:00 算空闲。
func tierAtByDeepseek(at time.Time) string {
	h := at.In(beijingTimeZone).Hour()
	if (h >= 9 && h < 12) || (h >= 14 && h < 18) {
		return TierPeak
	}
	return TierOffPeak
}

// Usage 之所以是切片而不是单条：同一次请求的产物可能落在不同档位，各算各的量，故分 TierUsage。
// seedream 图层拆分就是这样 —— 火山明确写了「同一次请求输出的图层可能分别
// 落在不同像素档位，按每个图层实际像素档位单独计费」。chat / speech 这类
// 单档的就只有一条。
type Usage []TierUsage

// TierUsage 是一个档位下的计量（比如 InputHit 是用了多少缓存命中的量）。字段跟 Pricing 一一对应，由 Surface 决定，
// 于是四种 Surface 共用一个结算公式，t 是用量，pr 是单位价格：t.InputHit*pr.InputHit + t.Input*pr.Input + t.Output*pr.Output
// 填法：
// chat   InputHit=缓存命中 token，Input=未命中 token，Output=补全 token
// image  Input=收费的输入图张数，Output=该档位下的产出图张数
// speech Input=输入字符数
// video  Output=秒数或 token，看上游按什么计
type TierUsage struct {
	Tier     string // 查价用的档位，空串是默认档
	InputHit int64
	Input    int64
	Output   int64
}

// Provider 是一个上游接入点
type Provider struct {
	// Name 同时是 Secrets.ProviderKeys 的索引。
	Name string

	// !!! UpstreamID 是上游认的 model 字符串，跟对外的 Model.ID 常常不一样
	// 同一个模型在官方、百炼、火山上可能分别叫
	// doubao-seed-2.1-pro / 别的 / doubao-seed-2-1-pro-260628。
	// !!! 转发前要把请求体里的 model 换成它。
	UpstreamID string

	BaseURL string

	// Pricing 按档位索引，"" 是默认档。分档的情形：视频按分辨率、
	// 图像按像素、部分文本模型按输入长度。当前六个 chat 模型都是单档。
	Pricing map[string]Pricing

	// TierAt 算分时档，nil 表示这家不分时。写死一家的时段表会让别家填了
	TierAt TierAtTimeFunc
}

// PriceOf 取指定档位的单价，at 是计价时刻（调用方统一取请求发起时刻，
// 这样同一次请求的预扣和结算落在同一档，不会跨过高峰边界后对不上）。
//
// 故意不做「查不到就回落默认档」：图像那边默认档放的是输入图单价（0.02 元/张），
// 而输出图是 0.15~0.60 —— 档位 key 写错时静默回落等于少收二三十倍，还不会有人
// 发现。查不到就让调用方退款，亏一次上游成本，但错误当场暴露。
//
// 分时的 provider（TierAt 非 nil）查默认档时，按 at 落到当时生效的那一档。
// 落不到同样不回落 TierDefault：既然声明了分时，查不到就是定价表漏填了一档，
// 回落等于按另一档的价收，还是没人发现。
func (p Provider) PriceOf(tier string, at time.Time) (Pricing, bool) {
	if tier == TierDefault && p.TierAt != nil {
		pr, ok := p.Pricing[p.TierAt(at)]
		return pr, ok
	}
	pr, ok := p.Pricing[tier]
	return pr, ok
}

type Model struct {
	ID        string
	Surface   Surface
	Owner     string
	Created   int64
	Providers []Provider
	CtxLimit  int64 // 上下文长度上限（token），预扣封顶用

	// MaxOutput 是单次响应的输出上限（token）。0 表示上游没单列，退回按
	// CtxLimit 封顶。预扣是 maxToken × 输出价，这个填大了就是白占用户余额：
	// deepseek-v4-pro 实际最多出 384K，按 1M 预扣要多占 16 块。
	MaxOutput int64
}

// ProviderByName 按名字取这个模型挂的某个上游。
//
// 异步任务（视频）用得上：任务提交给了哪家，轮询就必须打回哪家，不能靠
// pickProvider 重算 —— 那个函数以后要做故障转移，重算会指向另一家。
func (m Model) ProviderByName(name string) (Provider, bool) {
	for _, p := range m.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return Provider{}, false
}

// All 返回全部可用模型。
func All() []Model {
	out := make([]Model, len(models))
	copy(out, models)
	return out
}

// Lookup 按 ID 查找，第二个返回值表示是否存在。
func Lookup(id string) (Model, bool) {
	for _, m := range models {
		if m.ID == id {
			return m, true
		}
	}
	return Model{}, false
}
