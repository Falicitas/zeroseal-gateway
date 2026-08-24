package catalog

// 定价按各家 2026-08 官方刊例价填，一律取**非优惠价**：限时折扣会到期，
// 跟着调等于要盯日期改 catalog，而改 catalog = 改 TD 二进制 = 换度量值 = 重走注入。
// 优惠跟踪是另一条线的事。
//
// 换算：X 元/百万 token = X×1000 纳元/token。
var models = []Model{
	// DeepSeek 两条走分时价（2026-08 起）：高峰为北京时间 9:00–12:00、
	// 14:00–18:00，空闲价是高峰价的一半。落档由 Provider.PriceOf 按请求发起
	// 时刻算，adapter 不知情。
	// 上下文 1M 但输出最长 384K，MaxOutput 单列，免得预扣按 1M 白占余额。
	{
		// 高峰 0.10 / 3.0 / 9.0，空闲 0.05 / 1.5 / 4.5（元/百万 token）。
		ID: "deepseek-v4-flash", Surface: SurfaceChat, Owner: "deepseek",
		CtxLimit: 1_000_000, MaxOutput: 384_000,
		Providers: []Provider{{
			Name: "deepseek", UpstreamID: "deepseek-v4-flash",
			BaseURL: "https://api.deepseek.com/v1",
			Pricing: map[string]Pricing{
				TierPeak:    {InputHit: 100, Input: 3000, Output: 9000},
				TierOffPeak: {InputHit: 50, Input: 1500, Output: 4500},
			},
			TierAt: tierAtByDeepseek,
		}},
	},
	{
		// 高峰 0.30 / 9.0 / 27.0，空闲 0.15 / 4.5 / 13.5（元/百万 token）。
		ID: "deepseek-v4-pro", Surface: SurfaceChat, Owner: "deepseek",
		CtxLimit: 1_000_000, MaxOutput: 384_000,
		Providers: []Provider{{
			Name: "deepseek", UpstreamID: "deepseek-v4-pro",
			BaseURL: "https://api.deepseek.com/v1",
			Pricing: map[string]Pricing{
				TierPeak:    {InputHit: 300, Input: 9000, Output: 27000},
				TierOffPeak: {InputHit: 150, Input: 4500, Output: 13500},
			},
			TierAt: tierAtByDeepseek,
		}},
	},
	{
		// ¥2 / ¥20 / ¥100 每百万 token。输出价是 deepseek-v4-pro 的 16.7 倍，
		// 预扣时注意（见 endpoints.defaultMaxToken）。
		ID: "kimi-k3", Surface: SurfaceChat, Owner: "moonshot",
		CtxLimit: 1_048_576,
		Providers: []Provider{{
			Name: "kimi", UpstreamID: "kimi-k3",
			// 文档站已改叫 platform.kimi.com，但 API base 仍是 moonshot.cn（实测通）
			BaseURL: "https://api.moonshot.cn/v1",
			Pricing: map[string]Pricing{"": {InputHit: 2000, Input: 20000, Output: 100000}},
		}},
	},
	{
		// ¥2 / ¥8 / ¥28 每百万 token。缓存命中当前限时免费，这里按原价 ¥2 填。
		ID: "glm-5.2", Surface: SurfaceChat, Owner: "zhipu",
		CtxLimit: 1_000_000,
		Providers: []Provider{{
			Name: "zhipu", UpstreamID: "glm-5.2",
			BaseURL: "https://open.bigmodel.cn/api/paas/v4",
			Pricing: map[string]Pricing{"": {InputHit: 2000, Input: 8000, Output: 28000}},
		}},
	},
	{
		// ¥12 / ¥36 每百万 token。百炼没有单列缓存命中价，规则是按输入单价打折：
		// 隐式缓存 20%、显式缓存 10%。显式要在 messages 里插 cache_control，
		// 那是改客户请求体，跟透传的定位冲突，不做——所以按隐式的 12×0.2=¥2.4 填。
		ID: "qwen3.8-max", Surface: SurfaceChat, Owner: "alibaba",
		CtxLimit: 1_000_000,
		Providers: []Provider{{
			Name: "bailian", UpstreamID: "qwen3.8-max",
			BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1",
			Pricing: map[string]Pricing{"": {InputHit: 2400, Input: 12000, Output: 36000}},
		}},
	},
	{
		// ¥1.20 / ¥6 / ¥30 每百万 token，输入长度 [0, 256]K 单档。
		// 价目表里还有一列「缓存存储 0.017 元/百万token/小时」，那是按时间计的
		// 存储费不是按量计费，不进这里。
		ID: "doubao-seed-2.1-pro", Surface: SurfaceChat, Owner: "bytedance",
		CtxLimit: 262_144,
		Providers: []Provider{{
			Name: "volc", UpstreamID: "doubao-seed-2-1-pro-260628",
			BaseURL: "https://ark.cn-beijing.volces.com/api/v3",
			Pricing: map[string]Pricing{"": {InputHit: 1200, Input: 6000, Output: 30000}},
		}},
	},
	{
		// 按张计费，不按 token（响应里那个 output_tokens 是统计不是账单依据）。
		// 输入图首张免费、第 2 张起 0.02 元；输出图按「场景 × 像素档」四档，
		// 且同一次请求的各个图层分别落档、单独计费。
		// CtxLimit 对图像没意义，留 0。
		ID: "doubao-seedream-5-0-pro", Surface: SurfaceImage, Owner: "bytedance",
		Providers: []Provider{{
			Name: "volc", UpstreamID: "doubao-seedream-5-0-pro-260628",
			BaseURL: "https://ark.cn-beijing.volces.com/api/v3",
			Pricing: map[string]Pricing{
				TierDefault:         {Input: 20_000_000},   // 输入图 0.02 元/张
				TierImageSingleLow:  {Output: 300_000_000}, // 单图 ≤261 万像素 0.30
				TierImageSingleHigh: {Output: 600_000_000}, // 单图 >261 万像素 0.60
				TierImageLayerLow:   {Output: 150_000_000}, // 图层 ≤261 万像素 0.15
				TierImageLayerHigh:  {Output: 300_000_000}, // 图层 >261 万像素 0.30
			},
		}},
	},
	{
		// 按 token 计费，只有输出侧。单价分四档（元/百万 token）：
		//                 含视频输入   纯生成
		//   480p/720p        42          70
		//   1080p            46          77
		// 分辨率同时还影响 token 用量（固定 24fps，像素越多 token 越多），
		// 所以 1080p 是单价和用量一起涨。
		// 上游限制：时长 4-30 秒，并发 3。
		ID: "doubao-seedance-2-5", Surface: SurfaceVideo, Owner: "bytedance",
		Providers: []Provider{{
			Name: "volc", UpstreamID: "doubao-seedance-2-5-260628",
			BaseURL: "https://ark.cn-beijing.volces.com/api/v3",
			Pricing: map[string]Pricing{
				TierVideoLowEdit:  {Output: 42_000},
				TierVideoLowGen:   {Output: 70_000},
				TierVideoHighEdit: {Output: 46_000},
				TierVideoHighGen:  {Output: 77_000},
			},
		}},
	},
	{
		// 按秒计费，不按 token（响应里那个 total_tokens 是统计不是账单依据）。
		// 输出秒按生成分辨率：2K 0.80 元/秒、768P 0.50 元/秒。
		// 输入素材：音频免费；图片 5 张以内免费、超出 0.20 元/张；
		// 输入视频按「输入时长 × 生成分辨率的秒单价」，跟输出同价，所以并进同一档。
		//
		// 另有 MiniMax-H3-Regeneration（768P→2K，0.30 元/秒）和
		// MiniMax-H3-Context-IR（按 token 的文本模型）两个单独的模型，
		// 没有实测过的请求样本，这轮不接。
		ID: "minimax-h3", Surface: SurfaceVideo, Owner: "minimax",
		Providers: []Provider{{
			Name: "minimax", UpstreamID: "MiniMax-H3",
			BaseURL: "https://api.minimaxi.com/v2",
			Pricing: map[string]Pricing{
				TierVideoMinimax768P:  {Output: 500_000_000},
				TierVideoMinimax2K:    {Output: 800_000_000},
				TierVideoMinimaxImage: {Input: 200_000_000},
			},
		}},
	},
	{
		// 按输入文本字符数计费，输出不计费。1.4 元/万字符 = 140000 纳元/字符。
		// BaseURL 跟百炼的 chat 不是一个：语音走 DashScope 原生 API，
		// 不在 compatible-mode 下（那条路上没有 audio/speech，实测 404）。
		// 官方另有 {WorkspaceId}.cn-beijing.maas.aliyuncs.com 的专属域名，
		// 但那要每个账号自己的 WorkspaceId，填不进这张公共表，用通用域名。
		// 仅华北 2（北京）可用。
		ID: "qwen-audio-3.0-tts-plus", Surface: SurfaceSpeech, Owner: "alibaba",
		Providers: []Provider{{
			Name: "bailian", UpstreamID: "qwen-audio-3.0-tts-plus",
			BaseURL: "https://dashscope.aliyuncs.com/api/v1",
			Pricing: map[string]Pricing{TierDefault: {Input: 140_000}},
		}},
	},
}
