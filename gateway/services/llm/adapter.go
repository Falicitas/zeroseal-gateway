package llm

import (
	"net/http"

	"github.com/zeroseal/shared/catalog"
)

// Adapter 收敛一家上游在 chat surface 上的方言：端点路径、请求头、
// 请求体改写、用量解析。
//
// 索引维度是 provider，不是 model：同一家上游的不同 surface 走完全不同的协议
// （火山的 chat 是 /chat/completions，image 是 /images/generations），但这个
// 差异由「查哪张表」表达 —— chatAdapters / imageAdapters / speechAdapters 的
// 值类型本来就不同，surface 再当一次 key 是个只有一种取值的死维度。
// 不同上游的同一 surface 却常常能共用一个实现。
type Adapter interface {
	// Path 相对 Provider.BaseURL 的端点路径。
	Path() string

	// SetHeaders 设上游专属的请求头，鉴权在这里。
	// 各家不一样：OpenAI 一系是 Authorization: Bearer，Anthropic 是 x-api-key
	// 再加一个 anthropic-version。
	SetHeaders(h http.Header, key string)

	// RewriteRequest 把客户的请求体改写成上游认的形式。至少要把 model 换成
	// p.UpstreamID —— 对外 ID 和上游 ID 常常不一样。stream 为 true 时还要让
	// 上游把 usage 带回来，否则流结束时没法按真实用量结算。
	RewriteRequest(body []byte, p catalog.Provider, stream bool) ([]byte, error)

	// ParseUsage 从响应体取用量。非流式传整个响应体，流式传单个 data chunk，
	// 两者的 usage 结构一样。取不到返回 ok=false。
	ParseUsage(body []byte) (catalog.Usage, bool)
}

// chatAdapters 按 provider 索引。image / speech 各有自己的同形表，
// 见 image.go / speech.go。
//
// 这一轮五家上游全是 OpenAI /chat/completions 兼容的，所以共用一个实现，
// 差异全落在 catalog 的数据里（BaseURL 和 UpstreamID）。
var chatAdapters = map[string]Adapter{
	"deepseek": openAIChat{},
	"kimi":     openAIChat{},
	"zhipu":    openAIChat{},
	"bailian":  openAIChat{},
	"volc":     openAIChat{},
}

// ChatFor 取 provider 的 chat adapter。
func ChatFor(provider string) (Adapter, bool) {
	a, ok := chatAdapters[provider]
	return a, ok
}
