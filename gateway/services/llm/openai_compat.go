package llm

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/zeroseal/shared/catalog"
)

// openAIChat 是 OpenAI /chat/completions 兼容上游的通用实现。
// DeepSeek、Kimi、智谱、百炼兼容模式、火山方舟都吃这一套。
type openAIChat struct{}

func (openAIChat) Path() string { return "/chat/completions" }

func (openAIChat) SetHeaders(h http.Header, key string) {
	h.Set("Authorization", "Bearer "+key)
}

// RewriteRequest 只动两个键：model 换成上游 ID，流式补上 include_usage。
// 其余原样留着 —— 客户传什么高级参数是他和上游之间的事，我们不解释也不过滤。
func (openAIChat) RewriteRequest(body []byte, p catalog.Provider, stream bool) ([]byte, error) {
	// UseNumber 保住客户写的数字字面量。默认会把所有数字解成 float64，
	// 超过 2^53 的整数（比如客户自己传的 seed）再序列化回去就变了值。
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	m["model"] = p.UpstreamID

	if stream {
		// 保留客户已有的 stream_options 其它键，只强制 include_usage。
		opts, _ := m["stream_options"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		opts["include_usage"] = true
		m["stream_options"] = opts
	}

	return json.Marshal(m)
}

// usageBody 同时认两套缓存字段名。OpenAI 标准把命中数放在
// prompt_tokens_details.cached_tokens，未命中要自己减；DeepSeek 一系直接
// 拆成 prompt_cache_hit_tokens / prompt_cache_miss_tokens。国内几家跟的是
// 哪一套要联调才知道，两套都认，谁有值用谁。
type usageBody struct {
	Usage *struct {
		PromptTokens        int64 `json:"prompt_tokens"`
		CompletionTokens    int64 `json:"completion_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`

		PromptCacheHitTokens  int64 `json:"prompt_cache_hit_tokens"`
		PromptCacheMissTokens int64 `json:"prompt_cache_miss_tokens"`
	} `json:"usage"`
}

func (openAIChat) ParseUsage(body []byte) (catalog.Usage, bool) {
	var r usageBody
	if err := json.Unmarshal(body, &r); err != nil || r.Usage == nil {
		return catalog.Usage{}, false
	}
	u := r.Usage

	// DeepSeek 一系：两个字段直接给了命中和未命中，加起来就是全部输入。
	if u.PromptCacheHitTokens > 0 || u.PromptCacheMissTokens > 0 {
		return catalog.Usage{{
			Tier:     catalog.TierDefault,
			InputHit: u.PromptCacheHitTokens,
			Input:    u.PromptCacheMissTokens,
			Output:   u.CompletionTokens,
		}}, true
	}

	// OpenAI 标准：prompt_tokens 是输入总数，命中部分要从 details 里取。
	// details 缺失时命中算 0 —— 会按未命中价多收一点，但比猜着退款强。
	var hit int64
	if u.PromptTokensDetails != nil {
		hit = u.PromptTokensDetails.CachedTokens
	}
	miss := u.PromptTokens - hit
	if miss < 0 {
		miss = 0
	}
	return catalog.Usage{{
		Tier:     catalog.TierDefault,
		InputHit: hit,
		Input:    miss,
		Output:   u.CompletionTokens,
	}}, true
}
