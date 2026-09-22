package llm

import (
	"encoding/json"
	"net/http"
)

// rewriteUpstreamError 区分上游账户欠费与用户的 ZeroSeal 钱包余额不足。
// 智谱业务码 1113、DeepSeek HTTP 402 表示调用方账户欠费。
// 这里只处理上游响应，用户钱包不足产生的本地 402 不经过这里。
func rewriteUpstreamError(provider string, status int, body []byte) (int, []byte) {
	if provider != "zhipu" && !(provider == "deepseek" && status == http.StatusPaymentRequired) {
		return status, body
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(body, &response) != nil {
		response = nil
	}
	var detail map[string]json.RawMessage
	if json.Unmarshal(response["error"], &detail) != nil {
		detail = nil
	}
	var message string
	if provider == "zhipu" {
		var code json.Number
		if json.Unmarshal(detail["code"], &code) != nil || code.String() != "1113" {
			return status, body
		}
		message = "ZeroSeal 的智谱服务账户余额不足，GLM 模型暂不可用。这与您的 ZeroSeal 钱包余额无关，请联系 ZeroSeal 支持。"
	} else {
		// DeepSeek 以 HTTP 402 判定欠费，不依赖错误体中的文案或业务码。
		// 没有标准 JSON 错误体时，也返回客户端可解析的错误结构。
		if detail == nil {
			response = make(map[string]json.RawMessage)
			detail = map[string]json.RawMessage{
				"code": json.RawMessage(`"upstream_insufficient_balance"`),
				"type": json.RawMessage(`"upstream_error"`),
			}
		}
		message = "ZeroSeal 的 DeepSeek 服务账户余额不足，该模型暂不可用。这与您的 ZeroSeal 钱包余额无关，请联系 ZeroSeal 支持。"
	}

	// 保留厂商错误码和请求 ID，HTTP 状态改成服务不可用，避免被当作用户限流。
	// 不记录上游响应体。
	detail["message"], _ = json.Marshal(message)
	response["error"], _ = json.Marshal(detail)
	rewritten, err := json.Marshal(response)
	if err != nil {
		return status, body
	}
	return http.StatusServiceUnavailable, rewritten
}
