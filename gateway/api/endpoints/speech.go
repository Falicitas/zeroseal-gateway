package endpoints

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/zeroseal/gateway/services/billing"
	"github.com/zeroseal/gateway/services/llm"
	"github.com/zeroseal/shared/catalog"
)

// audioSpeech 是 OpenAI /v1/audio/speech 兼容的语音合成端点，返裸音频字节。
//
// 上游走的是 DashScope 的流式模式：非流式只给一个 OSS 链接，音频字节根本不
// 经过 TD；流式则是一段段 base64，边收边解边写，字节全程在信任边界内，而且
// 不比转发链接多传一次。
func (h *LLM) audioSpeech(c echo.Context) error {
	acc, ok := accountFrom(c)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "缺少鉴权账户")
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "读取请求体失败")
	}

	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "请求体不是合法 JSON")
	}

	m, ok := catalog.Lookup(probe.Model)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "model "+probe.Model+" 不存在")
	}
	if m.Surface != catalog.SurfaceSpeech {
		return echo.NewHTTPError(http.StatusBadRequest, "model "+probe.Model+" 不是语音合成模型，请用它对应的端点")
	}

	p, ok := pickProvider(m)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "model "+m.ID+" 无可用上游")
	}
	key, ok := h.providerKeys[p.Name]
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 无可用凭据")
	}
	adapter, ok := llm.SpeechFor(p.Name)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 未接入语音合成协议")
	}

	// 计价时刻取一次，预扣和结算共用（分时定价的上游靠它落档）。
	at := time.Now()

	// 预扣：按我们自己数的字符数。上游返回的 usage.characters 才是账单依据，
	// 两者口径可能有细微出入（空白、SSML 标记），所以还是走预扣—结算两段。
	worst, err := adapter.EstimateUsage(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "input 为空或无法估算用量")
	}
	hold, ok := billing.Settle(p, worst, at)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "model "+m.ID+" 缺定价")
	}

	recordID, err := billing.Hold(c.Request().Context(), h.pool, acc.KeyID, m.ID, hold)
	if errors.Is(err, billing.ErrUnauthorized) {
		return echo.NewHTTPError(http.StatusUnauthorized, "凭据无效")
	}
	if errors.Is(err, billing.ErrInsufficient) {
		return echo.NewHTTPError(http.StatusPaymentRequired, "余额不足")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "预扣失败")
	}

	resp := c.Response()

	// 长文本合成会写很久，解除这条响应的写超时，理由同流式对话。
	rc := http.NewResponseController(resp.Writer)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		return echo.NewHTTPError(http.StatusInternalServerError, "无法配置流式响应")
	}

	// onStart 在上游确认 2xx 之后才被调用，此前一个字节都没写，
	// 所以上游报错时下面还能正常返 JSON。
	onStart := func() {
		resp.Header().Set("Content-Type", adapter.ContentType(body))
		resp.Header().Set("Cache-Control", "no-cache")
		resp.WriteHeader(http.StatusOK)
	}

	// 读上游用独立 ctx（客户端断连也读完，拿 usage 结算），但要带上限，
	// 否则上游挂住这条请求就永远不回来。
	upCtx, cancel := context.WithTimeout(context.Background(), llm.SpeechTimeout)
	defer cancel()

	settleCtx := context.Background()
	result, ferr := llm.ForwardSpeech(upCtx, adapter, p, key, body, onStart, resp.Writer, resp.Flush)

	var upErr *llm.UpstreamError
	switch {
	case errors.As(ferr, &upErr):
		// 上游非 2xx，此时还没写过响应头，可以照常返错误体并退款。
		_ = billing.Refund(settleCtx, h.pool, recordID)
		return c.Blob(upErr.Status, echo.MIMEApplicationJSON, upErr.Body)

	case result == nil:
		// 连上游都没连上（DNS / TCP / 超时）。onStart 还没被调过，
		// 响应头没发出去，可以正常返错误。
		_ = billing.Refund(settleCtx, h.pool, recordID)
		return echo.NewHTTPError(http.StatusBadGateway, ferr.Error())

	case result.Bytes == 0:
		// 上游返了 2xx 却一个音频块都没有。实测音色不存在时就是这样：
		// 它照报 usage，只是不合成。客户拿到的是空文件，不该付钱。
		_ = billing.Refund(settleCtx, h.pool, recordID)
		c.Logger().Errorf("speech 无音频产出，已退款 %s", recordID)
		return nil

	case ferr != nil && len(result.Usage) == 0:
		// 上游流中途断且没拿到用量。已经写出去的音频是真花了钱的，
		// 按预扣全额扣，跟流式对话一致。
		if err := billing.SettleFull(settleCtx, h.pool, recordID); err != nil {
			c.Logger().Errorf("speech 流中断，全额结算 %s: %v", recordID, err)
		}
		return nil

	case len(result.Usage) > 0:
		actual, ok := billing.Settle(p, result.Usage, at)
		if !ok {
			_ = billing.Refund(settleCtx, h.pool, recordID)
			c.Logger().Errorf("speech settle 查不到档位单价，已退款 %s", recordID)
			return nil
		}
		if err := billing.Finalize(settleCtx, h.pool, recordID, actual); err != nil {
			c.Logger().Errorf("finalize speech billing %s: %v", recordID, err)
		}
		return nil

	default:
		// 流正常结束但没扫到 usage。音频已经发给客户了，不退，按预扣全额扣。
		// TODO 观察是否真会发生；若频繁说明 ScanChunk 没认出 usage 字段
		if err := billing.SettleFull(settleCtx, h.pool, recordID); err != nil {
			c.Logger().Errorf("speech 结束但无 usage，全额结算 %s: %v", recordID, err)
		}
		return nil
	}
}
