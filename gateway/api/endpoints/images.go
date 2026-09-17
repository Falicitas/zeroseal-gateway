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

// imageGenerations 是 OpenAI Image 兼容的图像生成端点。
//
// 跟 chat 的区别在计费：chat 按 token、单档；图像按张、分档，而且一次请求的
// 产物可能跨多个档位。所以预扣走 EstimateUsage（从请求参数推最坏情况），
// 结算走 ParseUsage（逐产物按实际尺寸落档），两边最后都过同一个 billing.Settle。
func (h *LLM) imageGenerations(c echo.Context) error {
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
	if m.Surface != catalog.SurfaceImage {
		return echo.NewHTTPError(http.StatusBadRequest, "model "+probe.Model+" 不是图像生成模型，请用它对应的端点")
	}

	p, ok := pickProvider(m)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "model "+m.ID+" 无可用上游")
	}
	key, ok := h.providerKeys[p.Name]
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 无可用凭据")
	}
	adapter, ok := llm.ImageFor(p.Name)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 未接入图像生成协议")
	}

	// 计价时刻取一次，预扣和结算共用（分时定价的上游靠它落档）。
	// 图像这条路一次请求能跑一分钟以上，更不能两头各取各的时刻。
	at := time.Now()

	// 预扣：先从请求参数推最坏情况用量，再用结算同一个公式换算成钱。
	worst, err := adapter.EstimateUsage(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "请求参数无法估算用量")
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

	// server 的 WriteTimeout 是 5 分钟，而出图动辄一分钟起步、图层拆分更久。
	// 不放宽的话客户端连接会先被掐断，而账仍然按上游实际结果扣 —— 客户付了钱
	// 什么也没收到。只在这条路径上把写截止时间放到跟上游同一个量级。
	rc := http.NewResponseController(c.Response().Writer)
	if err := rc.SetWriteDeadline(time.Now().Add(llm.ImageTimeout + 30*time.Second)); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "无法配置图像响应超时")
	}

	// 上游请求不挂客户端 context，理由同 chat：客户端断了图也已经生成了、
	// 上游照样计费，得把响应读完才知道该扣多少。
	upCtx, cancel := context.WithTimeout(context.Background(), llm.ImageTimeout)
	defer cancel()

	resp, err := llm.ForwardImage(upCtx, adapter, p, key, body)
	if err != nil {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		return echo.NewHTTPError(http.StatusBadGateway, upstreamUnreachable).SetInternal(err)
	}
	// 上游非 2xx 退款（用户不该为上游错误付费）。
	if resp.Status < 200 || resp.Status >= 300 {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}

	usage, ok := adapter.ParseUsage(body, resp.Body)
	if !ok {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		c.Logger().Errorf("image 解析不出 usage，已退款 %s", recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}
	actual, ok := billing.Settle(p, usage, at)
	if !ok {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		c.Logger().Errorf("image settle 查不到档位单价，已退款 %s", recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}
	if err := billing.Finalize(context.Background(), h.pool, recordID, actual); err != nil {
		// 结算失败不影响给用户返响应，但要记日志人工对账。
		c.Logger().Errorf("finalize image billing %s: %v", recordID, err)
	}

	return c.Blob(resp.Status, resp.ContentType, resp.Body)
}
