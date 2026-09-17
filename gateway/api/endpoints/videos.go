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
	"github.com/zeroseal/gateway/services/video"
	"github.com/zeroseal/shared/catalog"
)

const (
	// videoSubmitTimeout 是提交任务的上限。上游只是入队就返回，很快。
	videoSubmitTimeout = 60 * time.Second

	// videoPollTimeout 是查询任务状态的上限。同样是个轻接口。
	videoPollTimeout = 30 * time.Second
)

// createVideo 提交一个视频生成任务。
//
// 跟前三个 surface 的区别是这里只走完计费的前一半：预扣 + 落库，结算要等任务
// 跑完，由客户轮询（getVideo）或者 worker 兜底完成。
func (h *LLM) createVideo(c echo.Context) error {
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
	if m.Surface != catalog.SurfaceVideo {
		return echo.NewHTTPError(http.StatusBadRequest, "model "+probe.Model+" 不是视频生成模型，请用它对应的端点")
	}

	p, ok := pickProvider(m)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "model "+m.ID+" 无可用上游")
	}
	key, ok := h.providerKeys[p.Name]
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 无可用凭据")
	}
	adapter, ok := llm.VideoFor(p.Name)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 未接入视频生成协议")
	}

	// 预扣按最坏情况估。结算时刻用的是任务落库的 created_at，跟这里的 now()
	// 差几毫秒，分时落档不受影响。
	worst, err := adapter.EstimateUsage(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "请求参数无法估算用量")
	}
	hold, ok := billing.Settle(p, worst, time.Now())
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

	upCtx, cancel := context.WithTimeout(context.Background(), videoSubmitTimeout)
	defer cancel()

	resp, err := llm.SubmitVideo(upCtx, adapter, p, key, body)
	if err != nil {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		return echo.NewHTTPError(http.StatusBadGateway, upstreamUnreachable).SetInternal(err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		_ = billing.Refund(context.Background(), h.pool, recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}

	upstreamID, ok := adapter.ParseSubmit(resp.Body)
	if !ok {
		// 任务多半真的建起来了，但我们拿不到它的 ID —— 那就再也没法查、没法
		// 结算，客户也没法取。退款，这次上游成本我们自己吃。
		_ = billing.Refund(context.Background(), h.pool, recordID)
		c.Logger().Errorf("video 提交成功但取不到任务 ID，已退款 %s", recordID)
		return echo.NewHTTPError(http.StatusBadGateway, "上游未返回任务 ID")
	}

	if err := video.Create(context.Background(), h.pool, video.Task{
		UpstreamID: upstreamID,
		Model:      m.ID,
		Provider:   p.Name,
		RecordID:   recordID,
		Status:     string(llm.TaskRunning),
		// 档位跟预扣用的是同一份估算结果，保证预扣和结算落同一档。
		Tier: worst[0].Tier,
	}); err != nil {
		// 同上：存不下就等于这个任务既结算不了也查不了。
		_ = billing.Refund(context.Background(), h.pool, recordID)
		c.Logger().Errorf("video 任务落库失败，已退款 %s: %v", recordID, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "任务创建失败")
	}

	// 上游的提交响应原样返回，客户拿到的就是那个任务 ID。
	return c.Blob(resp.Status, resp.ContentType, resp.Body)
}

// getVideo 查任务。响应体是上游原文，我们只在它到达终态时顺手把账结了。
func (h *LLM) getVideo(c echo.Context) error {
	acc, ok := accountFrom(c)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "缺少鉴权账户")
	}

	// video.Get 里带了归属校验，别人的任务一律当不存在。
	t, err := video.Get(c.Request().Context(), h.pool, c.Param("id"), acc.KeyID)
	if errors.Is(err, video.ErrNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, "任务不存在")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "查询任务失败")
	}

	m, ok := catalog.Lookup(t.Model)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "model "+t.Model+" 已不可用")
	}
	// 提交给了哪家就查哪家，不重算 —— pickProvider 以后要做故障转移。
	p, ok := m.ProviderByName(t.Provider)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+t.Provider+" 已不可用")
	}
	key, ok := h.providerKeys[t.Provider]
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+t.Provider+" 无可用凭据")
	}
	adapter, ok := llm.VideoFor(t.Provider)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+t.Provider+" 未接入视频生成协议")
	}

	upCtx, cancel := context.WithTimeout(context.Background(), videoPollTimeout)
	defer cancel()

	resp, err := llm.PollVideo(upCtx, adapter, p, key, t.UpstreamID)
	if err != nil {
		// 查不到不动账：任务还在上游那儿，客户下次再来，或者 worker 兜底。
		return echo.NewHTTPError(http.StatusBadGateway, upstreamUnreachable).SetInternal(err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}

	if !t.Settled {
		if state, usage, ok := adapter.ParseTask(resp.Body); ok {
			// 结算用独立 ctx：客户端这时候断连不该让账留在半路。
			video.Finish(context.Background(), h.pool, p, t, state, usage)
		}
	}

	return c.Blob(resp.Status, resp.ContentType, resp.Body)
}
