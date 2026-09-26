package endpoints

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/zeroseal/gateway/services/auth"
	"github.com/zeroseal/gateway/services/billing"
	"github.com/zeroseal/gateway/services/llm"
	"github.com/zeroseal/shared/catalog"
)

// upstreamUnreachable 是上游连不上时回给客户端的话。
//
// 原来这里直接回 err.Error()，里面是 DNS 失败、拨号超时、上游 URL 这些
// 内部细节。现在原文改走 diag 的 ring（经 SetInternal 由 HTTPErrorHandler
// 取走），只有管理员读得到；客户端拿到的是这句固定短语。
//
// 🤔：SetInternal 就是给 ring 看的，ring 通过 newHTTPEvent 的 he.Internal 取到了 err
//
// 注意只脱敏这一类：上游自己返的非 2xx 响应体照旧原样透传（c.Blob），
// 那是 OpenAI 兼容的客户端 SDK 要按格式解析的东西。
const upstreamUnreachable = "上游暂时不可达"

const ctxAccountKey = "zeroseal.account" // 随便一个，避免之后和别的 c 的 ctx 重了

// LLM 持有 llm handler 的依赖。providerKeys 转发用，pool 鉴权和下一步计费用。
type LLM struct {
	providerKeys map[string]string
	pool         *pgxpool.Pool
}

func NewLLM(providerKeys map[string]string, pool *pgxpool.Pool) *LLM {
	return &LLM{providerKeys: providerKeys, pool: pool}
}

// Register 注册 OpenAI 兼容路由。/models 公开；
// /chat/completions 通过第三个变长参数单独挂鉴权，只作用于这条路由。
func (h *LLM) Register(g *echo.Group) {
	g.GET("/models", h.listModels)
	catalogGroup := g.Group("/catalog", middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: panelOrigins,
		AllowMethods: []string{http.MethodGet},
	}))
	catalogGroup.GET("/models", h.listCatalogModels)
	g.POST("/chat/completions", h.chatCompletions, h.requireAuth)
	g.POST("/images/generations", h.imageGenerations, h.requireAuth)
	g.POST("/audio/speech", h.audioSpeech, h.requireAuth)
	// 视频是异步的：POST 提交拿任务 ID，GET 轮询取结果。
	g.POST("/videos", h.createVideo, h.requireAuth)
	g.GET("/videos/:id", h.getVideo, h.requireAuth)
}

func (h *LLM) requireAuth(next echo.HandlerFunc) echo.HandlerFunc { // 接一个 handler，下面的闭包执行完后出一个 handler。这里的 next 就是 h.chatCompletions
	return func(c echo.Context) error {
		key, ok := strings.CutPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "缺少 Bearer 凭据")
		}
		acc, err := auth.Authenticate(c.Request().Context(), h.pool, strings.TrimSpace(key))
		if err != nil {
			if err == auth.ErrUnauthorized {
				return echo.NewHTTPError(http.StatusUnauthorized, "凭据无效")
			}
			return echo.NewHTTPError(http.StatusInternalServerError, "鉴权失败")
		}
		c.Set(ctxAccountKey, acc) // 放置请求级别的上下文
		return next(c)
	}
}

type modelObject struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type modelList struct {
	Object string        `json:"object"`
	Data   []modelObject `json:"data"`
}

// 公开目录 DTO 是响应 schema，不是每个模型各自的一份配置：新增模型只改
// shared/catalog/models.go，listCatalogModels 会自动遍历 catalog.All()。
// 字段保持显式白名单，避免直接序列化 catalog.Provider，把 BaseURL、UpstreamID
// 等内部路由信息暴露给浏览器。
type catalogPrice struct {
	Tier     string `json:"tier"`
	InputHit int64  `json:"input_hit"`
	Input    int64  `json:"input"`
	Output   int64  `json:"output"`
}

type catalogModel struct {
	ID        string          `json:"id"`
	Surface   catalog.Surface `json:"surface"`
	Owner     string          `json:"owner"`
	Created   int64           `json:"created"`
	CtxLimit  int64           `json:"ctx_limit"`
	MaxOutput int64           `json:"max_output"`
	Prices    []catalogPrice  `json:"prices"`
}

type catalogModelList struct {
	Object string         `json:"object"`
	Data   []catalogModel `json:"data"`
}

func accountFrom(c echo.Context) (auth.Account, bool) {
	acc, ok := c.Get(ctxAccountKey).(auth.Account)
	return acc, ok
}

// surfaceAll 是 ?surface= 的特殊值，表示不过滤。
const surfaceAll = "all"

// listModels 默认只列对话模型。
//
// OpenAI 的 /v1/models 响应没有能力字段（就 id/object/created/owned_by 四个），
// 客户端拿到列表分不出谁能对话——把生图、语音模型混在里面，用户在模型下拉框里
// 选中就是一个 400，而且他不知道自己做错了什么。「列表不全」还能靠 panel 页面和
// 文档补，「选了就报错」补不了，所以默认收窄。
//
// 收窄的只是默认展示什么，不是能用什么：直接按 ID 打对应端点照样通。
// 要别的模态传 ?surface=image|speech|video，要全量传 ?surface=all。
func (h *LLM) listModels(c echo.Context) error {
	want := c.QueryParam("surface")
	if want == "" {
		want = string(catalog.SurfaceChat)
	}
	if want != surfaceAll && !catalog.Surface(want).Valid() {
		return echo.NewHTTPError(http.StatusBadRequest, "surface 只能是 chat / image / speech / video / all")
	}

	entries := catalog.All()
	out := modelList{
		Object: "list",
		Data:   make([]modelObject, 0, len(entries)),
	}
	for _, m := range entries {
		if want != surfaceAll && string(m.Surface) != want {
			continue
		}
		out.Data = append(out.Data, modelObject{
			ID:      m.ID,
			Object:  "model",
			Created: m.Created,
			OwnedBy: m.Owner,
		})
	}
	return c.JSON(http.StatusOK, out)
}

// listCatalogModels 返回给 panel 展示用的公开目录。一个模型可能接入多个
// provider；相同 tier 和价格只保留一条，但不同 tier 始终分别展示。
// 只有公开目录需要新的字段时，才在 DTO 这里同步扩展；模型增删不需要改这里。
func (h *LLM) listCatalogModels(c echo.Context) error {
	entries := catalog.All()
	out := catalogModelList{
		Object: "catalog",
		Data:   make([]catalogModel, 0, len(entries)),
	}
	for _, m := range entries {
		out.Data = append(out.Data, catalogModel{
			ID:        m.ID,
			Surface:   m.Surface,
			Owner:     m.Owner,
			Created:   m.Created,
			CtxLimit:  m.CtxLimit,
			MaxOutput: m.MaxOutput,
			Prices:    publicPrices(m),
		})
	}
	return c.JSON(http.StatusOK, out)
}

func publicPrices(m catalog.Model) []catalogPrice {
	prices := make([]catalogPrice, 0)
	seen := make(map[catalogPrice]struct{})
	for _, p := range m.Providers {
		for tier, price := range p.Pricing {
			item := catalogPrice{
				Tier:     tier,
				InputHit: price.InputHit,
				Input:    price.Input,
				Output:   price.Output,
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			prices = append(prices, item)
		}
	}
	slices.SortFunc(prices, func(a, b catalogPrice) int {
		if a.Tier != b.Tier {
			return strings.Compare(a.Tier, b.Tier)
		}
		if a.InputHit != b.InputHit {
			return cmp.Compare(a.InputHit, b.InputHit)
		}
		if a.Input != b.Input {
			return cmp.Compare(a.Input, b.Input)
		}
		return cmp.Compare(a.Output, b.Output)
	})
	return prices
}
func (h *LLM) chatCompletions(c echo.Context) error {
	acc, ok := accountFrom(c)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "缺少鉴权账户")
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "读取请求体失败")
	}

	var probe struct {
		Model     string `json:"model"`
		MaxTokens int64  `json:"max_tokens"`
		Stream    bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "请求体不是合法 JSON")
	}

	m, ok := catalog.Lookup(probe.Model)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "model "+probe.Model+" 不存在")
	}
	if m.Surface != catalog.SurfaceChat {
		return echo.NewHTTPError(http.StatusBadRequest, "model "+probe.Model+" 不是对话模型，请用它对应的端点")
	}

	p, ok := pickProvider(m)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "model "+m.ID+" 无可用上游")
	}
	key, ok := h.providerKeys[p.Name]
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 无可用凭据")
	}
	adapter, ok := llm.ChatFor(p.Name)
	if !ok {
		return echo.NewHTTPError(http.StatusBadGateway, "provider "+p.Name+" 未接入对话协议")
	}
	// 计价时刻只在这里取一次，预扣和结算共用 —— 分时定价的上游（DeepSeek）
	// 靠它落档，两边取不同时刻的话，跨过 9:00 这种边界的请求会按不同单价
	// 预扣和结算。
	at := time.Now()

	// chat 请求本身不分档，tier 恒为默认档；分时的落档在 PriceOf 里按 at 做。
	pricing, ok := p.PriceOf(catalog.TierDefault, at)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "model "+m.ID+" 缺定价")
	}

	// 预扣（两条路径共用）
	maxToken := probe.MaxTokens
	if maxToken <= 0 {
		maxToken = defaultMaxToken
	}
	// 输出封顶：上游单列了输出上限就按它，没单列的退回上下文上限。
	// 再多预扣也是空占余额 —— 上游不可能输出超过这个数。
	outputCap := m.MaxOutput
	if outputCap <= 0 {
		outputCap = m.CtxLimit
	}
	if maxToken > outputCap {
		maxToken = outputCap
	}
	runeCount := int64(len([]rune(string(body)))) // rune 不等于 int32。里面转为 rune[]，这个是解析 utf-8 字符用的
	hold := billing.EstimateHold(pricing, m.CtxLimit, runeCount, maxToken)

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

	cl := call{
		adapter:  adapter,
		provider: p,
		key:      key,
		body:     body,
		recordID: recordID,
		at:       at,
	}
	if probe.Stream {
		return h.streamCompletion(c, cl)
	}
	return h.nonStreamCompletion(c, cl)
}

// defaultMaxToken 是客户没传 max_tokens 时用来预扣输出的量。
//
// 原来这里取 m.CtxLimit，在便宜模型上就已经难看（deepseek-v4-pro 一次预扣 6 元），
// 接上 kimi-k3（输出 ¥100/百万 token、上下文 1M）之后会变成一次预扣 105 元 ——
// 余额不到这个数的用户连一句「你好」都发不出去。
//
// 32768 覆盖绝大多数单轮输出。真超了也只是预扣不足，结算时从余额补扣
// （见 billing.Finalize），比误拒强。
const defaultMaxToken = 32768

// pickProvider 选一个上游。目前固定第一个 —— 故障转移、按价选、限流分流
// 这些策略等真有第二个上游可选时再说，届时只动这个函数。
func pickProvider(m catalog.Model) (catalog.Provider, bool) {
	if len(m.Providers) == 0 {
		return catalog.Provider{}, false
	}
	return m.Providers[0], true
}

// call 是一次转发要用到的全部上下文。攒成一个结构是为了避免在几个 handler
// 之间传一长串位置参数，加一个维度就得改所有签名。
type call struct {
	adapter  llm.Adapter
	provider catalog.Provider
	key      string
	body     []byte
	recordID string
	at       time.Time // 计价时刻，取请求发起时。分时定价靠它落档
}

// upstreamTimeout 是非流式请求等上游把话说完的上限。
// 要大于 http.Server 的 WriteTimeout：客户端那条连接先断没关系，
// 我们得把上游读完才知道该扣多少。
const upstreamTimeout = 10 * time.Minute

func (h *LLM) nonStreamCompletion(c echo.Context, cl call) error {

	// 上游请求刻意不挂客户端的 context。挂上去的话，客户端断连或者
	// WriteTimeout 到点会连带取消上游请求——而上游那边活已经干了、token 照样计费，
	// 我们却因为没读到响应而拿不到 usage，只能在「全退」和「全扣」之间猜。
	//
	// 断开之后照样把上游读完，按真实用量结算。这跟流式路径的 ClientGone
	// 是同一个处理：客户端走了，账还是要按上游实际发生的算。
	upCtx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()

	// 转发。失败则退款。
	resp, err := llm.Forward(upCtx, cl.adapter, cl.provider, cl.key, cl.body)
	if err != nil {
		_ = billing.Refund(context.Background(), h.pool, cl.recordID)
		return echo.NewHTTPError(http.StatusBadGateway, upstreamUnreachable).SetInternal(err)
	}
	// 上游返回非 2xx 也退款（用户不该为上游错误付费）。
	if resp.Status < 200 || resp.Status >= 300 {
		_ = billing.Refund(context.Background(), h.pool, cl.recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}

	// 解析 usage 结算。解析不出、或档位查不到价，都退款（拿不到用量不能乱扣）。
	usage, ok := cl.adapter.ParseUsage(resp.Body)
	if !ok {
		_ = billing.Refund(context.Background(), h.pool, cl.recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}
	actual, ok := billing.Settle(cl.provider, usage, cl.at)
	if !ok {
		_ = billing.Refund(context.Background(), h.pool, cl.recordID)
		return c.Blob(resp.Status, resp.ContentType, resp.Body)
	}
	if err := billing.Finalize(context.Background(), h.pool, cl.recordID, actual); err != nil {
		// 结算失败不影响给用户返响应，但要记日志人工对账。
		c.Logger().Errorf("finalize billing %s: %v", cl.recordID, err)
	}

	return c.Blob(resp.Status, resp.ContentType, resp.Body)
}

func (h *LLM) streamCompletion(c echo.Context, cl call) error {
	resp := c.Response()

	// 只在这条流式响应上解除写超时
	rc := http.NewResponseController(resp.Writer)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		_ = billing.Refund(context.Background(), h.pool, cl.recordID)
		return echo.NewHTTPError(http.StatusInternalServerError, "无法配置流式响应")
	}

	// 首次写入上游数据时才提交 200，建流失败仍能返回正确的 HTTP 错误码。
	resp.Header().Set("Content-Type", "text/event-stream")
	resp.Header().Set("Cache-Control", "no-cache")
	resp.Header().Set("Connection", "keep-alive")

	// 读上游用独立 ctx：客户端断连也读完，拿 usage 结算
	readCtx := context.Background()
	result, ferr := llm.ForwardStream(readCtx, cl.adapter, cl.provider, cl.key, cl.body, resp.Writer, resp.Flush)
	if result == nil {
		// 建流失败改回普通 HTTP 响应；Echo 不会覆盖已经设置的 Content-Type。
		resp.Header().Del("Content-Type")
		resp.Header().Del("Cache-Control")
		resp.Header().Del("Connection")
	}

	// 计费收尾。用独立 ctx，不受客户端断连影响。
	settleCtx := context.Background()

	var upErr *llm.UpstreamError
	switch {
	case errors.As(ferr, &upErr):
		// 上游尚未建流，下游也未提交响应，可以返回 JSON 和实际错误状态。
		_ = billing.Refund(settleCtx, h.pool, cl.recordID)
		c.Logger().Errorf("stream upstream %d, refunded %s", upErr.Status, cl.recordID)
		return c.Blob(upErr.Status, "application/json", upErr.Body)

	case result == nil:
		// 上游根本没连上（DNS / TCP / 超时），ForwardStream 在建流之前就返错，
		// result 是 nil。这里不判空的话下面几个分支会直接 panic，而 panic 之后
		// 预扣既不结算也不退款，用户余额被永久锁住。
		_ = billing.Refund(settleCtx, h.pool, cl.recordID)
		c.Logger().Errorf("stream 上游不可达，已退款 %s: %v", cl.recordID, ferr)
		return echo.NewHTTPError(http.StatusBadGateway, upstreamUnreachable).SetInternal(ferr)

	case ferr != nil && len(result.Usage) == 0:
		// 上游流中途断、且没扫到 usage → 按预扣全额扣（暂定，不退）。
		// TODO 上游断的计费策略待进一步决策。目前是全扣
		if err := billing.SettleFull(settleCtx, h.pool, cl.recordID); err != nil {
			c.Logger().Errorf("stream broken, settle-full %s: %v", cl.recordID, err)
		}
		return nil

	case len(result.Usage) > 0:
		// 正常拿到 usage（不管客户端有没有断连，都按真实用量结算）
		actual, ok := billing.Settle(cl.provider, result.Usage, cl.at)
		if !ok {
			_ = billing.Refund(settleCtx, h.pool, cl.recordID)
			c.Logger().Errorf("stream settle 查不到档位单价，已退款 %s", cl.recordID)
			return nil
		}
		if err := billing.Finalize(settleCtx, h.pool, cl.recordID, actual); err != nil {
			c.Logger().Errorf("stream finalize %s: %v", cl.recordID, err)
		}
		return nil

	default:
		// 流正常结束但没扫到 usage（理论不该发生，include_usage 已注入）。
		// 内容已发完、用户已消费，不退——按预扣全额扣，跟上游中断一致。
		// TODO 观察是否真会发生；若频繁说明 usage 扫描有 bug
		if err := billing.SettleFull(settleCtx, h.pool, cl.recordID); err != nil {
			c.Logger().Errorf("stream end no usage, settle-full %s: %v", cl.recordID, err)
		}
		return nil
	}
}
