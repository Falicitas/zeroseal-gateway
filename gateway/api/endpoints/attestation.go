package endpoints

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/zeroseal/gateway/services/attestation"
)

var panelOrigins = []string{
	"https://zeroseal.cn",
	"http://localhost:3000",
}

// Attestation 挂 TDX 挑战证明端点。
//
// col 为 nil 表示本实例没有 attestation 能力（本机不是 TDX 环境）。
// 这种情况下路由照样注册、一律返 503：返 404 会让调用方以为是路径写错了，
// 503 才说得清是环境不支持。
type Attestation struct {
	col *attestation.Collateral
}

func NewAttestation(col *attestation.Collateral) *Attestation {
	return &Attestation{col: col}
}

// Register 注册公开路由，不挂鉴权。
// 验证能力锁在付费墙后面等于自断卖点——潜在客户、白帽、第三方尽调
// 都需要在不持有 api key 的前提下能验。
//
// CORS 只开给这一个端点。/v1/chat/completions 不开
// 挂在路由上而非整组，是因为这是简单 GET 请求，浏览器不发 OPTIONS 预检。
// TODO: 以后若给这个端点加自定义请求头，就得改挂到组上，否则预检会走不到中间件。
func (h *Attestation) Register(g *echo.Group) {
	g.GET("/attestation", h.get, middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: panelOrigins,
		AllowMethods: []string{http.MethodGet},
	}))
}

func (h *Attestation) get(c echo.Context) error {
	if h.col == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable,
			"本实例未启用 attestation：不是 TDX 环境")
	}

	// EKM 只能取自本连接的 TLS 状态，绝不接受请求方传入。
	// 这条是整个通道绑定成立的前提，破了就等于允许上游节点
	// 拿它与客户端那条会话的 EKM 来换 quote。
	// 详见 services/attestation/reportdata.go 的注释。
	cs := c.Request().TLS
	if cs == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable,
			"attestation 需要 TLS 连接，本实例监听的是明文 HTTP")
	}

	raw, err := cs.ExportKeyingMaterial(attestation.EKMLabel, nil, 32)
	if err != nil {
		// TLS 1.3 下不该走到这里。会返错的两种情况是开了 renegotiation，
		// 或者既非 TLS 1.3 又没有 Extended Master Secret。
		log.Printf("attestation: 导出 EKM 失败: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "导出 EKM 失败")
	}
	var ekm [32]byte
	copy(ekm[:], raw)

	quote, err := attestation.Quote(attestation.ComposeReportData(ekm))
	if err != nil {
		log.Printf("attestation: 取 quote 失败: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "取 quote 失败")
	}

	return c.JSON(http.StatusOK, attestation.Response{
		Version:    attestation.ProtocolVersion,
		Provider:   attestation.Provider,
		Quote:      quote,
		Collateral: h.col.Snapshot(), // secrets.Attestation 被 goroutine 和 h.col 同时持有，并且持有读写锁避免在写的时候发生读
	})
}
