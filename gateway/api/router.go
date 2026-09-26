package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/zeroseal/gateway/api/endpoints"
	"github.com/zeroseal/gateway/services/attestation"
	"github.com/zeroseal/gateway/services/diag"
)

// NewRouter 建实例、划版本组，具体路由由 endpoints 各文件注册。
// 返回 http.Handler，Echo 只作路由，超时和 TLS 由 main 的 http.Server 管。
//
// col 为 nil 表示本机不是 TDX 环境，attestation 路由照样注册但一律返 503。
func NewRouter(providerKeys map[string]string, pool *pgxpool.Pool, col *attestation.Collateral) http.Handler {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// echo 层的两个采集点，业务代码一行不改。
	//
	// HTTPErrorHandler 接住 api/endpoints 里全部 72 处 echo.NewHTTPError
	// （echo 自己的默认实现不打日志，那些错误今天完全静默）；
	// Logger 接住 17 处 c.Logger().Errorf 的计费收尾失败；
	// Recover 接住 panic 的栈（现在没装，栈只进 stderr，摘 sshd 后就没了）。
	//
	// 第三个采集点是上游失败，在 services/llm 里直接调 diag.RecordUpstream。
	e.HTTPErrorHandler = diag.HTTPErrorHandler(e.DefaultHTTPErrorHandler)
	e.Logger = diag.Logger(e.Logger)
	e.Use(diag.Recover())

	v1 := e.Group("/v1")
	// 仅检查 HTTP 服务存活，不调用模型或生成 TEE quote。
	v1.GET("/health", func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(http.StatusOK, map[string]string{"service": "gateway", "status": "ok"})
	}, middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"https://zeroseal.cn", "https://zeroseal.cc"},
		AllowMethods: []string{http.MethodGet},
	}))

	endpoints.NewLLM(providerKeys, pool).Register(v1)
	endpoints.NewAttestation(col).Register(v1)
	endpoints.NewDiag().Register(v1)

	return e
}
