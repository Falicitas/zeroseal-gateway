package api

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/zeroseal/gateway/api/endpoints"
	"github.com/zeroseal/gateway/services/attestation"
)

// NewRouter 建实例、划版本组，具体路由由 endpoints 各文件注册。
// 返回 http.Handler，Echo 只作路由，超时和 TLS 由 main 的 http.Server 管。
//
// col 为 nil 表示本机不是 TDX 环境，attestation 路由照样注册但一律返 503。
func NewRouter(providerKeys map[string]string, pool *pgxpool.Pool, col *attestation.Collateral) http.Handler {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	v1 := e.Group("/v1")

	endpoints.NewLLM(providerKeys, pool).Register(v1)
	endpoints.NewAttestation(col).Register(v1)

	return e
}
