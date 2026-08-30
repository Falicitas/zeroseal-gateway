package endpoints

import (
	"crypto/ed25519"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/zeroseal/gateway/services/attestation"
	"github.com/zeroseal/gateway/services/diag"
	"github.com/zeroseal/gateway/services/secret"
)

// diagRequestMax 是 POST /diag 请求体的上限。里面只有两个 hex 串，
// 1 KB 绰绰有余，超过就是在试探。
const diagRequestMax = 1 << 10

// Diag 挂管理员只读诊断端点。
//
// 这条端点能吐什么由 diag.Dump 穷举，
// 而那份代码在被度量的镜像里，所以「只出错误码」是可审计的事实。
//
// adminPub 为空表示公钥不可用（adminPubHex 是坏的），路由照样注册但一律返 503 ——
// 跟 Attestation 一样，返 404 会让人以为是路径写错了。
type Diag struct {
	adminPub ed25519.PublicKey
	nonces   *nonceStore
}

// NewDiag 取编译进二进制的管理员公钥。
//
// 正常路径下取不到是不可能的：注入本身就要用它，坏了的话 secret.Load 先挂。
// 但 dev 模式走 env 不碰注入，坏常量能一路到这里，所以还是要挡。
func NewDiag() *Diag {
	pub, err := secret.AdminPub()
	if err != nil {
		log.Printf("diag: 管理员公钥不可用，诊断端点将返 503: %v", err)
		return &Diag{}
	}
	return &Diag{adminPub: pub, nonces: newNonceStore()}
}

// Register 注册两条路由。不挂 CORS：这不是给浏览器用的。
func (h *Diag) Register(g *echo.Group) {
	g.GET("/diag/challenge", h.challenge)
	g.POST("/diag", h.read)
}

type challengeResponse struct {
	Nonce string `json:"nonce"`
}

type diagRequest struct {
	Nonce string `json:"nonce"`
	Sig   string `json:"sig"`
}

// challenge 发一个一次性挑战。不带认证——要认证就得先有挑战。
func (h *Diag) challenge(c echo.Context) error {
	if h.nonces == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "诊断端点未启用")
	}
	n, err := h.nonces.issue()
	if err != nil {
		// 挤满只可能是有人在刷这个端点。注意这种时候你也读不到「被刷了」
		// 这件事——读诊断本身要先拿挑战。退路是控制台串口，或者重启。
		return echo.NewHTTPError(http.StatusServiceUnavailable, "挑战暂不可用")
	}
	return c.JSON(http.StatusOK, challengeResponse{Nonce: n})
}

// read 验完签名吐出全部记录。
func (h *Diag) read(c echo.Context) error {
	if h.adminPub == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "诊断端点未启用")
	}

	var req diagRequest
	r := c.Request()
	r.Body = http.MaxBytesReader(c.Response(), r.Body, diagRequestMax)
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "报文解析失败")
	}

	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return echo.NewHTTPError(http.StatusUnauthorized, "挑战格式错误")
	}
	sig, err := hex.DecodeString(req.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return echo.NewHTTPError(http.StatusUnauthorized, "签名格式错误")
	}

	// 先消费再验签：消费是一次 map 操作、验签是一次 Ed25519，便宜的先挡。
	// 顺带得到一个性质——每个挑战只够一次签名尝试，签错了就得重新要挑战。
	if !h.nonces.consume(req.Nonce) {
		return echo.NewHTTPError(http.StatusUnauthorized, "挑战无效或已过期")
	}
	if !ed25519.Verify(h.adminPub, attestation.DiagSigMessage(nonce), sig) {
		return echo.NewHTTPError(http.StatusUnauthorized, "签名校验失败")
	}

	return c.JSON(http.StatusOK, diag.NewDump())
}
