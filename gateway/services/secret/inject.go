package secret

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/zeroseal/gateway/services/attestation"
)

// adminPubHex 是唯一被允许注入机密的管理员 Ed25519 公钥。
//
// 换 key 需要重出镜像，这是有意的——注入授权本来就该是需要重新度量的变更。
const adminPubHex = "4ae8117f1160da2e58dd7e1d75dd60f3a3c27590dd3849eb27ee12d1080ff062"

// injectShutdownGrace 给成功响应留出写回客户端的时间，再关监听。
const injectShutdownGrace = 2 * time.Second

// injectQuoteResponse 是 GET /inject/quote 的响应体。
//
// 不带 collateral：注入发生在拉 collateral 之前，而注入工具跑在有外网的机器上，
// 自己去 Intel 拉就行。
//
// EphPub 必须发：report_data 是 sha512(domain || eph_pub)，是单向的，
// 注入方反推不出公钥。发出来之后由注入方验 sha512(domain||eph_pub) == report_data，
// 这份公钥就等于被 quote 背书了——服务端给不了一把 quote 没盖章的公钥。
type injectQuoteResponse struct {
	Version  int    `json:"version"`
	Provider string `json:"provider"`
	Quote    []byte `json:"quote"`
	EphPub   []byte `json:"eph_pub"`
}

type injector struct {
	priv     *ecdh.PrivateKey
	pub      []byte
	quote    []byte
	adminPub ed25519.PublicKey
	result   chan *Payload
	status   *injectStatus
}

// newInjector 备好临时密钥和 quote。
//
// 这两样只要 configfs、不要 collateral，所以能排在拉 collateral 之前 ——
// 监听因此也提前得了，拉 collateral 的过程中 /inject/status 就能答话。
func newInjector() (*injector, error) {
	adminPub, err := decodeAdminPub()
	if err != nil {
		return nil, err
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secret: 生成 TD 临时密钥: %w", err)
	}
	var pub [32]byte
	copy(pub[:], priv.PublicKey().Bytes())

	quote, err := attestation.Quote(attestation.ComposeInjectReportData(pub))
	if err != nil {
		return nil, fmt.Errorf("secret: 取注入用 quote: %w", err)
	}

	return &injector{
		priv:     priv,
		pub:      pub[:],
		quote:    quote,
		adminPub: adminPub,
		result:   make(chan *Payload, 1),
		status:   newInjectStatus(),
	}, nil
}

// serve9443 起监听并立刻返回，errCh 收监听自身的失败。
//
// 监听是明文 HTTP：TLS 私钥本身就是要注入的东西之一，这条信道不能依赖它。
// 保密性靠信封（收方公钥来自 quote，注入方验完度量才加密），
// 授权靠 adminPub 的签名，可达性靠安全组只放行管理员 IP。
func (i *injector) serve9443(addr string) (*http.Server, <-chan error) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           i.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	log.Printf("secret: 注入监听已起 %s，TD 临时公钥 %s",
		addr, hex.EncodeToString(i.pub))
	return srv, errCh
}

// handler 是 9443 上的三条路由。
//
// quote 和 status 是 GET、无认证：前者是公开材料，后者只出枚举和时间戳。
// 授权只发生在 POST /inject，靠信封里的 adminPub 签名。
func (i *injector) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /inject/quote", i.serveQuote)
	mux.HandleFunc("GET /inject/status", i.serveStatus)
	mux.HandleFunc("POST /inject", i.serveInject)
	return mux
}

// wait 阻塞到收到一份验签解密都通过的机密。
func (i *injector) wait(ctx context.Context, srv *http.Server, errCh <-chan error) (*Payload, error) {
	select {
	case p := <-i.result:
		// 成功才关。验签失败、解密失败、字段缺失都不关，允许重试——
		// 关早了就只能重启 TD，而重启要走一次 grub-reboot，代价不小。
		time.Sleep(injectShutdownGrace)
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("secret: 关闭注入监听: %v", err)
		}
		log.Print("secret: 机密注入完成，注入监听已关闭")
		return p, nil
	case err := <-errCh:
		return nil, fmt.Errorf("secret: 注入监听失败: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (i *injector) serveQuote(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(injectQuoteResponse{
		Version:  attestation.ProtocolVersion,
		Provider: attestation.Provider,
		Quote:    i.quote,
		EphPub:   i.pub,
	})
}

func (i *injector) serveInject(w http.ResponseWriter, r *http.Request) {
	// 🤔：Load 中的 collateral 没拉完就不收。见 ErrCodeNotReady 的注释：这一段收下机密
	// 🤔：等于赌 collateral 一定成功，赌输了机密就随进程没掉。
	if !i.status.ready() {
		i.reject(w, http.StatusServiceUnavailable, ErrCodeNotReady, "尚未就绪，稍后重试", nil)
		return
	}

	var env Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&env); err != nil {
		i.reject(w, http.StatusBadRequest, ErrCodeEnvelopeMalformed, "报文解析失败", err)
		return
	}

	plain, err := OpenEnvelope(&env, i.priv, i.adminPub)
	if err != nil {
		i.reject(w, http.StatusForbidden, codeOf(err), "信封校验失败", err)
		return
	}

	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		i.reject(w, http.StatusBadRequest, ErrCodePayloadMalformed, "载荷格式错误", err)
		return
	}
	if err := p.validate(); err != nil {
		// 载荷校验的原因原样回给注入方，让他当场知道是哪个字段不对。
		// 进 /inject/status 的只有码，不是这句话。
		// 🤔：到这一步，已经确认是管理员了，所以下面就可以放出 err.Error() 而不是类似上面的有限信息的错误字面量
		i.reject(w, http.StatusBadRequest, codeOf(err), err.Error(), err)
		return
	}

	select {
	case i.result <- &p:
		w.WriteHeader(http.StatusNoContent)
	default:
		// 已经注入过一次了。机密不轮换、进程期不变，第二次一律拒。
		i.reject(w, http.StatusConflict, ErrCodeAlreadyInjected, "已完成注入", nil)
	}
}

// reject 把「记状态、写日志、回响应」收在一处，免得哪条失败路径漏记状态。
// 日志只记类别不记内容 —— 注入端点是对外可达的。
func (i *injector) reject(w http.ResponseWriter, status int, code InjectErrCode, msg string, err error) {
	i.status.fail(code)
	if err != nil {
		log.Printf("secret: 注入被拒 [%s]: %v", code, err)
	} else {
		log.Printf("secret: 注入被拒 [%s]", code)
	}
	http.Error(w, msg, status)
}

// validate 在这里而不是在 Load 里做，是为了让失败能带着原因回给注入方，
// 而不是等进程退出之后再去翻日志。
func (p *Payload) validate() error {
	if len(p.ProviderKeys) == 0 {
		return &injectCodedError{code: ErrCodeProviderKeysEmpty, msg: "provider_keys 为空"}
	}
	for name, key := range p.ProviderKeys {
		if name == "" || key == "" {
			return &injectCodedError{code: ErrCodeProviderKeysInvalid, msg: "provider_keys 里有空的 name 或 key"}
		}
	}
	if p.DBDSN == "" {
		return &injectCodedError{code: ErrCodeDBDSNEmpty, msg: "db_dsn 为空"}
	}
	if p.TLSCertPEM == "" || p.TLSKeyPEM == "" {
		return &injectCodedError{code: ErrCodeTLSPairIncomplete, msg: "tls_cert_pem 和 tls_key_pem 必须同时提供"}
	}
	if _, err := tls.X509KeyPair([]byte(p.TLSCertPEM), []byte(p.TLSKeyPEM)); err != nil {
		return &injectCodedError{ErrCodeCertKeyMismatch, "证书和私钥不匹配或格式错误", err}
	}
	return nil
}

// AdminPub 返回编译进二进制的管理员公钥。
//
// 诊断端点复用同一把密钥做挑战认证。两个协议的签名消息靠域分离区分：
// 诊断那边签 sha256("ZS-DIAG-v1") || nonce，见 api/endpoints/challenge.go。
// 标签只加在那一侧，所以下面 sigMessage 的格式不用动，zsinject 也不受影响。
func AdminPub() (ed25519.PublicKey, error) {
	return decodeAdminPub()
}

func decodeAdminPub() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(adminPubHex)
	if err != nil {
		return nil, fmt.Errorf("secret: adminPubHex 不是合法 hex（编译期常量还没填？）: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("secret: adminPubHex 长度是 %d，应为 %d 字节",
			len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
