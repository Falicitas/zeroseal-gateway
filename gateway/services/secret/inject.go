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
// 它是公开信息，进公开源码没有问题。而它编译进二进制、也就进了 measurement，
// 这带来一个可以对外展示的性质：任何人审我们的镜像都能确认，这台 TD 只接受
// 某一把特定私钥签发的配置指令，运营方换不了人也塞不了别的东西。
//
// 换 key 需要重出镜像，这是有意的——注入授权本来就该是需要重新度量的变更。
//
// 生成方式见 cmd/zsinject 的 -gen-key。
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
}

// awaitInjection 起注入监听并阻塞，直到收到一份验签解密都通过的机密。
//
// 监听是明文 HTTP：TLS 私钥本身就是要注入的东西之一，这条信道不能依赖它。
// 保密性靠信封（收方公钥来自 quote，注入方验完度量才加密），
// 授权靠 adminPub 的签名，可达性靠安全组只放行管理员 IP。
func awaitInjection(ctx context.Context, addr string) (*Payload, error) {
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

	inj := &injector{
		priv:     priv,
		pub:      pub[:],
		quote:    quote,
		adminPub: adminPub,
		result:   make(chan *Payload, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /inject/quote", inj.serveQuote)
	mux.HandleFunc("POST /inject", inj.serveInject)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
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
	log.Printf("secret: 等待机密注入，监听 %s，TD 临时公钥 %s",
		addr, hex.EncodeToString(pub[:]))

	select {
	case p := <-inj.result:
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
		_ = srv.Close()
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
	var env Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&env); err != nil {
		http.Error(w, "报文解析失败", http.StatusBadRequest)
		return
	}

	plain, err := OpenEnvelope(&env, i.priv, i.adminPub)
	if err != nil {
		// 日志只记类别不记内容，注入端点是对外可达的。
		log.Printf("secret: 注入被拒: %v", err)
		http.Error(w, "信封校验失败", http.StatusForbidden)
		return
	}

	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		log.Printf("secret: 注入载荷解析失败: %v", err)
		http.Error(w, "载荷格式错误", http.StatusBadRequest)
		return
	}
	if err := p.validate(); err != nil {
		log.Printf("secret: 注入载荷校验失败: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	select {
	case i.result <- &p:
		w.WriteHeader(http.StatusNoContent)
	default:
		// 已经注入过一次了。机密不轮换、进程期不变，第二次一律拒。
		http.Error(w, "已完成注入", http.StatusConflict)
	}
}

// validate 在这里而不是在 Load 里做，是为了让失败能带着原因回给注入方，
// 而不是等进程退出之后再去翻日志。
func (p *Payload) validate() error {
	if len(p.ProviderKeys) == 0 {
		return errors.New("provider_keys 为空")
	}
	for name, key := range p.ProviderKeys {
		if name == "" || key == "" {
			return errors.New("provider_keys 里有空的 name 或 key")
		}
	}
	if p.DBDSN == "" {
		return errors.New("db_dsn 为空")
	}
	if p.TLSCertPEM == "" || p.TLSKeyPEM == "" {
		return errors.New("tls_cert_pem 和 tls_key_pem 必须同时提供")
	}
	if _, err := tls.X509KeyPair([]byte(p.TLSCertPEM), []byte(p.TLSKeyPEM)); err != nil {
		return fmt.Errorf("证书和私钥不匹配或格式错误: %w", err)
	}
	return nil
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
