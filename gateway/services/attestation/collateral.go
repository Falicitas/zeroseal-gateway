package attestation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// EKMLabel 是 RFC 5705 导出密钥材料用的 label。
// 带版本号是为了以后 report_data 布局变了能换 label，
// 避免新旧客户端算出同一个值却含义不同。
const EKMLabel = "EXPORTER-ZeroSeal-Attestation-v1"

// ProtocolVersion 是响应体的协议版本。
// v1 的 report_data 尾 32 字节恒为零，等 receipt 签名密钥定下来之后升 v2。
const ProtocolVersion = 1

// Provider 是 configfs TSM 在 TDX 下的 provider 取值，原样回给客户端。
const Provider = wantProvider

// rootCACRLURL 必须和客户端验证库请求的 URL 一致，
// 否则客户端拿 bundle 做离线验证、按 URL 分派时会 miss。
const rootCACRLURL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

// pckCA 是 PCK CRL 的 ca 参数，阿里云这批机器是 platform CA。
const pckCA = "platform"

const (
	// refreshInterval 按最短的那份材料定。PCK CRL 有效期 30 天，
	// 6 小时一轮意味着连续失败一百多次才会真的过期。
	refreshInterval = 6 * time.Hour
	fetchTimeout    = 15 * time.Second
	loadAttempts    = 5
)

// Item 是一份 collateral 及其 issuer chain。
// IssuerChain 存的是已经解过 URL 编码的 PEM——Intel 在 header 里传的是
// %20 %0A %2F 那种编码形式，那属于它的传输层细节，没理由渗到我们的协议里。
type Item struct {
	Body        []byte `json:"body"`
	IssuerChain string `json:"issuer_chain,omitempty"`
}

// Bundle 是客户端离线验证 quote 所需的全部 Intel 材料。
type Bundle struct {
	TCBInfo    Item `json:"tcb_info"`
	QEIdentity Item `json:"qe_identity"`
	PCKCRL     Item `json:"pck_crl"`
	RootCACRL  Item `json:"root_ca_crl"`
}

// Response 是 GET /v1/attestation 的响应体。
type Response struct {
	Version    int    `json:"version"`
	Provider   string `json:"provider"`
	Quote      []byte `json:"quote"`
	Collateral Bundle `json:"collateral"`
}

// Collateral 缓存 Intel PCS 的材料并定期刷新。
type Collateral struct {
	fmspc  string
	client *http.Client

	mu     sync.RWMutex
	bundle Bundle
}

// NewCollateral 解出本机 FMSPC 并同步拉一次 collateral。
//
// 第一份必须成功，拉不到就返错让调用方 fail-fast。理由是「从来没拉到过」
// 这个状态如果允许存在，客户端拿到的就是一份没有价值的材料，
// 而端点又不该为此返 503（那会把 quote 一起挡掉，客户端连兜底机会都没有）。
// 直接不启动比带着这个状态跑更干净。
//
// 非 TDX 环境返回的错误可以用 errors.Is(err, ErrTSMUnavailable) 判定，
// 调用方据此降级成「不启用 attestation」，而不是启动失败。
func NewCollateral(ctx context.Context) (*Collateral, error) {
	// 先取一份 quote 只为解 FMSPC，report_data 填什么都无所谓。
	quote, err := Quote([64]byte{})
	if err != nil {
		return nil, fmt.Errorf("attestation: 取 quote 解 FMSPC: %w", err)
	}
	fmspc, err := extractFMSPC(quote)
	if err != nil {
		return nil, err
	}

	c := &Collateral{
		fmspc:  fmspc,
		client: &http.Client{Timeout: fetchTimeout},
	}

	// 重试退避，总上限约 30 秒。realistic 的失败模式是网络还没就绪
	// （overlay 里 systemd-networkd-wait-online 被 mask 了）和瞬时抖动，
	// 一次失败就放弃会让开机变得很脆。
	var lastErr error
	for i := range loadAttempts {
		if i > 0 {
			select {
			case <-time.After(time.Duration(1<<i) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if lastErr = c.refresh(ctx); lastErr == nil {
			log.Printf("attestation: collateral 就绪，fmspc=%s", fmspc)
			return c, nil
		}
		log.Printf("attestation: 拉 collateral 失败（第 %d/%d 次）: %v", i+1, loadAttempts, lastErr)
	}
	return nil, fmt.Errorf("attestation: collateral 首次拉取失败: %w", lastErr)
}

// Start 起后台刷新，ctx 取消时退出。
func (c *Collateral) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(refreshInterval)
		defer t.Stop()
		for {
			select { // select 而非 switch。select 会同时监听所有阻塞
			case <-ctx.Done():
				return
			case <-t.C:
				// 刷新失败保留旧值。材料本身带 Intel 签名的 nextUpdate，
				// 真过期了客户端自己看得出来，不需要我们代为判断。
				if err := c.refresh(ctx); err != nil {
					log.Printf("attestation: 刷新 collateral 失败，保留旧值: %v", err)
				}
			}
		}
	}()
}

// Snapshot 返回当前 bundle。refresh 每次整体替换切片、不原地改，
// 所以返回结构体副本、调用方只读是安全的。
func (c *Collateral) Snapshot() Bundle {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bundle
}

// refresh 拉一整套材料，四份全成功才整体换上，避免出现半新半旧的 bundle。
func (c *Collateral) refresh(ctx context.Context) error {
	var (
		b   Bundle
		err error
	)
	if b.TCBInfo, err = c.get(ctx, pcs.TcbInfoURL(c.fmspc), "TCB-Info-Issuer-Chain"); err != nil {
		return err
	}
	if b.QEIdentity, err = c.get(ctx, pcs.QeIdentityURL(), "SGX-Enclave-Identity-Issuer-Chain"); err != nil {
		return err
	}
	if b.PCKCRL, err = c.get(ctx, pcs.PckCrlURL(pckCA), "SGX-PCK-CRL-Issuer-Chain"); err != nil {
		return err
	}
	if b.RootCACRL, err = c.get(ctx, rootCACRLURL, ""); err != nil {
		return err
	}

	c.mu.Lock()
	c.bundle = b
	c.mu.Unlock()
	return nil
}

func (c *Collateral) get(ctx context.Context, u, chainHeader string) (Item, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Item{}, fmt.Errorf("attestation: 构造请求 %s: %w", u, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Item{}, fmt.Errorf("attestation: 请求 %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Item{}, fmt.Errorf("attestation: %s 返回 %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Item{}, fmt.Errorf("attestation: 读 %s 响应体: %w", u, err)
	}

	item := Item{Body: body}
	if chainHeader != "" {
		raw := resp.Header.Get(chainHeader)
		if raw == "" {
			return Item{}, fmt.Errorf("attestation: %s 缺 %s header", u, chainHeader)
		}
		chain, err := url.QueryUnescape(raw)
		if err != nil {
			return Item{}, fmt.Errorf("attestation: 解码 %s: %w", chainHeader, err)
		}
		item.IssuerChain = chain
	}
	return item, nil
}

// extractFMSPC 从 quote 尾部内嵌的证书链里解出 FMSPC。
// 链的顺序是 PCK Cert → PCK Platform CA → Intel SGX Root CA，
// 第一张就是带 SGX 扩展的叶子证书。
//
// 用 pcs 包而不是自己解 OID，是为了让 TD 侧算出的 FMSPC 字符串
// 跟客户端验证库算出的完全一致——该库用 hex.EncodeToString，出来是小写，
// TD 侧要是拼成大写，客户端按 URL 分派 bundle 时会静默 miss。
func extractFMSPC(quote []byte) (string, error) {
	i := bytes.Index(quote, []byte("-----BEGIN CERTIFICATE-----"))
	if i < 0 {
		return "", errors.New("attestation: quote 里找不到内嵌证书链")
	}
	block, _ := pem.Decode(quote[i:])
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("attestation: quote 内嵌证书链 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("attestation: 解析 PCK 证书: %w", err)
	}
	ext, err := pcs.PckCertificateExtensions(cert)
	if err != nil {
		return "", fmt.Errorf("attestation: 解析 PCK 证书的 SGX 扩展: %w", err)
	}
	if ext.FMSPC == "" {
		return "", errors.New("attestation: PCK 证书里没有 FMSPC")
	}
	return ext.FMSPC, nil
}
