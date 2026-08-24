package secret

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/zeroseal/gateway/services/attestation"
)

// defaultInjectAddr 是注入监听的默认地址。非标端口，靠安全组只放行管理员 IP。
const defaultInjectAddr = ":9443"

// Secrets 是启动时一次性备齐的全部机密。
type Secrets struct {
	// ProviderKeys 按 provider name 索引它的 upstream key。
	// KMS 注入时一并提供 provider 和对应 key，dev 期从 env 读。
	ProviderKeys map[string]string
	DBDSN        string

	// TLSCert 是 gw.zeroseal.cn 的证书链和私钥，来自注入的内存数据，
	// 全程不落文件系统。为 nil 时 main 起明文 HTTP，
	// 此时 attestation 端点也拿不到 EKM、一律返 503。
	//
	// 私钥不能落在只读的 erofs rootfs 上，路径要指向内存文件系统。
	// TD 上 /tmp 属于只读根，能写的是 /run（tmpfs），
	// systemd unit 里给个 RuntimeDirectory= 就会在 /run 下建目录。
	TLSCert *tls.Certificate

	// Attestation 是 Intel collateral 的缓存。本机不是 TDX 环境时为 nil。
	// 严格说它不是机密（材料全是 Intel 公开签名的），放这里是因为
	// 它和机密共享同一条「启动时一次性备齐、缺了就不启动」的语义。
	Attestation *attestation.Collateral
}

// Load 备齐启动前置。任何一项该有而没有的，直接返错让 main 退出。
//
// 两条路径：dev 模式从 env 读、不起 TLS，用于本机开发；
// 否则起注入监听阻塞等一次人工注入。判据是 ZEROSEAL_DEV_MODE，
// 跟 attestation 的判据（configfs 在不在）是两件独立的事——
// TD 上跑 prod 路径拿机密，同时 attestation 因为有 configfs 而启用。
func Load(ctx context.Context) (*Secrets, error) {
	// collateral 只需要 configfs 和网络，不需要任何机密，所以排在注入之前。
	// 排在后面的话，Intel 或 DNS 一出问题就 Fatal，会连带把已经注入的机密弄丢——
	// 重启后临时密钥就换了，只能从头再注入一次。早失败的代价是零。
	col, err := loadAttestation(ctx)
	if err != nil {
		return nil, err
	}

	var s *Secrets
	if os.Getenv("ZEROSEAL_DEV_MODE") == "1" {
		s, err = loadFromEnv()
	} else {
		s, err = loadFromInjection(ctx)
	}
	if err != nil {
		return nil, err
	}
	s.Attestation = col
	return s, nil
}

// upstreamKeyPrefix 是 dev 模式下上游 key 的环境变量前缀，后面接大写的
// provider 名：ZEROSEAL_KEY_DEEPSEEK、ZEROSEAL_KEY_VOLC。
const upstreamKeyPrefix = "ZEROSEAL_KEY_"

// loadFromEnv 是本机开发路径：不注入、不起 TLS。
// 没有 TLS 就没有 EKM，attestation 端点会返 503，这跟 Mac 上没有 configfs
// 的结果一致，不需要额外分支。
func loadFromEnv() (*Secrets, error) {
	keys := providerKeysFromEnv()
	if len(keys) == 0 {
		return nil, errors.New("secret: 没有上游 key，至少设一个 " + upstreamKeyPrefix + "<PROVIDER>")
	}
	dsn := os.Getenv("ZEROSEAL_DB_DSN")
	if dsn == "" {
		return nil, errors.New("secret: ZEROSEAL_DB_DSN 未设置")
	}

	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	sort.Strings(names)
	log.Printf("secret: dev 模式，从 env 读机密，不启用 TLS；已配上游 %v", names)

	return &Secrets{ProviderKeys: keys, DBDSN: dsn}, nil
}

// providerKeysFromEnv 扫 ZEROSEAL_KEY_<PROVIDER> 形式的环境变量，
// provider 名转小写以对齐 catalog 里的 Provider.Name。
//
// 顺带认一个老变量 ZEROSEAL_UPSTREAM_KEY：多 provider 之前上游只有 deepseek，
// 留着免得把已有的本地开发脚本弄坏。前缀形式优先级更高。
func providerKeysFromEnv() map[string]string {
	keys := map[string]string{}
	if k := os.Getenv("ZEROSEAL_UPSTREAM_KEY"); k != "" {
		keys["deepseek"] = k
	}
	for _, kv := range os.Environ() {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || value == "" {
			continue
		}
		provider, ok := strings.CutPrefix(name, upstreamKeyPrefix)
		if !ok || provider == "" {
			continue
		}
		keys[strings.ToLower(provider)] = value
	}
	return keys
}

// loadFromInjection 起注入监听并阻塞，拿到机密后组装成 Secrets。
func loadFromInjection(ctx context.Context) (*Secrets, error) {
	addr := os.Getenv("ZEROSEAL_INJECT_ADDR")
	if addr == "" {
		addr = defaultInjectAddr
	}

	p, err := awaitInjection(ctx, addr)
	if err != nil {
		return nil, err
	}

	// validate 里已经解过一次确认能配上，这里不会失败。
	cert, err := tls.X509KeyPair([]byte(p.TLSCertPEM), []byte(p.TLSKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("secret: 解析注入的证书: %w", err)
	}

	return &Secrets{
		ProviderKeys: p.ProviderKeys,
		DBDSN:        p.DBDSN,
		TLSCert:      &cert,
	}, nil
}

// loadAttestation 在 TDX 环境下同步解 FMSPC 并拉第一份 collateral，
// 拉不到就 fail-fast。非 TDX 环境不是错误，降级成「不启用 attestation」。
//
// 判据是 configfs TSM 在不在，而不是 ZEROSEAL_DEV_MODE。用环境本身做判据，
// Mac 上和 TD 上跑的就是同一条代码路径。
func loadAttestation(ctx context.Context) (*attestation.Collateral, error) {
	col, err := attestation.NewCollateral(ctx)
	switch {
	case err == nil:
		return col, nil
	case errors.Is(err, attestation.ErrTSMUnavailable):
		log.Print("secret: 本机不是 TDX 环境，attestation 端点将返 503")
		return nil, nil
	default:
		return nil, fmt.Errorf("secret: 初始化 attestation: %w", err)
	}
}
