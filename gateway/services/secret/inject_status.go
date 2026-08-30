package secret

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InjectState 是 /inject/status 报的启动阶段。
//
// 只有两个值，因为 9443 的存活区间就这么长：临时密钥和 quote 备好之后开，
// 注入成功就关。关了之后 gateway 去连 DB、起 443，那一段没有端口可问 ——
// 那时能看的只有阿里云控制台的串口输出（cmdline 里有 console=ttyS0）。
type InjectState string

const (
	StateFetchingCollateral InjectState = "fetching_collateral"
	StateAwaitingInjection  InjectState = "awaiting_injection"
)

// InjectErrCode 是上一次注入尝试被拒的原因，机器可读。
//
// 用枚举而不是 err.Error() 的原文：/inject/status 不带认证（可达性只靠安全组），
// 而错误原文里会带 tls.X509KeyPair 的解析细节这类内部信息。
// 回给注入方的 HTTP 响应仍然是带原因的中文 —— 那条路径是点对点的，不受这条约束。
type InjectErrCode string

const (
	// ErrCodeUnknown 是兜底：状态字段宁可报「不认识」，也不能把 err.Error() 吐出去。
	ErrCodeUnknown InjectErrCode = "unknown"

	ErrCodeEnvelopeMalformed InjectErrCode = "envelope_malformed"
	ErrCodeSigInvalid        InjectErrCode = "sig_invalid"
	ErrCodeDecryptFailed     InjectErrCode = "decrypt_failed"
	ErrCodePayloadMalformed  InjectErrCode = "payload_malformed"

	ErrCodeProviderKeysEmpty   InjectErrCode = "provider_keys_empty"
	ErrCodeProviderKeysInvalid InjectErrCode = "provider_keys_invalid"
	ErrCodeDBDSNEmpty          InjectErrCode = "db_dsn_empty"
	ErrCodeTLSPairIncomplete   InjectErrCode = "tls_pair_incomplete"
	ErrCodeCertKeyMismatch     InjectErrCode = "cert_key_mismatch"

	ErrCodeAlreadyInjected InjectErrCode = "already_injected"

	// ErrCodeNotReady 是 Collateral 还没拉完就来注入。
	//
	// 监听提前到拉 collateral 之前，是为了让 /inject/status 在那段时间能答话；
	// 但注入不能跟着提前 —— 这时候收下机密，紧接着 collateral 拉失败就是 Fatal，
	// 机密随进程一起没掉，而重启后 TD 临时密钥已经换了，只能从头再注一次。
	// 所以这一段只答话、不收东西。
	ErrCodeNotReady InjectErrCode = "not_ready"
)

// injectCodedError 是带机器可读码的错误。
// 码进 /inject/status，消息回给注入方 —— 前者要稳定可枚举，后者要人能读懂。
type injectCodedError struct {
	code InjectErrCode // 🤔：给 inject/status，因为这个端口没有鉴权，不适合放出具体 msg
	msg  string        // 给 inject，但只有 validate 有具体 Err 错误。见 serveInject
	err  error         // 可选的底层原因，只进消息不进码
}

func (e *injectCodedError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}
	return e.msg
}

func (e *injectCodedError) Unwrap() error { return e.err }

func codeOf(err error) InjectErrCode {
	var ce *injectCodedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return ErrCodeUnknown
}

// processStartedAt 是本进程的启动时刻。
var processStartedAt = time.Now()

// bootedAt 从 /proc/uptime 反推开机时刻，只算一次。
// 非 Linux 上读不到（Mac 本地开发），返零值，响应里那个字段会被略掉。
var bootedAt = sync.OnceValue(func() time.Time {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	sec, err := strconv.ParseFloat(first, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(sec * float64(time.Second)))
})

// statusResponse 是 GET /inject/status 的响应体，字段就是白名单的全部。
//
// StartedAt 和 BootedAt 配着看：差得远说明 gateway 进程重启过。注入成功之后
// 崩溃的话 systemd 会把它拉起来（Restart=on-failure），新进程重新回到
// awaiting_injection —— 从外面看跟「还没注入」一模一样，而新进程不知道
// 上一个为什么死。这两个字段只能告诉你「重启发生了」，告诉不了「为什么」，
// 那是明知的缺口，补它要么持久化死因、要么让进程别退出，两条都另说。
type statusResponse struct {
	State     InjectState   `json:"state"`
	LastError InjectErrCode `json:"last_error,omitempty"`
	StartedAt time.Time     `json:"started_at"`
	BootedAt  time.Time     `json:"booted_at,omitzero"`
}

// injectStatus 是状态的持有者。serveInject 写、serveStatus 读，两边并发。
type injectStatus struct {
	mu      sync.Mutex
	state   InjectState
	lastErr InjectErrCode
}

func newInjectStatus() *injectStatus {
	return &injectStatus{state: StateFetchingCollateral}
}

func (s *injectStatus) set(st InjectState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
}

// ready 报 collateral 是否已经就绪，也就是能不能收注入了。
func (s *injectStatus) ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == StateAwaitingInjection
}

func (s *injectStatus) fail(code InjectErrCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = code
}

func (s *injectStatus) snapshot() statusResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return statusResponse{
		State:     s.state,
		LastError: s.lastErr,
		StartedAt: processStartedAt,
		BootedAt:  bootedAt(),
	}
}

// serveStatus 不带认证：只出枚举和两个时间戳，没有任何机密，
// 可达性靠安全组只放行管理员 IP。zsdeploy 拿它做探活 ——
// 有了它，「9443 连不上」和「9443 开着但注入被拒」才分得开。
func (i *injector) serveStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(i.status.snapshot())
}
