package attestation

import "crypto/sha256"

// DiagDomain 是 443 上诊断信道签名的域分离标签。
//
// 管理员那把 Ed25519 私钥同时服务两个协议：注入（secret.sigMessage 签的是
// tdPub||senderPub||nonce||ct，裸拼接、没有域标签）和诊断的挑战应答。
// 标签只加在诊断这一侧就够 —— 注入消息以 tdPub 打头，那是每次开机重新生成的
// X25519 公钥，要跟诊断消息混淆得让 tdPub == sha256("ZS-DIAG-v1")。
// 所以 secret.sigMessage 和已经验过的注入流程都不用动。
//
// 放在这里而不是 api/endpoints，是因为签和验分处两侧：gateway 在 endpoints
// 里验，zsinject 在命令行里签。定义只能有一份 —— 两份的话改一边漏一边，
// 症状是「签名校验失败」，查起来极费劲（同样的道理见 envelope.go 里
// sealInfo 的注释）。而 endpoints 拖着 echo 和 pgx，不该被命令行工具链进去。
//
// 命名跟 InjectDomain 对齐，那个在 reportdata.go。
const DiagDomain = "ZS-DIAG-v1"

var diagDomainTag = sha256.Sum256([]byte(DiagDomain))

// DiagSigMessage 拼诊断签名覆盖的内容：sha256(DiagDomain) || nonce。
func DiagSigMessage(nonce []byte) []byte {
	msg := make([]byte, 0, len(diagDomainTag)+len(nonce))
	msg = append(msg, diagDomainTag[:]...)
	msg = append(msg, nonce...)
	return msg
}
