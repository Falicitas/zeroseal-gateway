package attestation

import (
	"crypto/sha256"
	"crypto/sha512"
)

// signPubLen 是 report_data 里预留给 receipt 签名公钥的长度。
// v1 恒为全零，等 receipt 签名密钥的来源定下来之后再填真值。
// 长度写死在这里而不是由调用方传，是为了让布局只有一个定义处。
const signPubLen = 32

// InjectDomain 是机密注入信道的域分离标签。
// secret 包的信封也用它做 HKDF info 前缀，所以定义放这里、那边引用，
// 避免两处各写一份字符串、改一处漏一处。
const InjectDomain = "ZS-INJECT-v1"

var injectDomainTag = sha256.Sum256([]byte(InjectDomain))

// ComposeReportData 拼出 /v1/attestation 那份 quote 的 report_data：
//
//	report_data = sha512( ekm(32) || sign_pub(32) )
//
// ekm 必须取自 TD 自己那条 TLS 连接的 ConnectionState，绝不能由请求方提供。
// 这一条是整个通道绑定成立的前提：一旦 attestation 端点接受外部传入的 ekm，
// 上游节点就能拿它与客户端那条会话的 ekm 来换 quote，冒充 TLS 终止在 TD 内。
//
// 同理，拼接顺序和偏移也不能改成「客户端传一个 blob，TD 检查里面含有 ekm」的形式，
// 那等于把同一个攻击放回来。
func ComposeReportData(ekm [32]byte) [64]byte {
	buf := make([]byte, 0, len(ekm)+signPubLen)
	buf = append(buf, ekm[:]...)
	buf = append(buf, make([]byte, signPubLen)...)
	return sha512.Sum512(buf)
}

// ComposeInjectReportData 拼出注入信道那份 quote 的 report_data：
//
//	report_data = sha512( sha256("ZS-INJECT-v1")(32) || eph_pub(32) )
//
// 跟上面那份的区分靠内容而不是长度（两者输入都是 64 字节）：要混淆得同时满足
// ekm == sha256("ZS-INJECT-v1") 且 eph_pub 全零，而 X25519 公钥不可能全零，
// ekm 也是 TLS 派生的、不受任何一方控制。
//
// ephPub 必须是 TD 自己生成的临时公钥，不接受上传方指定。否则注入端点就成了
// 「能签任意 report_data 的接口」，而「TD 内没有代签服务」正是 attestation
// 那条推理链的前提。
func ComposeInjectReportData(ephPub [32]byte) [64]byte {
	buf := make([]byte, 0, len(injectDomainTag)+len(ephPub))
	buf = append(buf, injectDomainTag[:]...)
	buf = append(buf, ephPub[:]...)
	return sha512.Sum512(buf)
}
