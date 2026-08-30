package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zeroseal/gateway/services/attestation"
)

// nonceLen 是 AES-GCM 的标准 nonce 长度。
const nonceLen = 12

// Envelope 是上传到注入端点的报文。
type Envelope struct {
	SenderPub  []byte `json:"sender_pub"` // 发送方一次性 X25519 公钥，32 字节
	Nonce      []byte `json:"nonce"`      // 12 字节
	Ciphertext []byte `json:"ciphertext"` // AES-256-GCM 密文
	Sig        []byte `json:"sig"`        // Ed25519 签名，64 字节
}

// Payload 是信封里的 JSON 明文，也就是全部要注入的机密。
type Payload struct {
	ProviderKeys map[string]string `json:"provider_keys"`
	DBDSN        string            `json:"db_dsn"`
	TLSCertPEM   string            `json:"tls_cert_pem"`
	TLSKeyPEM    string            `json:"tls_key_pem"`
}

// sealInfo 把两边公钥绑进 HKDF 的 info，让派生出的密钥只对这一次交换有效。
// 少了这层，同一个 TD 临时公钥下抓到的密文可以被搬到另一次交换里。
func sealInfo(tdPub, senderPub []byte) string {
	return attestation.InjectDomain + "|" +
		hex.EncodeToString(tdPub) + "|" +
		hex.EncodeToString(senderPub)
}

// sigMessage 是 Ed25519 签的内容。覆盖 tdPub 是关键一环：
// TD 的临时密钥每次开机都换，所以抓到的注入包重放不到下一次开机。
func sigMessage(tdPub, senderPub, nonce, ct []byte) []byte {
	msg := make([]byte, 0, len(tdPub)+len(senderPub)+len(nonce)+len(ct))
	msg = append(msg, tdPub...)
	msg = append(msg, senderPub...)
	msg = append(msg, nonce...)
	msg = append(msg, ct...)
	return msg
}

func aeadFor(shared, tdPub, senderPub []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, nil, sealInfo(tdPub, senderPub), 32)
	if err != nil {
		return nil, fmt.Errorf("secret: HKDF 派生失败: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: AES 初始化失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: GCM 初始化失败: %w", err)
	}
	return aead, nil
}

// SealEnvelope 给注入工具用（cmd/zsinject）。
// 跟 OpenEnvelope 放同一个文件，是为了让两侧的绑定规则只有一份定义——
// HKDF 的 info、AAD、签名覆盖范围三处只要改一边漏一边，症状就是
// 「解密失败」这种查起来很费劲的错。
func SealEnvelope(plain, tdPub []byte, adminPriv ed25519.PrivateKey) (*Envelope, error) {
	if len(tdPub) != 32 {
		return nil, errors.New("secret: TD 临时公钥长度不对")
	}
	tdKey, err := ecdh.X25519().NewPublicKey(tdPub)
	if err != nil {
		return nil, fmt.Errorf("secret: TD 临时公钥无效: %w", err)
	}

	senderPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secret: 生成发送方临时密钥: %w", err)
	}
	senderPub := senderPriv.PublicKey().Bytes()

	shared, err := senderPriv.ECDH(tdKey)
	if err != nil {
		return nil, fmt.Errorf("secret: ECDH: %w", err)
	}
	aead, err := aeadFor(shared, tdPub, senderPub)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret: 生成 nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plain, tdPub)

	return &Envelope{
		SenderPub:  senderPub,
		Nonce:      nonce,
		Ciphertext: ct,
		Sig:        ed25519.Sign(adminPriv, sigMessage(tdPub, senderPub, nonce, ct)),
	}, nil
}

// 🤔：OpenEnvelope 对 inject 进来的信息进行验签、解密，返回明文载荷。
// 先验签再解密：签名不对的请求在做 ECDH 之前就拒掉，
// 注入端点对未授权方就只是个消耗一次 Ed25519 验证的空壳。
func OpenEnvelope(env *Envelope, tdPriv *ecdh.PrivateKey, adminPub ed25519.PublicKey) ([]byte, error) {
	tdPub := tdPriv.PublicKey().Bytes()

	if len(env.SenderPub) != 32 {
		return nil, &injectCodedError{code: ErrCodeEnvelopeMalformed, msg: "secret: sender_pub 长度不对"}
	}
	if len(env.Nonce) != nonceLen {
		return nil, &injectCodedError{code: ErrCodeEnvelopeMalformed, msg: "secret: nonce 长度不对"}
	}
	if len(env.Sig) != ed25519.SignatureSize {
		return nil, &injectCodedError{code: ErrCodeEnvelopeMalformed, msg: "secret: sig 长度不对"}
	}
	if len(env.Ciphertext) == 0 {
		return nil, &injectCodedError{code: ErrCodeEnvelopeMalformed, msg: "secret: ciphertext 为空"}
	}

	if !ed25519.Verify(adminPub, sigMessage(tdPub, env.SenderPub, env.Nonce, env.Ciphertext), env.Sig) {
		return nil, &injectCodedError{code: ErrCodeSigInvalid, msg: "secret: 签名校验失败"}
	}

	senderKey, err := ecdh.X25519().NewPublicKey(env.SenderPub)
	if err != nil {
		return nil, &injectCodedError{ErrCodeEnvelopeMalformed, "secret: sender_pub 无效", err}
	}
	shared, err := tdPriv.ECDH(senderKey)
	if err != nil {
		return nil, &injectCodedError{ErrCodeDecryptFailed, "secret: ECDH 失败", err}
	}
	aead, err := aeadFor(shared, tdPub, env.SenderPub)
	if err != nil {
		return nil, &injectCodedError{ErrCodeDecryptFailed, "secret: 派生 AEAD 失败", err}
	}
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, tdPub)
	if err != nil {
		return nil, &injectCodedError{ErrCodeDecryptFailed, "secret: 解密失败", err}
	}
	return plain, nil
}
