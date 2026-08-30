package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"time"
)

// selfExe 是本进程二进制在 Linux 上的路径。
const selfExe = "/proc/self/exe"

// serving443Since 是 443 开始监听的时刻，由 main 在起监听的 goroutine 之前打点。
// 先写后读，不需要同步。（dev 模式下监听的其实是 8080，见 GATEWAY_ADDR。）
//
// 🤔：利用 serving443Since 和 DumpedAt 相减，可以做 err 在这期间的出现速率
var serving443Since time.Time

// MarkServing 记下 443 开始服务的时刻。必须在起监听的 goroutine 之前调用。
func MarkServing() { serving443Since = time.Now() }

// binarySHA 算本进程二进制自己的 sha256，只算一次。
//
// 这个字段没有安全价值：它是自报的，被换掉的二进制想报什么就报什么。
// 真正证明「跑的是哪个二进制」的是 /v1/attestation 那条链——
// quote → RTMR2 → dm-verity roothash → rootfs 上的这个文件。
//
// 留着它只为抓操作失误：部错版本、回滚了没察觉、别人动过。摘掉 sshd 之后
// 没有别的一次调用能回答「现在跑的是哪个 build」——走 attestation 拿到的是
// roothash，还得查 measurements.jsonl 才落到 gateway 版本上。
// 用 sha 而不是 -ldflags 打版本号，是不想动已经验过的可复现构建参数。
//
// 非 Linux 上读不到 /proc/self/exe（比如 Mac 本地开发），返空串。
var binarySHA = sync.OnceValue(func() string {
	f, err := os.Open(selfExe)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
})

// Dump 是诊断端点吐出去的全部内容。
//
// 这个结构体就是白名单的出口：能离开 TD 的每一个字段都在这里，
// 而这份代码在 dm-verity rootfs 上、roothash 经 cmdline 进 RTMR2。
// 审我们镜像的人读这一个结构体就能确认「只出错误码、不出对话历史」。
// 加字段要重出镜像、改度量值——这是有意的。
type Dump struct {
	BinarySHA256    string    `json:"binary_sha256"`
	Serving443Since time.Time `json:"serving_443_since"`
	DumpedAt        time.Time `json:"dumped_at"`
	Counters        []Counter `json:"counters"`
	Events          []Event   `json:"events"`
}

// NewDump 把记录全倒出来：ring 全量 + 计数器全量 + 进程身份。
func NewDump() Dump {
	events, counters := Snapshot()
	return Dump{
		BinarySHA256:    binarySHA(),
		Serving443Since: serving443Since,
		DumpedAt:        time.Now(),
		Counters:        counters,
		Events:          events,
	}
}
