// Package diag 收集运行时错误，供管理员通过 443 上的只读端点取回。
//
// 存在的理由是摘掉镜像里的 sshd：今天 gateway 出问题只能 ssh 进去看 journal，
// 而 TD 里留着 sshd 就等于 root 能读 /proc/<pid>/mem 掏走注入的机密，
// 「TD 内读不出密钥」这条对运营方就不成立。
//
// 关键性质：能吐出去什么由这个包穷举，而这个包编译进的二进制在 dm-verity
// rootfs 上、roothash 经内核 cmdline 进 RTMR2。所以「只出错误码、不出对话历史」
// 是可审计的事实，不是一句承诺。这比留着 sshd 严格得多——root 进去是想读什么读什么。
package diag

import (
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

// Kind 标记事件来自哪个采集点。单独一个字段而不靠 Status 反推：
// panic 没有状态码，上游返的 502 和我们自己返的 502 也是两回事。
type Kind uint8

const (
	KindHTTP5xx  Kind = iota // 我们返给客户端的 5xx
	KindHTTP4xx              // 我们返给客户端的 4xx，只计数不进 ring
	KindUpstream             // 上游非 2xx，或连不上上游
	KindPanic                // handler 里的 panic
	KindBilling              // 计费收尾失败
)

var kindNames = [...]string{"http5xx", "http4xx", "upstream", "panic", "billing"}

func (k Kind) String() string {
	if int(k) >= len(kindNames) {
		return "unknown"
	}
	return kindNames[k]
}

// MarshalJSON 让输出里出 "upstream" 而不是 2。这份 JSON 是给人读的，
// 出数字等于逼着读的人回来查代码。
func (k Kind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON 认 MarshalJSON 出的那些名字。加它是为了让客户端
// （cmd/zsinject 的 diag 子命令）能直接把响应反序列化成 Dump，
// 而不是再抄一份平行的结构体——抄了就会有一天两边对不上。
func (k *Kind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for i, n := range kindNames {
		if n == s {
			*k = Kind(i)
			return nil
		}
	}
	return fmt.Errorf("diag: 未知的 kind %q", s)
}

const (
	// detailMax 是 Detail 的字节上限。够装一条 pgx 错误或一次 DNS 失败，
	// 又不至于让单条事件把 ring 的内存吃掉。
	detailMax = 512
	// panicDetailMax 单独放宽：栈的前几帧才是有用的部分，512 字节装不下。
	panicDetailMax = 2048
)

// Event 是 ring 和计数器共用的事件结构。这五个字段就是白名单的全部内容——
// 不存请求体、不存 prompt、不存上游响应体、不存 provider key、
// 不存任何用户标识。要加字段就得改这里，也就得重出镜像、改度量值。
type Event struct {
	At     time.Time `json:"at"`
	Kind   Kind      `json:"kind"`
	Status int       `json:"status"` // upstream 记上游返的码；panic 记 0
	Where  string    `json:"where"`  // 路由模板或上游 host，都不含请求参数
	Detail string    `json:"detail"`
}

// NewEvent 是构造 Event 的唯一入口。截断放在这里而不是读的时候做——
// 存进去多大就占多久，ring 里躺着 1024 条超长 Detail 是实打实的内存。
//
// Where 由调用方保证是路由模板（echo 的 c.Path()）或上游 host，
// 不能传 c.Request().URL.Path：后者带着真实的任务 ID。
func NewEvent(kind Kind, status int, where, detail string) Event {
	max := detailMax
	if kind == KindPanic {
		max = panicDetailMax
	}
	return Event{
		At:     time.Now(),
		Kind:   kind,
		Status: status,
		Where:  where,
		Detail: truncate(detail, max),
	}
}

// truncate 按 UTF-8 边界截断。按字节硬切会切出半个汉字，而这里的消息大多是中文，
// 切坏之后 JSON 编码出来是替换字符，读的人会以为整条记录都乱了。
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "…"
}
