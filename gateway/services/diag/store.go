package diag

import (
	"sort"
	"sync"
	"time"
)

// ringSize 是保留的最近事件条数。按实际 Detail 长度算约 120 KB。
//
// 正常运行下 5xx 一天只有几条，1024 覆盖几个月。上游挂掉时每个请求进一条，
// 几分钟就绕完一圈——但那一档不该靠 ring 扛：那时的条目内容全一样，
// 看第 3 条和看第 500 条得到的信息相同。真正会丢的是洪水之前那条不一样的错误，
// 由计数器的 First 保住，那个永不被覆盖。
const ringSize = 1024

// counterKey 三个字段都是有界集合：Kind 是枚举，Status 是 HTTP 状态码，
// Where 是 echo 路由表里的常量模板或 catalog 里的上游 host。
// 所以这张表的键数天然有上界，不需要淘汰策略，也刷不爆。
type counterKey struct {
	kind   Kind
	status int
	where  string
}

// Counter 是一类错误的汇总。
//
// First 只在这个键第一次出现时写入，之后不再覆盖：排查时最有价值的是最早那条，
// 它往往跟后面的洪水不是同一个错误（连不上 DB 之后紧跟着几千条上游超时），
// 而 FIFO ring 恰恰最先把它挤掉。
type Counter struct {
	Kind   Kind      `json:"kind"`
	Status int       `json:"status"`
	Where  string    `json:"where"`
	Count  int64     `json:"count"`
	First  Event     `json:"first"`
	LastAt time.Time `json:"last_at"`
}

// Store 是进程内的错误记录。全部状态都在内存，进程退出即消失。
//
// 不落盘是有意的：rootfs 是只读 erofs，唯一能写的是 tmpfs，
// 而写进 tmpfs 的东西会活过进程重启——那需要另一套关于「谁能读到它」的论证，
// 现在不值得。代价是崩溃重启会丢掉全部记录，这是已知缺口。
type Store struct {
	mu       sync.Mutex
	ring     []Event
	next     int  // 下一条写入的位置
	wrapped  bool // ring 是否已经绕过一圈
	counters map[counterKey]*Counter
}

func NewStore() *Store {
	return &Store{
		ring:     make([]Event, ringSize),
		counters: make(map[counterKey]*Counter),
	}
}

// Record 收一条事件。
//
// 4xx 只进计数器、不进 ring：443 公网可达，任何扫描器几秒钟就能用 401
// 把真正的 5xx 从窗口里挤出去。而 4xx 逐条也没有内容可看——白名单不许存
// 用户标识，一条 401 记下来没有主体，一百条和一条给的信息量一样。
// 计数器答的才是 4xx 该答的问题：401 有 3 次说明谁把 key 配错了，
// 有 30000 次说明有人在扫。
func (s *Store) Record(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.count(e)
	if e.Kind == KindHTTP4xx {
		return
	}

	s.ring[s.next] = e
	s.next++
	if s.next == len(s.ring) {
		s.next = 0
		s.wrapped = true
	}
}

// count 累加计数器。调用方已持锁。
func (s *Store) count(e Event) {
	k := counterKey{kind: e.Kind, status: e.Status, where: e.Where}
	c, ok := s.counters[k]
	if !ok {
		s.counters[k] = &Counter{
			Kind:   e.Kind,
			Status: e.Status,
			Where:  e.Where,
			Count:  1,
			First:  e,
			LastAt: e.At,
		}
		return
	}
	c.Count++
	c.LastAt = e.At
}

// Snapshot 返回一份拷贝，内部切片和 map 一概不外泄——读的一侧（诊断端点）
// 跟写的一侧（请求处理）并发，把内部结构交出去等于把锁的边界交出去。
// 跟 attestation.Collateral.Snapshot 是同一个理由。
//
// events 从旧到新，counters 按最近活跃降序，相同时刻用 Where 兜底。
// 两者顺序都确定，免得每次取回来的排列都不一样、两次读之间没法 diff。
func (s *Store) Snapshot() (events []Event, counters []Counter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	events = s.snapshotRing()

	counters = make([]Counter, 0, len(s.counters))
	for _, c := range s.counters {
		counters = append(counters, *c)
	}
	sort.Slice(counters, func(i, j int) bool {
		if !counters[i].LastAt.Equal(counters[j].LastAt) {
			return counters[i].LastAt.After(counters[j].LastAt)
		}
		return counters[i].Where < counters[j].Where
	})
	return events, counters
}

// snapshotRing 按时间顺序导出 ring。调用方已持锁。
// 没绕圈时有效区间是 [0, next)；绕过之后最旧的一条就在 next 上。
func (s *Store) snapshotRing() []Event {
	if !s.wrapped {
		out := make([]Event, s.next)
		copy(out, s.ring[:s.next])
		return out
	}
	out := make([]Event, 0, len(s.ring))
	out = append(out, s.ring[s.next:]...)
	out = append(out, s.ring[:s.next]...)
	return out
}
