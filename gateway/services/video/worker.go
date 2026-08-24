package video

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeroseal/gateway/services/billing"
	"github.com/zeroseal/gateway/services/llm"
	"github.com/zeroseal/shared/catalog"
)

const (
	// sweepInterval 是扫描间隔。视频实测三分钟左右出结果，扫得再勤也没用。
	sweepInterval = time.Minute

	// idleBefore 是「客户多半不来了」的门槛：提交这么久还没结算，worker 才接手。
	// 设短了会和正在轮询的客户一起打上游，纯属浪费。
	idleBefore = 5 * time.Minute

	// taskExpiry 对齐上游的 execution_expires_after（实测 172800 秒 = 48 小时）。
	// 过了这个点上游那边任务就没了，再怎么轮询也拿不到用量。
	taskExpiry = 48 * time.Hour

	// sweepBatch 单轮最多处理多少个。每个都要打一次上游，别在一轮里堆太多。
	sweepBatch = 50

	// pollTimeout 单次查询任务状态的上限。查状态是个很轻的接口。
	pollTimeout = 30 * time.Second
)

// Worker 是视频任务的兜底结算。
//
// 为什么需要它：预扣发生在提交那一刻，结算要等任务跑完。客户正常轮询的话结算在
// 轮询那条路上就做了 —— 但客户完全可以提交完就再也不回来（脚本崩了、用户关了
// 页面、干脆只想要个任务 ID）。那笔预扣没人收尾就会一直挂着，用户的余额被永久
// 占住，而且他自己看不出为什么。
type Worker struct {
	pool *pgxpool.Pool
	keys map[string]string
}

func NewWorker(pool *pgxpool.Pool, providerKeys map[string]string) *Worker {
	return &Worker{pool: pool, keys: providerKeys}
}

// Start 起后台扫描，ctx 取消时退出。
func (w *Worker) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.sweep(ctx)
			}
		}
	}()
}

func (w *Worker) sweep(ctx context.Context) {
	tasks, err := Unsettled(ctx, w.pool, idleBefore, sweepBatch)
	if err != nil {
		log.Printf("video worker: 取待结算任务失败: %v", err)
		return
	}
	for _, t := range tasks {
		w.settleOne(ctx, t)
	}
}

func (w *Worker) settleOne(ctx context.Context, t Task) {
	// 超过上游保留期还没终态：用量再也拿不到了，只能收尾。退款而不是全扣 ——
	// 一个跑了两天还没结果的任务几乎肯定是上游那边废了，让用户付钱说不过去。
	if time.Since(t.CreatedAt) > taskExpiry {
		_ = billing.Refund(ctx, w.pool, t.RecordID)
		_ = MarkSettled(ctx, w.pool, t.UpstreamID, "expired")
		log.Printf("video worker: 任务 %s 超过保留期仍无终态，已退款", t.UpstreamID)
		return
	}

	m, ok := catalog.Lookup(t.Model)
	if !ok {
		// 模型从 catalog 里被摘掉了（改名、下线），但在途任务还挂着。
		// 查不到定价就结算不了，退款收尾，否则这条记录永远扫不掉。
		_ = billing.Refund(ctx, w.pool, t.RecordID)
		_ = MarkSettled(ctx, w.pool, t.UpstreamID, "expired")
		log.Printf("video worker: 任务 %s 的模型 %s 已不在 catalog，已退款", t.UpstreamID, t.Model)
		return
	}
	p, ok := m.ProviderByName(t.Provider)
	if !ok {
		_ = billing.Refund(ctx, w.pool, t.RecordID)
		_ = MarkSettled(ctx, w.pool, t.UpstreamID, "expired")
		log.Printf("video worker: 任务 %s 的上游 %s 已不在 catalog，已退款", t.UpstreamID, t.Provider)
		return
	}
	key, ok := w.keys[t.Provider]
	if !ok {
		// 凭据没注入，查不了。不动账，等下一轮 —— 这多半是配置问题，会被修好。
		log.Printf("video worker: provider %s 无可用凭据，跳过 %s", t.Provider, t.UpstreamID)
		return
	}
	a, ok := llm.VideoFor(t.Provider)
	if !ok {
		log.Printf("video worker: provider %s 未接入视频协议，跳过 %s", t.Provider, t.UpstreamID)
		return
	}

	pollCtx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()

	resp, err := llm.PollVideo(pollCtx, a, p, key, t.UpstreamID)
	if err != nil {
		// 网络问题，不动账，下一轮再来。
		log.Printf("video worker: 查询 %s 失败: %v", t.UpstreamID, err)
		return
	}
	if resp.Status < 200 || resp.Status >= 300 {
		log.Printf("video worker: 查询 %s 上游返回 %d", t.UpstreamID, resp.Status)
		return
	}

	state, usage, ok := a.ParseTask(resp.Body)
	if !ok {
		log.Printf("video worker: 解析 %s 的任务响应失败", t.UpstreamID)
		return
	}
	Finish(ctx, w.pool, p, t, state, usage)
}
