package video

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeroseal/gateway/services/billing"
	"github.com/zeroseal/gateway/services/llm"
	"github.com/zeroseal/shared/catalog"
)

// Finish 按一次轮询的结果给计费收尾。
//
// 客户轮询和 worker 兜底都走这里：两条路的结算规则必须是同一份代码，否则迟早
// 漂移成两套，而「哪条路先到」是随机的，漂移出来的 bug 也就随机复现。
//
// 幂等由 billing 那层的 status='held' 守卫保证：两边同时到达时先到的结算，
// 后到的空转。MarkSettled 同理只动 settled_at IS NULL 的行。
//
// state 是 TaskRunning 时什么都不做 —— 任务还在跑，下一轮再看。
func Finish(ctx context.Context, pool *pgxpool.Pool, p catalog.Provider, t Task,
	state llm.TaskState, usage catalog.Usage) {

	switch {
	case state == llm.TaskSucceeded && len(usage) > 0:
		// 计价时刻用提交时刻，跟预扣同一个值。分时定价的上游靠它落档，
		// 视频动辄跑几分钟，两头各取各的时刻必然跨档。
		actual, ok := billing.Settle(p, withTier(usage, t.Tier), t.CreatedAt)
		if !ok {
			_ = billing.Refund(ctx, pool, t.RecordID)
			_ = MarkSettled(ctx, pool, t.UpstreamID, "succeeded")
			log.Printf("video: settle 查不到档位单价，已退款 record=%s", t.RecordID)
			return
		}
		if err := billing.Finalize(ctx, pool, t.RecordID, actual); err != nil {
			// 结算失败不改任务状态，留给下一轮重试 —— 这条路是幂等的。
			log.Printf("video: finalize 失败 record=%s: %v", t.RecordID, err)
			return
		}
		_ = MarkSettled(ctx, pool, t.UpstreamID, "succeeded")

	case state == llm.TaskSucceeded:
		// 上游说成功却没给用量。不猜：预扣是按最坏情况估的，直接按预扣扣会
		// 明显多收；退款只亏一次上游成本，方向上不伤客户。
		_ = billing.Refund(ctx, pool, t.RecordID)
		_ = MarkSettled(ctx, pool, t.UpstreamID, "succeeded")
		log.Printf("video: 上游报成功但无用量，已退款 record=%s", t.RecordID)

	case state == llm.TaskFailed:
		// 用户不该为上游故障付费，跟其他三个 surface 一致。
		_ = billing.Refund(ctx, pool, t.RecordID)
		_ = MarkSettled(ctx, pool, t.UpstreamID, "failed")
	}
}

// withTier 给用量补上任务记下的档位，返回新切片，不改原值。
//
// 只补空档：adapter 自己定得出档的保持原样。两家的情况正好相反 ——
// MiniMax 的轮询响应里分辨率和图片数都有，ParseTask 自己就能定档，还可能一次
// 出两档（秒一档、张一档）；火山的响应里查不到「当初带没带视频输入」，只能用
// 提交时存下来的那个。无脑覆盖会把 MiniMax 的图片档也盖成秒档，一张图按一秒
// 的价收。
func withTier(u catalog.Usage, tier string) catalog.Usage {
	out := make(catalog.Usage, len(u))
	for i, tu := range u {
		if tu.Tier == catalog.TierDefault {
			tu.Tier = tier
		}
		out[i] = tu
	}
	return out
}
