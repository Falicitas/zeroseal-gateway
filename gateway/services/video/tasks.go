// Package video 管视频任务的生命周期：落库、按轮询结果结算、以及客户提交完
// 就不回来时的兜底。
//
// 前三个 surface 的一次调用就是一个 HTTP 请求，预扣和结算在同一个 handler 里
// 走完。视频不是：提交只拿到一个任务 ID，结果几分钟后才有，而客户完全可能再也
// 不来取。那笔预扣要是没人收尾，用户的余额就被永久占住了。
package video

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 任务不存在，或者不属于这个用户 —— 两者故意不区分。
var ErrNotFound = errors.New("video task not found")

// Task 是一个在途的视频任务。
type Task struct {
	UpstreamID string
	UserID     string
	Model      string
	Provider   string
	RecordID   string
	Status     string

	// Tier 是计费档位，提交时定下来。视频的单价看请求带没带视频输入，
	// 而轮询响应里没有这个信息 —— 不存就结算不了。
	Tier string

	// CreatedAt 既是提交时刻也是计价时刻：预扣按它落档，结算必须按同一个值，
	// 否则跨过分时边界的任务两头会用不同单价。
	CreatedAt time.Time

	// Settled 为 true 表示计费已收尾，别再动账。
	Settled bool
}

// Create 落库。调用方必须在拿到上游任务 ID 之后、返回给客户之前调它 ——
// 存不下就等于这个任务再也结算不了，那时应当退款。
// 上游返回前可能已经完成认领，因此从计费记录读取当前账户，并持锁到任务落库。
// 认领事务须先锁计费记录再迁移已有任务，保证晚到的任务不会留在影子账户。
func Create(ctx context.Context, pool *pgxpool.Pool, t Task) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx,
		`SELECT user_id FROM billing_records WHERE id=$1 FOR UPDATE`, t.RecordID,
	).Scan(&t.UserID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO video_tasks (upstream_id, user_id, model, provider, record_id, status, tier)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.UpstreamID, t.UserID, t.Model, t.Provider, t.RecordID, t.Status, t.Tier,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Get 按任务 ID 取，用 key 当前所属账户校验归属。
// key 与任务在同一条查询中读取，避免混用认领前后的归属。
// 归属不匹配统一返回 ErrNotFound，避免泄露别人的任务是否存在。
func Get(ctx context.Context, pool *pgxpool.Pool, upstreamID, keyID string) (Task, error) {
	t := Task{UpstreamID: upstreamID}
	var settledAt *time.Time
	err := pool.QueryRow(ctx,
		`SELECT v.user_id, v.model, v.provider, v.record_id, v.status, v.tier, v.created_at, v.settled_at
		 FROM video_tasks v
		 JOIN api_keys k ON k.user_id = v.user_id
		 JOIN users u ON u.id = v.user_id
		 WHERE v.upstream_id = $1 AND k.id = $2 AND u.deleted_at IS NULL`,
		upstreamID, keyID,
	).Scan(&t.UserID, &t.Model, &t.Provider, &t.RecordID, &t.Status, &t.Tier, &t.CreatedAt, &settledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Task{}, ErrNotFound
	}
	if err != nil {
		return Task{}, err
	}
	t.Settled = settledAt != nil
	return t, nil
}

// MarkSettled 记下终态。只动还没结算的行，重复调用空转 —— 客户轮询和 worker
// 可能同时到达同一个任务。
func MarkSettled(ctx context.Context, pool *pgxpool.Pool, upstreamID, status string) error {
	_, err := pool.Exec(ctx,
		`UPDATE video_tasks SET status = $1, settled_at = now()
		 WHERE upstream_id = $2 AND settled_at IS NULL`,
		status, upstreamID,
	)
	return err
}

// Unsettled 取一批还没结算、且已经放了一会儿的任务，给 worker 兜底用。
//
// 刚提交的不扫：那会儿客户多半自己在轮询，两边一起打上游没有意义。
// idle 就是这个「放了一会儿」的门槛。
func Unsettled(ctx context.Context, pool *pgxpool.Pool, idle time.Duration, limit int) ([]Task, error) {
	rows, err := pool.Query(ctx,
		`SELECT upstream_id, user_id, model, provider, record_id, status, tier, created_at
		 FROM video_tasks
		 WHERE settled_at IS NULL AND created_at < now() - make_interval(secs => $1)
		 ORDER BY created_at
		 LIMIT $2`,
		idle.Seconds(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.UpstreamID, &t.UserID, &t.Model, &t.Provider,
			&t.RecordID, &t.Status, &t.Tier, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
