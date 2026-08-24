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
func Create(ctx context.Context, pool *pgxpool.Pool, t Task) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO video_tasks (upstream_id, user_id, model, provider, record_id, status, tier)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.UpstreamID, t.UserID, t.Model, t.Provider, t.RecordID, t.Status, t.Tier,
	)
	return err
}

// Get 按任务 ID 取，归属校验写在查询条件里而不是留给调用方 —— 这样不可能忘。
// user_id 对不上返回 ErrNotFound 而不是 403：不该让人靠状态码试探出别人的任务
// 存不存在。
func Get(ctx context.Context, pool *pgxpool.Pool, upstreamID, userID string) (Task, error) {
	t := Task{UpstreamID: upstreamID, UserID: userID}
	var settledAt *time.Time
	err := pool.QueryRow(ctx,
		`SELECT model, provider, record_id, status, tier, created_at, settled_at
		 FROM video_tasks WHERE upstream_id = $1 AND user_id = $2`,
		upstreamID, userID,
	).Scan(&t.Model, &t.Provider, &t.RecordID, &t.Status, &t.Tier, &t.CreatedAt, &settledAt)
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
