package billing

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeroseal/shared/catalog"
)

// ErrInsufficient 余额不足，调用方返 402。
var ErrInsufficient = errors.New("insufficient balance")

// ErrUnauthorized 表示预扣前 key 已删除或所属账户已软删，调用方返 401。
var ErrUnauthorized = errors.New("unauthorized")

// EstimateHold 算预扣额（纳元）。
// 输入部分保守按未命中价，token 数用 min(runeCount×1.2, ctxLimit)；
// 输出部分按 maxToken × 输出价，maxToken 由调用方决定。
func EstimateHold(pr catalog.Pricing, ctxLimit, runeCount, maxToken int64) int64 {
	inputTokens := int64(float64(runeCount) * 1.2)
	if inputTokens > ctxLimit {
		inputTokens = ctxLimit
	}
	return inputTokens*pr.Input + maxToken*pr.Output
}

// Settle 按真实 usage 算实际花费（纳元）。
//
// TierUsage 的字段跟 Pricing 一一对应，所以四种 Surface 共用这一个公式 ——
// 量纲是 token 还是张、字符、秒，由 Model.Surface 决定，这里不关心。
//
// Usage 可能有多条（图层拆分那种一次请求跨多个像素档），逐条查自己档位的
// 单价再累加。任何一条查不到价就返回 ok=false：与其按错的单价扣，不如让
// 调用方退款，这样配置错误当场就暴露。
//
// at 是计价时刻，传请求发起时刻 —— 分时定价的 provider 靠它落档，预扣和
// 结算传同一个值才能保证两边同档。
func Settle(p catalog.Provider, u catalog.Usage, at time.Time) (int64, bool) {
	if len(u) == 0 {
		return 0, false
	}
	var total int64
	for _, t := range u {
		pr, ok := p.PriceOf(t.Tier, at)
		if !ok {
			return 0, false
		}
		total += t.InputHit*pr.InputHit + t.Input*pr.Input + t.Output*pr.Output
	}
	return total, true
}

// SettleFull 按预扣全额结算：actual = hold，退 0。
// 用于「上游流中断、拿不到真实 usage」——暂定全扣（不退）。
// 跟 Finalize 一样的防双花：只动 status='held' 的记录，已结算/退款过则幂等空转。
func SettleFull(ctx context.Context, pool *pgxpool.Pool, recordID string) error {
	tag, err := pool.Exec(ctx,
		`UPDATE billing_records
		 SET actual_amount = hold_amount, status = 'settled', settled_at = now()
		 WHERE id = $1 AND status = 'held'`,
		recordID,
	)
	if err != nil {
		return err
	}
	_ = tag // 命中 0 行=已被处理过，幂等，不算错误
	return nil
}

// Hold 预扣事务：锁 key 并读取当前归属 → 锁账户读余额 → 扣款并写 held 记录。
// key 锁持有到提交，认领迁移也锁同一行，避免鉴权后的账户变更导致扣错账户。
// 返回 recordID 供后续结算/退款定位。
func Hold(ctx context.Context, pool *pgxpool.Pool, keyID, model string, amount int64) (string, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) // 已 Commit 后 Rollback 是 no-op，安全兜底

	var userID string
	err = tx.QueryRow(ctx,
		`SELECT user_id FROM api_keys WHERE id=$1 FOR UPDATE`, keyID,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if err != nil {
		return "", err
	}

	var balance int64
	err = tx.QueryRow(ctx,
		`SELECT balance FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, userID,
	).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	if balance < amount {
		return "", ErrInsufficient
	}

	if _, err = tx.Exec(ctx,
		`UPDATE users SET balance = balance - $1, updated_at = now() WHERE id=$2`,
		amount, userID,
	); err != nil {
		return "", err
	}

	var recordID string
	if err = tx.QueryRow(ctx,
		`INSERT INTO billing_records (user_id, key_id, model, hold_amount, status)
		 VALUES ($1, $2, $3, $4, 'held') RETURNING id`,
		userID, keyID, model, amount,
	).Scan(&recordID); err != nil {
		return "", err
	}

	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return recordID, nil
}

// Finalize 结算事务：退回（预扣 - 实际），把记录标 settled。
// 若 actual > hold（几乎不会，除非估价过低），差额从余额再扣，
// 但不因此让余额转负也不拦——预扣已放行，这里只如实结算。
func Finalize(ctx context.Context, pool *pgxpool.Pool, recordID string, actual int64) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var userID string
	var hold int64
	err = tx.QueryRow(ctx,
		`SELECT user_id, hold_amount FROM billing_records
		 WHERE id=$1 AND status='held' FOR UPDATE`, recordID,
	).Scan(&userID, &hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // 已结算/退款过，幂等
	}
	if err != nil {
		return err
	}

	refund := hold - actual // 正=退回，负=补扣
	if _, err = tx.Exec(ctx,
		`UPDATE users SET balance = balance + $1, updated_at = now() WHERE id=$2`,
		refund, userID,
	); err != nil {
		return err
	}

	if _, err = tx.Exec(ctx,
		`UPDATE billing_records
		 SET actual_amount=$1, status='settled', settled_at=now()
		 WHERE id=$2`,
		actual, recordID,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// Refund 退款事务：请求失败时全额退预扣，记录标 refunded。
func Refund(ctx context.Context, pool *pgxpool.Pool, recordID string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var userID string
	var hold int64
	err = tx.QueryRow(ctx,
		`SELECT user_id, hold_amount FROM billing_records
		 WHERE id=$1 AND status='held' FOR UPDATE`, recordID,
	).Scan(&userID, &hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // 已被结算或退款过，幂等
	}
	if err != nil {
		return err
	}

	if _, err = tx.Exec(ctx,
		`UPDATE users SET balance = balance + $1, updated_at = now() WHERE id=$2`,
		hold, userID,
	); err != nil {
		return err
	}

	if _, err = tx.Exec(ctx,
		`UPDATE billing_records SET status='refunded', settled_at=now() WHERE id=$1`,
		recordID,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
