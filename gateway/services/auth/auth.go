package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUnauthorized 表示 key 无效或对应用户已软删。
// 不区分「key 不存在」和「用户已删」，避免向调用方泄露原因。
var ErrUnauthorized = errors.New("unauthorized")

// Account 是鉴权时的账户快照。U 盘认领后 KeyID 不变，
// UserID 和 Balance 可能变化，不能作为后续扣费时的最新状态。
type Account struct {
	KeyID   string
	UserID  string
	Balance int64
}

// Authenticate 收明文 key，算 sha256 查库，返回账户或 ErrUnauthorized。
func Authenticate(ctx context.Context, pool *pgxpool.Pool, plainKey string) (Account, error) {
	if plainKey == "" {
		return Account{}, ErrUnauthorized
	}
	sum := sha256.Sum256([]byte(plainKey))
	keyHash := hex.EncodeToString(sum[:])
	const q = `
		SELECT k.id, u.id, u.balance
		FROM api_keys k
		JOIN users u ON u.id = k.user_id
		WHERE k.key_hash = $1 AND u.deleted_at IS NULL`

	var acc Account
	err := pool.QueryRow(ctx, q, keyHash).Scan(&acc.KeyID, &acc.UserID, &acc.Balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrUnauthorized
	}
	if err != nil {
		return Account{}, err
	}
	return acc, nil
}
