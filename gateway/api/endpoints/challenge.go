package endpoints

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	// nonceTTL 是一个挑战的有效期。
	nonceTTL = 60 * time.Second
	// maxNonces 是同时在途的挑战上限。issue 必须不带认证（带了就是鸡生蛋），
	// 所以这张表是外部可写的——满了拒发新挑战，而不是无限涨。
	maxNonces = 10000
	// nonceLen 是挑战的字节数。
	nonceLen = 32
)

var errTooManyNonces = errors.New("在途挑战已达上限")

// nonceStore 是在途挑战的集合。
type nonceStore struct {
	mu sync.Mutex
	m  map[string]time.Time // nonce -> 过期时刻
}

func newNonceStore() *nonceStore {
	return &nonceStore{m: make(map[string]time.Time)}
}

// issue 发一个新挑战。
func (s *nonceStore) issue() (string, error) {
	b := make([]byte, nonceLen)
	rand.Read(b) // Go 1.24 起 crypto/rand.Read 保证不返错、且必定填满
	n := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()

	// sweep 是 O(n)，只在挤满时才值得跑：正常情况下表里没几项，扫也扫不出东西，
	// 而真被刷的时候每个请求都遍历一万项还捏着锁。
	// 过期项留在表里没有危害，consume 本来就查过期。
	if len(s.m) >= maxNonces {
		s.sweep()
		if len(s.m) >= maxNonces {
			return "", errTooManyNonces
		}
	}
	s.m[n] = time.Now().Add(nonceTTL)
	return n, nil
}

// consume 取出即删：同一个挑战第二次一定失败，重放窗口是零。
// 也因此每个挑战只允许一次签名尝试。
func (s *nonceStore) consume(n string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.m[n]
	if !ok {
		return false
	}
	delete(s.m, n)
	return time.Now().Before(exp)
}

// sweep 清掉已过期的项。调用方已持锁。
func (s *nonceStore) sweep() {
	now := time.Now()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
}
