package attestation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// tsmReportDir 是内核 configfs TSM 的挂载点，v6.7 引入。
	tsmReportDir = "/sys/kernel/config/tsm/report"

	// instPrefix 给我们建的 report 实例加个前缀，
	// 这样 CleanupStale 能只清自己的，不碰别的进程建的。
	instPrefix = "zs-"

	// wantProvider 是 TDX 下 provider 属性的取值。
	// 对上了才说明 outblob 是 Intel DCAP 格式的 quote 而不是别的机密计算平台的东西。
	wantProvider = "tdx_guest"
)

// ErrTSMUnavailable 表示本机没有 configfs TSM 接口，也就是不在 TDX 环境里
// （典型场景是本地开发机）。调用方靠它区分「环境不支持」和「取 quote 失败」：
// 前者在 dev 模式下是预期内的，后者在任何环境下都是故障。
var ErrTSMUnavailable = errors.New("attestation: configfs TSM 不可用，本机不是 TDX 环境")

// Quote 取一份 TDX quote。reportData 原样写进 inblob，读回的 outblob 就是 quote。
//
// 每次调用建一个独立的 report 实例。内核 ABI 文档给了两种避免并发争用的做法，
// 一种是读写 generation 计数自己核对，另一种是每个请求上下文建一个实例，
// 这里用后者——省掉一整套计数核对逻辑，代价只是一次 mkdir 和一次 rmdir。
func Quote(reportData [64]byte) ([]byte, error) {
	if _, err := os.Stat(tsmReportDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrTSMUnavailable
		}
		return nil, fmt.Errorf("attestation: 检查 %s 失败: %w", tsmReportDir, err)
	}

	dir, err := newInstance()
	if err != nil {
		return nil, err
	}
	defer os.Remove(dir)

	provider, err := os.ReadFile(filepath.Join(dir, "provider"))
	if err != nil {
		return nil, fmt.Errorf("attestation: 读 provider 失败: %w", err)
	}
	if got := strings.TrimSpace(string(provider)); got != wantProvider {
		return nil, fmt.Errorf("attestation: provider 是 %q，期望 %q", got, wantProvider)
	}

	// inblob 是只写属性，必须一次写完整 64 字节。
	if err := os.WriteFile(filepath.Join(dir, "inblob"), reportData[:], 0o600); err != nil {
		return nil, fmt.Errorf("attestation: 写 inblob 失败: %w", err)
	}

	// 读 outblob 才触发生成。这一步走 TDCALL 再经 vsock 找宿主机的 QGS，
	// 是几十到几百毫秒级的重操作，宿主机 QGS 不可用时也在这里报错。
	quote, err := os.ReadFile(filepath.Join(dir, "outblob"))
	if err != nil {
		return nil, fmt.Errorf("attestation: 读 outblob 失败: %w", err)
	}
	if len(quote) == 0 {
		return nil, errors.New("attestation: outblob 为空")
	}
	return quote, nil
}

// newInstance 建一个名字唯一的 report 实例目录，返回它的绝对路径。
func newInstance() (string, error) {
	for range 5 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("attestation: 生成实例名失败: %w", err)
		}
		dir := filepath.Join(tsmReportDir, instPrefix+hex.EncodeToString(b[:]))

		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("attestation: 建 report 实例失败: %w", err)
		}
		// 重名了就换个名字重试。64 位随机撞上属于异常，循环只是兜底。
	}
	return "", errors.New("attestation: 建 report 实例连续重名")
}

// CleanupStale 清掉上次进程留下的孤儿实例目录。
// Quote 里的 defer os.Remove 在进程被 SIGKILL 时不会执行，
// 那些目录会一直留在 configfs 里，重启也不会自己消失。
//
// 启动时调一次即可。非 TDX 环境直接返回 nil，方便 dev 模式无脑调用。
func CleanupStale() error {
	entries, err := os.ReadDir(tsmReportDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("attestation: 列 %s 失败: %w", tsmReportDir, err)
	}

	var errs []error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), instPrefix) {
			continue
		}
		if err := os.Remove(filepath.Join(tsmReportDir, e.Name())); err != nil {
			errs = append(errs, fmt.Errorf("清理 %s: %w", e.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("attestation: 清理孤儿实例: %w", errors.Join(errs...))
	}
	return nil
}
