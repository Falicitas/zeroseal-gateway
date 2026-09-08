// Command verify-quote 验证远端此刻跑的是不是那一版。
//
//	verify-quote -host gw.zeroseal.cn
//
// verify.sh 回答的是「这份声明可复现」，全程离线；verify-quote 回答的是
// 「远端此刻在跑它」，必须连上去。两件事性质不同，所以是两条命令 —— 想离线
// 审计的人不该被迫连生产，想快速查状态的人不该等一次完整 mkosi 构建。
//
// 期望值有两个来源，含义差别很大：
//
//	reproduced.json    verify.sh 在你自己机器上复现出来的值 —— 独立验证
//	measurements.jsonl zeroseal 自己的声明 —— 只在没有前者时降级使用
//
// 拿 measurements.jsonl 去比 quote，两边都是 zeroseal 的说法，证明不了什么。
// 所以没有 reproduced.json 时会明确降级并用不同的退出码。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeroseal/gateway/services/attestation"
	"github.com/zeroseal/gateway/services/attestation/qvl"
)

// declared 是 measurements.jsonl 里一行的子集 —— 只取比对要用的字段。
type declared struct {
	Version string   `json:"version"`
	MRTD    string   `json:"mrtd"`
	RTMRs   []string `json:"rtmrs"`
}

// reproduced 是 verify.sh [5/5] 落的那份。它只有 RTMR1/RTMR2，因为
// 也只有这两个是能从公开材料复现出来的。
type reproduced struct {
	Version      string `json:"version"`
	RTMR1        string `json:"rtmr1"`
	RTMR2        string `json:"rtmr2"`
	ReproducedAt string `json:"reproduced_at"`
}

func main() {
	var (
		host    = flag.String("host", "gw.zeroseal.cn", "TD 的对外地址")
		mPath   = flag.String("measurements", "measurements.jsonl", "声明值，一行一次发布")
		rPath   = flag.String("reproduced", "reproduced.json", "verify.sh 落的复现值")
		version = flag.String("version", "", "验哪一版，不给则取 measurements.jsonl 最后一行")
		allow   = flag.String("allow-tcb-status", "",
			"放行指定的平台 TCB 档位（目前只接受 OutOfDate）。不传则严格要求 UpToDate")
	)
	flag.Parse()

	degraded, err := run(*host, *mPath, *rPath, *version, *allow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-quote: %v\n", err)
		os.Exit(1)
	}
	// 退出码分三档，让 CI 能把「验过了」和「只比了声明值」区别对待。
	if degraded {
		os.Exit(2)
	}
}

func run(host, mPath, rPath, version, allowTcb string) (bool, error) {
	want, err := loadDeclared(mPath, version)
	if err != nil {
		return false, err
	}
	repro, err := loadReproduced(rPath, want.Version)
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	resp, ekm, err := fetchAttestation(ctx, host)
	if err != nil {
		return false, err
	}

	// 不用端点一并返回的 collateral 去验它自己 —— 那是让被验方提供自己的证据链。
	// qvl.Verify 走 GetCollateral=true，自己去 Intel PCS 拉。端点给的那份留给
	// 将来的离线场景（拿不到 PCS 时，验签后可作退路）。
	res, err := qvl.Verify(ctx, resp.Quote, allowTcb)
	if err != nil {
		return false, err
	}

	fmt.Printf("=== %s 的 quote ===\n", host)
	fmt.Printf("协议版本 %d   provider %s\n\n", resp.Version, resp.Provider)

	// 绑定校验放在度量值比对之前：度量值对不对，前提是这份 quote 确实属于你
	// 眼前这条连接。否则中间人转发一份真实 TD 的 quote，后面每一项都会打勾。
	if err := checkEKMBinding(ekm, res.ReportData); err != nil {
		return false, err
	}

	fmt.Println("=== 密码学证明 ===")
	fmt.Println("  Intel 签名链、吊销状态   ✓ 通过标准 QVL")
	fmt.Println("  TD debug 位              ✓ 未开启")
	fmt.Println("  这条连接的归属           ✓ report_data 绑定了本连接导出的 EKM")
	if allowTcb != "" {
		fmt.Printf("  平台 TCB 档位            ! 按 -allow-tcb-status=%s 放行（详见上方警告）\n", allowTcb)
	} else {
		fmt.Println("  平台 TCB 档位            ✓ UpToDate")
	}

	if err := reportChain(want, repro, res.Measurements); err != nil {
		return false, err
	}

	fmt.Println()
	if repro == nil {
		fmt.Printf("远端跑的东西与 %s 声明的值一致。\n", want.Version)
		fmt.Println("但没有独立复现 —— 上面的 RTMR1/RTMR2 来自 measurements.jsonl，")
		fmt.Println("那是 zeroseal 自己的说法。跑 verify.sh 生成 reproduced.json 才算验完。")
		return true, nil
	}
	fmt.Printf("远端此刻运行的启动链与 rootfs，与 %s 的可复现构建一致。\n", want.Version)
	fmt.Println("固件层（MRTD / RTMR0）按信任边界接受，见 README「哪些寄存器复现得出来」。")
	return false, nil
}

// reportChain 分组打印比对结果。分组不是为了好看 —— 四类结论的强度完全不同，
// 全打一样的勾会让人以为固件层也被验过了。
func reportChain(want declared, repro *reproduced, got qvl.Measurements) error {
	if len(got.RTMRs) != 4 {
		return fmt.Errorf("quote 里只有 %d 个 RTMR", len(got.RTMRs))
	}

	fmt.Println()
	if repro != nil {
		fmt.Printf("=== 已独立验证（复现于 %s）===\n", repro.ReproducedAt)
		if err := line("RTMR1", repro.RTMR1, got.RTMRs[1]); err != nil {
			return err
		}
		if err := line("RTMR2", repro.RTMR2, got.RTMRs[2]); err != nil {
			return err
		}
	} else {
		fmt.Println("=== ! 降级：以下比的是声明值，没有独立复现 ===")
		if err := line("RTMR1", want.RTMRs[1], got.RTMRs[1]); err != nil {
			return err
		}
		if err := line("RTMR2", want.RTMRs[2], got.RTMRs[2]); err != nil {
			return err
		}
	}

	fmt.Println()
	fmt.Println("=== 按信任边界接受（无法从公开材料复现，只能确认与部署时观测一致）===")
	if err := line("MRTD ", want.MRTD, got.MRTD); err != nil {
		return err
	}
	if err := line("RTMR0", want.RTMRs[0], got.RTMRs[0]); err != nil {
		return err
	}
	if err := line("RTMR3", want.RTMRs[3], got.RTMRs[3]); err != nil {
		return err
	}
	return nil
}

// checkEKMBinding 验 report_data 是不是由这条连接的 EKM 算出来的。
//
// 没有这一步，验的只是「某个 TD 出过这份 quote」—— 中间人拿一份真实 TD 的
// quote 转发，就能让整套验证对着一条它自己终止的 TLS 连接全部打勾。有了它，
// 结论才是「我此刻连的这个端点，就是那个 TD」。
//
// 组装规则用的是服务端同一个 attestation.ComposeReportData，不在这边重推一遍：
// 两边各写一份的话，哪天改了域分隔标签就是一个无声的分叉。
func checkEKMBinding(ekm [32]byte, reportData []byte) error {
	want := attestation.ComposeReportData(ekm)
	if !bytes.Equal(want[:], reportData) {
		return errors.New("report_data 与本连接的 EKM 对不上 —— " +
			"这份 quote 不属于你眼前这条连接，中间可能有人在转发")
	}
	return nil
}

func line(name, want, got string) error {
	if !strings.EqualFold(want, got) {
		fmt.Printf("  %s  ✗ 不符\n    期望 %s\n    实际 %s\n", name, want, got)
		return fmt.Errorf("%s 与期望值不符 —— 远端跑的不是这一版", name)
	}
	fmt.Printf("  %s  %s  ✓\n", name, got[:16]+"…")
	return nil
}

// loadDeclared 从 measurements.jsonl 取一行。不给版本号就取最后一行 ——
// 那份文件只追加，最后一行即最新发布。
func loadDeclared(path, version string) (declared, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return declared{}, fmt.Errorf("读 %s: %w", path, err)
	}
	var hit *declared
	for _, ln := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var d declared
		if err := json.Unmarshal([]byte(ln), &d); err != nil {
			return declared{}, fmt.Errorf("解析 %s 的某一行: %w", path, err)
		}
		if version == "" || d.Version == version {
			cp := d
			hit = &cp
		}
	}
	if hit == nil {
		return declared{}, fmt.Errorf("%s 里没有 version=%s 那一行", path, version)
	}
	if hit.MRTD == "" || len(hit.RTMRs) != 4 {
		return declared{}, errors.New("声明值不完整：需要 mrtd 和四项 rtmrs")
	}
	return *hit, nil
}

// loadReproduced 读 verify.sh 落的复现值。文件不在就返回 nil 走降级 ——
// 那是允许的用法（监控场景）。但版本对不上必须停：拿另一版的复现值来比，
// 比不上是必然的，报出来的却会是「远端跑的不是这一版」，误导。
func loadReproduced(path, version string) (*reproduced, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读 %s: %w", path, err)
	}
	var r reproduced
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	if r.Version != version {
		return nil, fmt.Errorf("%s 记的是 %s 的复现值，不是 %s —— 重跑 verify.sh %s",
			path, r.Version, version, version)
	}
	if r.RTMR1 == "" || r.RTMR2 == "" {
		return nil, fmt.Errorf("%s 里缺 rtmr1 或 rtmr2", path)
	}
	return &r, nil
}

// fetchAttestation 取 quote，同时从**这条**连接导出 EKM。
//
// 两者必须来自同一条 TLS 连接，否则绑定校验就没有意义：拿另一条连接的 EKM
// 去比，中间人只要转发一份真实 TD 的 quote 就能骗过。DisableKeepAlives 是为了
// 让这一点显而易见——每次运行独占一条连接，不从池子里捡。
func fetchAttestation(ctx context.Context, host string) (*attestation.Response, [32]byte, error) {
	var ekm [32]byte
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	url := "https://" + host + "/v1/attestation"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ekm, err
	}
	hr, err := client.Do(req)
	if err != nil {
		return nil, ekm, fmt.Errorf("取 quote: %w", err)
	}
	defer hr.Body.Close()
	if hr.StatusCode != http.StatusOK {
		return nil, ekm, fmt.Errorf("取 quote 返回 %d", hr.StatusCode)
	}
	if hr.TLS == nil {
		return nil, ekm, errors.New("这不是一条 TLS 连接，没有 EKM 可导")
	}
	raw, err := hr.TLS.ExportKeyingMaterial(attestation.EKMLabel, nil, 32)
	if err != nil {
		return nil, ekm, fmt.Errorf("导出 EKM: %w", err)
	}
	copy(ekm[:], raw)

	var r attestation.Response
	if err := json.NewDecoder(hr.Body).Decode(&r); err != nil {
		return nil, ekm, fmt.Errorf("解析响应: %w", err)
	}
	if len(r.Quote) == 0 {
		return nil, ekm, errors.New("响应里没有 quote")
	}
	return &r, ekm, nil
}
