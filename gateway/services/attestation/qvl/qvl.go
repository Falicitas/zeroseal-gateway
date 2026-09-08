// Package qvl 是 quote 的验证侧：验 Intel 签名链、解析 TD 报告体、比对度量值。
//
// 单独成包而不是并进 attestation，是因为它依赖 go-tdx-guest 的 QVL 与 collateral
// 拉取，而那套东西不该进 gateway server 的二进制 —— server 只负责出 quote，验
// quote 的是 zsinject 和 verify-quote 这类命令行工具。被度量的二进制里不放用不上
// 的依赖：既白白改掉 sha256，也平添攻击面。
//
// 包名不叫 verify，是因为调用方普遍要同时 import go-tdx-guest/verify，同名就得
// 到处起别名。QVL 是 Intel 自己对这套验证库的叫法。
package qvl

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// Measurements 是 quote 里的 TD 度量值。它同时是 zsinject -expect 文件的格式和
// -show 的输出格式，所以第一次采集可以直接把 -show 的输出重定向成 -expect 的输入。
type Measurements struct {
	MRTD  string   `json:"mrtd"`
	RTMRs []string `json:"rtmrs"`
}

// Result 是一份 quote 验过之后能拿出来的东西。ReportData 留给调用方做绑定校验：
// zsinject 用它验注入用的临时公钥，verify-quote 用它验 TLS 的 EKM。
type Result struct {
	Measurements Measurements
	ReportData   []byte
}

// TcbOutOfDate 是目前唯一允许放行的 TCB 档位，给调用方校验 flag 用。
const TcbOutOfDate = string(pcs.TcbComponentStatusOutOfDate)

// Verify 验 Intel 签名链、吊销状态、TCB 档位，再解析报告体并拒绝 debug TD。
//
// allowTcb 非空时只放行一种情形：验证唯一的失败原因是平台 TCB 档位为 OutOfDate。
// 签名不对、证书被吊销、或者档位比这更差，一律照常拒。
func Verify(ctx context.Context, raw []byte, allowTcb string) (Result, error) {
	// 验 Intel 签名链、吊销状态、TCB 状态。TrustedRoots 留空，
	// 库会用编译进来的 Intel SGX Root CA——从对端拿到的那张自签根不能直接信。
	opts := verify.DefaultOptions()
	opts.GetCollateral = true
	opts.CheckRevocations = true
	verifyErr := verify.RawTdxQuoteContext(ctx, raw, opts)

	// 刻意不直接设 DisableTcbStatusCheck：那样会永久失明，以后宿主机退化或
	// Intel 发新公告都不会再报。这里是先严格验一遍、失败原因确认无误后才放行，
	// 而且每次都打印警告。
	if verifyErr != nil &&
		allowTcb == TcbOutOfDate &&
		strings.Contains(verifyErr.Error(), verify.ErrTdxTcbStatus.Error()) {

		fmt.Fprintf(os.Stderr,
			"警告：平台 TCB 档位为 %s，按 -allow-tcb-status 放行。\n"+
				"      该档位挂着 Intel 已公布的 SGX/TDX 提权与信息泄露公告，\n"+
				"      意味着宿主机运营方有可能击穿 TD 隔离。别用它注生产凭据。\n"+
				"      落后在哪几位微码上，用 tcbcheck 查。\n",
			allowTcb)

		relaxed := verify.DefaultOptions()
		relaxed.GetCollateral = true
		relaxed.CheckRevocations = true
		relaxed.DisableTcbStatusCheck = true
		verifyErr = verify.RawTdxQuoteContext(ctx, raw, relaxed)
	}
	if verifyErr != nil {
		return Result{}, fmt.Errorf("quote 验证失败: %w", verifyErr)
	}

	body, err := tdBody(raw)
	if err != nil {
		return Result{}, err
	}
	if err := checkNotDebug(body); err != nil {
		return Result{}, err
	}

	m := Measurements{
		MRTD:  hex.EncodeToString(body.GetMrTd()),
		RTMRs: make([]string, 0, 4),
	}
	for _, r := range body.GetRtmrs() {
		m.RTMRs = append(m.RTMRs, hex.EncodeToString(r))
	}
	return Result{Measurements: m, ReportData: body.GetReportData()}, nil
}

// Compare 比对期望与实测的度量值。want 通常读自 -expect 文件。
func Compare(want, got Measurements) error {
	if want.MRTD == "" || len(want.RTMRs) != 4 {
		return errors.New("期望度量值不完整：需要 mrtd 和四项 rtmrs")
	}
	if !equalHex(want.MRTD, got.MRTD) {
		return fmt.Errorf("MRTD 不匹配\n  期望 %s\n  实际 %s", want.MRTD, got.MRTD)
	}
	if len(got.RTMRs) != 4 {
		return fmt.Errorf("quote 里只有 %d 个 RTMR", len(got.RTMRs))
	}
	for i := range 4 {
		if !equalHex(want.RTMRs[i], got.RTMRs[i]) {
			return fmt.Errorf("RTMR%d 不匹配\n  期望 %s\n  实际 %s",
				i, want.RTMRs[i], got.RTMRs[i])
		}
	}
	return nil
}

// tdBody 从 quote 里取出 TD 报告体。生产上是 v5，v4 一并支持，
// 免得以后宿主机降级到 v4 时这个工具直接不能用。
func tdBody(raw []byte) (tdMeasurable, error) {
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("解析 quote: %w", err)
	}
	switch v := q.(type) {
	case *pb.QuoteV5:
		b := v.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
		if b == nil {
			return nil, errors.New("quote v5 里没有 TD 报告体")
		}
		return b, nil
	case *pb.QuoteV4:
		b := v.GetTdQuoteBody()
		if b == nil {
			return nil, errors.New("quote v4 里没有 TD 报告体")
		}
		return b, nil
	default:
		return nil, fmt.Errorf("不认识的 quote 类型 %T", q)
	}
}

// tdMeasurable 把 v4 和 v5 两种报告体收敛成我们需要的四个访问器。
type tdMeasurable interface {
	GetMrTd() []byte
	GetRtmrs() [][]byte
	GetReportData() []byte
	GetTdAttributes() []byte
}

// checkNotDebug 拒绝开了 debug 位的 TD。TD_ATTRIBUTES 的 bit 0 是 DEBUG，
// 置位意味着宿主机可以直接检视这个 TD 的内存，机密性保证全部作废。
// 这一条比度量值比对还要靠前——度量对了但能被 debug，等于没保护。
func checkNotDebug(b tdMeasurable) error {
	attrs := b.GetTdAttributes()
	if len(attrs) == 0 {
		return errors.New("quote 里没有 TD_ATTRIBUTES")
	}
	if attrs[0]&0x01 != 0 {
		return fmt.Errorf("这个 TD 开了 debug 位（TD_ATTRIBUTES=%s）",
			hex.EncodeToString(attrs))
	}
	return nil
}

func equalHex(a, b string) bool {
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}
