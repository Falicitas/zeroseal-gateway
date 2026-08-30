package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zeroseal/gateway/api"
	"github.com/zeroseal/gateway/services/attestation"
	"github.com/zeroseal/gateway/services/diag"
	"github.com/zeroseal/gateway/services/secret"
	"github.com/zeroseal/gateway/services/video"
	"github.com/zeroseal/shared/db"
)

func main() {
	ctx := context.Background()

	// 清掉上次进程被 SIGKILL 时留在 configfs 里的 report 实例。
	// 非 TDX 环境返回 nil，不用判断环境。
	if err := attestation.CleanupStale(); err != nil {
		log.Printf("cleanup stale tsm reports: %v", err)
	}

	secrets, err := secret.Load(ctx)
	if err != nil {
		log.Fatalf("load secrets: %v", err)
	}

	pool, err := db.New(ctx, secrets.DBDSN)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	defer pool.Close()
	// 只报连上了，不打库名 —— DSN 相关的一切都算注入进来的机密，不进日志。
	log.Print("postgres 已连接")

	// collateral 的后台刷新。第一份已经在 Load 里同步拉过了，
	// 这里起的是 6 小时一轮的 ticker。
	// 为空可能是 dev，也不需要 secrets.Attestation.Start
	if secrets.Attestation != nil {
		refreshCtx, stopRefresh := context.WithCancel(ctx)
		defer stopRefresh()
		secrets.Attestation.Start(refreshCtx)
	}

	// 视频任务的兜底结算。客户提交完不回来取的话，那笔预扣没人收尾，
	// 用户余额会被永久占住 —— 这个 worker 负责扫掉。
	videoCtx, stopVideo := context.WithCancel(ctx)
	defer stopVideo()
	video.NewWorker(pool, secrets.ProviderKeys).Start(videoCtx)

	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewRouter(secrets.ProviderKeys, pool, secrets.Attestation),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		// 转发的是推理，不是 CRUD：非流式长补全跑几分钟很正常。
		// 原来的 30s 会把这类请求当场掐断，而上游已经在生成、已经在计费。
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	// 只收 TLS 1.3。EKM 在 TLS 1.2 + Extended Master Secret 下也能导出，
	// 但锁死 1.3 能让「导不出 EKM」这种情况不存在，安全论证也少一个分支。
	// 2026 年还在用 1.2 的客户端栈基本不存在。
	// 另外没有 TLSCert 就走 http，对应本地开发
	if secrets.TLSCert != nil {
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*secrets.TLSCert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	// 在起监听的 goroutine 之前打点：先写后读，handler 读到的一定是已写入的值。
	diag.MarkServing()

	go func() {
		var err error
		if srv.TLSConfig != nil {
			// 证书已经在 TLSConfig.Certificates 里，两个路径参数传空。
			err = srv.ListenAndServeTLS("", "")
		} else {
			// srv.ListenAndServe() 阻塞且返回值不为 nil。如果 err 不是 http.ErrServerClosed 代表的正常 shutdown 就打出日志
			// log.Fatalf = 打日志 + os.Exit(1)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()
	if srv.TLSConfig != nil {
		log.Printf("gateway listening on %s (TLS 1.3)", addr)
	} else {
		log.Printf("gateway listening on %s (plaintext HTTP)", addr)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM) // signal.Notify = 订阅模式。出现后面的信号，不管有多少订阅了 syscall.SIGINT 都会确保 quit 能收到

	// 缓冲区 1 时避免在 signal.Notify 结束，<-quit 还没执行到的非常微小的若干个时钟信号区间接收到 SIG 信号导致信号丢了
	// 所以可以丢到长度为 1 的缓冲区，涵盖了上面的情况

	<-quit // 只取 1 个，然后结束阻塞

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel() // 如果 srv.Shutdown 10s 内结束则要 cancel ctx。超过 10s 虽 Shutdown 被 ctx 断掉，但保障大部分 http 连接正常断开
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
