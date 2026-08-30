package diag

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// ctxRecorded 标记这条请求的错误已经被 Recover 记过。
//
// panic 会先经 Recover 记一条带栈的 KindPanic，再由 echo 转交给
// HTTPErrorHandler。不打这个标记，同一次 panic 会进 ring 两条、
// 计数器也被算两次。
const ctxRecorded = "zeroseal.diag.recorded"

// noRoute 是请求没匹配到任何路由时 Where 的取值。留空串的话计数器里会
// 出现一个 where 为空的键，读的人分不清是没路由还是我们漏填了。
const noRoute = "(no route)"

// echoInternal 是 echo 内部报错时 Where 的取值，那条路径没有格式串可用。
const echoInternal = "(echo)"

// panicStackSize 是抓栈的缓冲上限。Detail 那边还会截到 panicDetailMax，
// 这里给宽一点只是别让栈在中间被切断。
const panicStackSize = 4 << 10

// 🤔：HTTPErrorHandler 是目前的三个采集点入口之一，采集 api/endpoints 里 72 处 echo.NewHTTPError（4xx，5xx），不含上游请求
// 🤔：HTTPErrorHandler 目前唯一用到的地方是建路由实例的 NewRouter
// 🤔：用途是包住 echo 自己的错误处理：先记一条，再把写响应的活原样交回去。
//
// echo 的 DefaultHTTPErrorHandler 自己不打任何日志（只在写响应失败时才 log），
// 所以 api/endpoints 里那 72 处 echo.NewHTTPError 今天是完全静默的 ——
// 401、402、404、502 在 journald 里一行都没有。这个包装就是把它们接住的地方，
// 业务代码一行不用改。
func HTTPErrorHandler(next echo.HTTPErrorHandler) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		if recorded, _ := c.Get(ctxRecorded).(bool); !recorded {
			Record(newHTTPEvent(err, c))
		}
		next(err, c)
	}
}

// 🤔：newHTTPEvent 目前唯一用得到的地方是 HTTPErrorHandler
// 从 echo 的错误里取状态码和消息。
//
// he.Message 是 any，但 api/endpoints 里传的全是我们自己写死的字符串
// （最多拼进一个模型名），不含机密。Internal 里裹着的底层错误一并带上 ——
// 502 那几处的上游细节就在里面，而那正是要看的东西。
func newHTTPEvent(err error, c echo.Context) Event {
	status := http.StatusInternalServerError
	detail := err.Error()

	if he, ok := err.(*echo.HTTPError); ok {
		status = he.Code
		detail = fmt.Sprint(he.Message)
		if he.Internal != nil {
			detail += " | " + he.Internal.Error()
		}
	}

	kind := KindHTTP5xx
	if status < http.StatusInternalServerError {
		kind = KindHTTP4xx
	}
	return NewEvent(kind, status, routeOf(c), detail)
}

// 🤔：Recover 是目前的三个远程 log 的采集点入口之一，采集 handler 里的 panic
// Recover 装 echo 自带的 Recover 中间件，把 panic 的栈接进 ring。
//
// 今天没装它，panic 由 net/http 的 conn.serve 兜住：进程不死，但连接被直接
// 关掉，栈只进 stderr。摘掉 sshd 之后 stderr 没人看得到，所以这里是 panic
// 唯一的落点。
//
// DisablePrintStack 必须保持 false —— echo 只在它为 false 时才调
// runtime.Stack，置 true 会让 LogErrorFunc 收到一个空栈。
// LogErrorFunc 非 nil 时 echo 自己那段打印是走不到的，不会重复输出。
//
// DisableStackAll=true 只抓出事那条 goroutine：全量 dump 在有几百条在途
// 请求时是几十 KB，多出来的部分只会被 Detail 的上限截掉。
func Recover() echo.MiddlewareFunc {
	return middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize:       panicStackSize,
		DisableStackAll: true,
		LogErrorFunc: func(c echo.Context, err error, stack []byte) error {
			Record(NewEvent(KindPanic, 0, routeOf(c),
				fmt.Sprintf("%v\n%s", err, stack)))
			c.Set(ctxRecorded, true)
			return err
		},
	})
}

// logger 包住 echo 的 logger，接住 api/endpoints 里那 17 处 c.Logger().Errorf。
// 那些全是计费收尾失败（退款、结算、finalize），是今天唯一真的会进 journald
// 的一类错误。
//
// Where 用格式串而不是路由：logger 拿不到 echo.Context，没有路由可取。
// 格式串是编译期常量、每处唯一、不含任何请求数据，正好当位置标识 ——
// 计数器因此能按调用点分开算，而不是把所有计费错误并成一个键。
type logger struct {
	echo.Logger
}

// Logger 用 base 兜底，只截 Error 这一档 —— Info/Debug 那些不是错误，
// 进 ring 只会把真正的问题冲掉。
func Logger(base echo.Logger) echo.Logger {
	return &logger{Logger: base}
}

func (l *logger) Errorf(format string, args ...any) {
	Record(NewEvent(KindBilling, 0, format, fmt.Sprintf(format, args...)))
	l.Logger.Errorf(format, args...)
}

// Error 是 echo 内部写响应失败时走的路径，没有格式串可用。
func (l *logger) Error(i ...any) {
	Record(NewEvent(KindBilling, 0, echoInternal, fmt.Sprint(i...)))
	l.Logger.Error(i...)
}

// routeOf 取路由模板而不是真实 URL —— c.Request().URL.Path 带着任务 ID
// 这类请求参数，那是白名单不收的东西。
func routeOf(c echo.Context) string {
	if p := c.Path(); p != "" {
		return p
	}
	return noRoute
}
