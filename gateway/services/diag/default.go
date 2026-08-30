package diag

// std 是进程级的默认记录，跟标准库 log 一个形状。
//
// 诊断记录本来就是「进程只有一个、到处都要写」的东西：为它穿一路参数，
// 或者绕一层函数变量让上层接线，都只是把同一个全局换个说法，
// 还多出一个可以忘记接的步骤。
//
// 要隔离状态就自己 NewStore()，跟 log.New() 之于 log.Printf 一样。
var std = NewStore()

// Record 往默认记录里收一条。
func Record(e Event) { std.Record(e) }

// 🤔：RecordUpstream 是目前的三个远程 log 的采集点入口之一，采集「上游拨不通 / 非 2xx / 流中途断」
// 🤔：RecordUpstream 收一条「上游失败（上游指 llm 侧）」：上游非 2xx 传它返的状态码，
// 连不上或流中途断传 0 加错误文本。
//
// host 只传主机名（req.URL.Host），不传整个 URL —— 有的上游把参数带在 query 里。
// 上游 key 走的是请求头（见 llm.buildRequest 里的 SetHeaders），不在 URL 里；
// host 本身来自 catalog，是公开配置。
//
// detail 不要传上游响应体：那是上游自己的 JSON，可能把请求内容回显出来。
// 非 2xx 传空串就够，状态码才是信息。
func RecordUpstream(host string, status int, detail string) {
	std.Record(NewEvent(KindUpstream, status, host, detail))
}

// Snapshot 取默认记录的快照，供诊断端点使用。
func Snapshot() ([]Event, []Counter) { return std.Snapshot() }
