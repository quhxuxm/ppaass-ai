# 移除 rate limit 的本机吞吐对比

测试日期：2026-11-13（Asia/Shanghai）。

四轮对照未显示已建立 flow 的吞吐获得一致提升。明确改善出现在突发新建 flow：
原生 UDP 和 TCP/Yamux UDP relay 的 128 个首包均由 64 个成功提升为 128 个成功。

## 测试环境与对照

- Apple M4，10 个逻辑 CPU，16 GiB 内存；macOS 27.2.1；Rust 1.100.0。
- Release：opt-level=3、fat LTO、codegen-units=1；测试运行时固定 4 个工作线程。
- 客户端、Entry 和 UDP echo 目标在同一测试进程，通过真实 loopback 套接字收发。
- 原生路径使用生产 UdpClientConnection 和 native_udp::run_listener，包含认证与 AEAD。
- TCP/Yamux 路径使用生产 YamuxClientConnection、ServerConnection 和 UdpRelayFlowSet，
  外层为真实 TCP/Yamux，子流包含 PPAASS 认证与加密。
- 两侧使用同一 Cargo.lock 和基准源码；基线仅恢复下述四个文件中的旧令牌桶，
  其余工作区代码与依赖均相同，不直接使用旧提交的依赖。
- 单个外层会话；目标 flow 容量 256；channel 容量 256；压缩 none；payload 1200 字节。
- 授权源为内存中的固定有效用户，访问记录关闭，分配器为测试可执行文件的系统默认值。
- 四轮逐组交替 before/after、after/before，测试顺序串行，未同时运行两个压测版本。

基线文件来源提交：`a0024a230a9f7d937890541c6e12fe1f4de7dc43`。

- `proxy-entry/src/native_udp/session.rs`
- `proxy-entry/src/native_udp/session/admission.rs`
- `proxy-entry/src/native_udp/session/runner.rs`
- `proxy-entry/src/connection/udp_relay_flow.rs`

## 已建立 flow 的稳态吞吐

每轮预热 1 秒、测量 3 秒；每个 flow 同时仅有一笔待回显请求。表中为四轮中位数，
括号内为最小值至最大值。单位 Mbps，仅计算校验成功的响应 payload，
不计协议头，也不把上行发送字节与下行回显字节相加。

| 传输 | 并发 flow | 修改前 Mbps（范围） | 修改后 Mbps（范围） | 中位数变化 |
| --- | ---: | ---: | ---: | ---: |
| 原生 UDP | 1 | 204.28（201.23–215.60） | 204.91（191.97–214.76） | +0.31% |
| 原生 UDP | 32 | 932.10（902.97–956.93） | 928.02（912.10–960.03） | -0.44% |
| TCP/Yamux UDP relay | 1 | 184.65（183.77–185.87） | 186.76（185.33–188.02） | +1.15% |
| TCP/Yamux UDP relay | 32 | 1095.88（1061.78–1138.49） | 1101.22（1066.70–1130.20） | +0.49% |

这些小幅差异没有呈现统一的改善方向，且每组仅四个短时样本，不能据此认定持续吞吐提速。

## 突发新建 128 个 flow

认证在计时前完成。128 个不同 flow 在同一时刻各发送一个 1200 字节首包；
固定观察 1 秒，不重试，窗口内校验成功的回显视为成功。每轮结果一致：

| 传输 | 修改前成功 | 修改后成功 | 首包成功率 | 1 秒窗口有效响应 payload |
| --- | ---: | ---: | --- | --- |
| 原生 UDP | 64/128 | 128/128 | 50% → 100% | 76,800 → 153,600 字节 |
| TCP/Yamux UDP relay | 64/128 | 128/128 | 50% → 100% | 76,800 → 153,600 字节 |

固定窗口有效响应吞吐为 0.6144 → 1.2288 Mbps，提升 100%。这是受固定请求数量限制的
突发交付指标；本组没有持续发包，不能作为峰值带宽结果。旧版本的 64 个突发额度
被消耗后，额外首包遭拒绝或丢弃，应用通常需要自行重试，因而会感受到等待或启动失败。

## 范围与原始数据

本次覆盖本机的协议客户端与 Entry 数据面，未经过完整 Desktop/Android、
SOCKS5、TUN、公网链路或 Registry 存储。未测 TCP 目标下载，也没有模拟 WAN RTT、
丢包、限带宽或生产多设备负载。桌面后台程序保持运行，未进行 CPU 绑核。
结果用于判断本次删除令牌桶的影响，不能外推为公网可持续吞吐。

稳态 raw 数据中的 failed_echoes 还包括观察窗口截止时未完成的请求，不应直接解读为
网络丢包率。突发场景的失败数量表示一秒内未收到正确响应的首包。

[48 次测试原始记录与环境、二进制及源码指纹](performance/rate-limit-comparison-2026-11-13.json)。

本机临时基准目录：`/private/var/folders/n0/ysn9lvwj0sz9tfhxh_jf_mz00000gn/T/ppaass-rate-comparison-e8wu3imh`。测试入口位于其
`source/proxy-entry/tests/rate_comparison.rs`，传输适配位于
`source/proxy-entry/tests/bench_transport/mod.rs`；构建日志和每次运行日志也保存在该目录。
生产数据面源码未因本次测量发生改动。
