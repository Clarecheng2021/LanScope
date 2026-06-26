# LanScope

[English](README.md) | [简体中文](README.zh-CN.md)

LanScope 是一个轻量级内网资产发现与端口扫描工具，用于发现局域网中的存活主机、开放 TCP 端口、HTTP/HTTPS 服务信息，并支持命令行和 Web 控制台两种使用方式。

请只扫描你拥有或已获得授权的网络和设备。

## 功能特性

- 支持扫描单个 IP、CIDR 网段和主机名
- 支持 TCP Connect 端口扫描，并可配置并发参数
- 支持常用端口、Top 100 端口、全端口和自定义端口范围
- 支持 nmap 风格扫描模式：`quick`、`normal`、`full`、`deep`、`custom`
- 支持主机发现，避免对全网段所有主机盲目执行全端口扫描
- 支持 HTTP/HTTPS 探测，采集状态码、标题、Server 和跳转地址
- 支持 ARP/MAC 信息辅助识别设备厂商
- 支持表格、JSON、CSV 输出
- 提供本地 Web 控制台，可自动发现当前局域网并一键快速扫描
- 无第三方运行时依赖

## 快速开始

扫描一个网段：

```powershell
python -m lanscope 192.168.1.0/24
```

扫描常用端口：

```powershell
python -m lanscope 192.168.1.0/24 --ports common
```

按 nmap 思路进行全端口扫描：

```powershell
python -m lanscope 192.168.1.0/24 --mode full
```

扫描指定端口并保存 JSON：

```powershell
python -m lanscope 10.0.0.5 10.0.0.8 --ports 22,80,443,8080 --format json --output scan.json
```

保存 CSV：

```powershell
python -m lanscope 192.168.1.0/28 --ports top100 --format csv --output assets.csv
```

## Web 控制台

启动本地 Web 控制台：

```powershell
python -m lanscope.web
```

然后在浏览器打开：

```text
http://127.0.0.1:8765
```

Web 控制台提供：

- 自动发现本机局域网地址
- 自动推荐当前局域网 CIDR，例如 `192.168.1.0/24`
- 一键快速扫描当前局域网
- 自定义目标和端口扫描
- 扫描任务进度查看
- JSON 扫描结果查看

快速扫描默认端口：

```text
22,80,443,445,3389,8080
```

## 命令行用法

```text
python -m lanscope TARGET [TARGET ...] [options]

Targets:
  192.168.1.10          单个 IP
  192.168.1.0/24        CIDR 网段
  intranet.local        主机名

Options:
  --mode MODE           扫描模式：quick、normal、full、deep 或 custom
  --ports PORTS         端口集合：common、top100、full 或自定义端口列表
  --timeout SECONDS     单次连接超时时间
  --host-concurrency N  最大并发主机数
  --global-concurrency N 全局最大 TCP 并发连接数
  --per-host-concurrency N 单主机最大 TCP 并发连接数
  --discover-hosts      端口扫描前先发现存活主机
  --skip-ping           跳过 ping，直接扫描目标端口
  --format FORMAT       输出格式：table、json 或 csv
  --output PATH         将结果写入文件
```

## 扫描模式

LanScope 提供 nmap 风格的扫描配置：

- `quick`：主机发现 + 少量高价值端口，例如 `22,80,443,445,3389,8080`
- `normal`：主机发现 + `top100`
- `full`：主机发现 + TCP 全端口 `1-65535`
- `deep`：更保守的深度全端口扫描，适合稳定性优先的场景
- `custom`：使用 `--ports` 和自定义并发、超时参数

对于较大的网段，推荐：

```powershell
python -m lanscope 192.168.1.0/24 --mode full
```

`full` 模式不会直接对整个网段的每台主机都扫描 `1-65535`，而是先通过 ARP 缓存、可选 ping 和 TCP 探测端口发现存活主机，再只对存活主机执行全端口扫描。扫描器使用流式 worker，不会一次性创建 `主机数 * 65535` 个任务。

如需调整性能参数：

```powershell
python -m lanscope 192.168.1.0/24 --mode full --global-concurrency 800 --per-host-concurrency 100 --timeout 0.4
```

## 更详细的中文说明

更完整的测试流程、参数建议和常见问题见：

[使用说明.md](使用说明.md)

## 注意事项

LanScope 适合做基础资产发现，不包含漏洞利用、弱口令爆破或高风险检测能力。请在授权范围内使用。
