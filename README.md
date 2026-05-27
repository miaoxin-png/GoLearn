## mDNS 网站测绘 CLI

扫描本地二层网络中的 mDNS 资产，按目标 IP 网段和服务端口范围过滤，并输出服务实例、IP、Hostname、TTL 与 TXT banner。

### 用法

```bash
go run . -cidr 192.168.1.0/24 -ports 1-65535
```

也支持位置参数：

```bash
go run . 192.168.1.0/24 1-65535
```

常用参数：

- `-cidr`: 目标 IP 网段、单 IP 或 IP 范围，例如 `192.168.1.0/24`、`192.168.1.10`、`192.168.1.10-192.168.1.50`
- `-ports`: 目标服务端口范围，例如 `80,443,5000-5010`
- `-timeout`: 探测时长，默认 `6s`
- `-iface`: 指定网卡名，例如 `en0`
- `-services`: 追加查询的 mDNS 服务类型，例如 `_http._tcp.local,_qdiscover._tcp.local`
- `-passive`: 只监听 mDNS 流量，不主动发送查询

输出格式固定为：

```text
services:
<port>/<proto> <service>:
Name=<instance>
IPv4=<ip>
IPv6=<ip>
Hostname=<host>
TTL=<ttl>
<TXT banner>
answers:
PTR:
<service-type>
```
