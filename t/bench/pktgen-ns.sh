#!/bin/bash
# 在 NetNS 中使用 pktgen 向主机 veth 极速发包测试 VoidGate XDP
#set -euo pipefail

set -ex

if [[ ${EUID} -ne 0 ]]; then
    echo "请以 root 权限运行" >&2
    exit 1
fi

# 确保内核加载了 pktgen 模块
modprobe pktgen 2>/dev/null || true

NS=vgpkt$$
HA=vha$$
HB=vhb$$

cleanup() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HA" 2>/dev/null || true
}
trap cleanup EXIT

# 1. 构建隔离网络环境
ip netns add "$NS"
ip link add "$HA" type veth peer name "$HB"
ip link set "$HB" netns "$NS"

ip addr add 198.51.100.10/24 dev "$HA"
ip link set "$HA" up

ip netns exec "$NS" ip addr add 198.51.100.1/24 dev "$HB"
ip netns exec "$NS" ip link set "$HB" up
ip netns exec "$NS" ip link set lo up

echo "================================================="
echo "主机端网卡: $HA (IP: 198.51.100.10)"
echo "请在另一终端运行 VoidGate 挂载到该网卡:"
echo "  sudo ./voidgate -c configs/voidgate.conf -i $HA"
echo "================================================="
echo "正在开始 pktgen 极速打流，按 Ctrl+C 停止..."
echo

# 2. 在 NetNS 命名空间内部配置并启动 pktgen
ip netns exec "$NS" bash -c "
    PG_THREAD=/proc/net/pktgen/kpktgend_0
    PG_DEV=/proc/net/pktgen/$HB
    PG_CTRL=/proc/net/pktgen/pgctrl

    # 绑定设备到 CPU 线程 0
    echo 'rem_device_all' > \$PG_THREAD
    echo 'add_device $HB' > \$PG_THREAD

    # 极限发包参数配置
    echo 'count 0' > \$PG_DEV          # 0 表示持续发包，不自动停止
    echo 'clone_skb 0' > \$PG_DEV   # 内存复用：1 个 SKB 重复发 10000 次，极大地节省 CPU
    echo 'delay 0' > \$PG_DEV          # 零延迟，全速发包
    echo 'pkt_size 64' > \$PG_DEV      # 64 字节小包，冲刷极限 PPS
    echo 'dst 198.51.100.10' > \$PG_DEV # 目标 IP
    echo 'udp_dst_min 53' > \$PG_DEV   # 目标端口 53 (DNS)
    echo 'udp_dst_max 53' > \$PG_DEV

    # 启动打流（阻塞运行）
    echo 'start' > \$PG_CTRL
"

# echo 'flag IPSRC_RND' > \$PG_DEV   # 随机源 IP（模拟 DDoS 攻击）
