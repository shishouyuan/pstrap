# Introduction 简介
**pstrap**(Port Scanner Trap) listens on specific ports (**trap ports**, e.g., pretend to be a SSH server on tcp port 22) and **deny all access from those IPs who connect these ports**. It is a simple way to prevent port scanning. Currently only work with ufw.

**pstrap**(Port Scanner Trap)侦听特定的端口（**陷阱端口**，例如监听22 tcp 端口来伪装成SSH服务），并且会**阻止连接这些端口的IP到本机的所有连接**。这是一个阻止端口扫描的简单方法。 目前需要和ufw配合使用。

# Configuration 配置
```ini
# /etc/pstrap/pstrap.ini
[DEFAULT]
trap_ports = 22,3389    # trap ports
db_file = /etc/pstrap/pstrapped.ini # file stores trapped IPs
log_file = /var/log/pstrap.log  # log file
trapped_duration = 10080    # minutes that a IP is trapped, after which the rule is deleted
```