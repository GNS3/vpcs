
    欢迎使用 VPCS, 最新版本为 0.3.

    VPCS 可以模拟最多 9 个虚拟的 PC。你可以 ping/traceroute 这些 PC，或者
在这些 PC 中 ping/traceroute 其他的主机或路由器。当然这些虚拟的 PC，并不
完全意义上的 PC，它只是一个运行在 Linux 或 Windows 上的应用程序，仅可以
使用少数几个有关网络的命令。在借助 Dynamips 学习 Cisco 设备的过程中，会
起到非常大的帮助。它可以替代在实验中充当 PC 的路由器或者使用 Vmware 虚拟
的 PC。通常，这些被替代者会占用大量的内存和 CPU 资源。

   VPCS 可以运行在 UDP 或者以太模式。在 UDP 方式下，VPCS 通过 UDP 发送和接
收数据包；以太方式下，使用 /dev/tapx 发送和接收数据包。在 Windows 下只支
持 UDP 方式。

   当 VPCS 启动后， 缺省监听自 20000 到 20008 的 UDP 端口，并向 30000 到 
30008 发送数据包。如果没有指定启动文件，且当前目录下存在缺省的启动文件
（文件名为：startup.vpc），VPCS 就会自动加载启动文件，并执行包含的命令。
startup.vpc 可以包含的命令即为 VPCS 的内部命令。

   VPCS 的命令行选项
   usage: vpcs [options]
           -u        udp mode, default
           -e        tap mode, using /dev/tapx
           -s port   local udp port, default from 20000
           -c port   remote udp port(dynamips udp ports), default from 30000
           -r file   run startup file

   注意：VPCS 使用的 cygwin1.dll 可能与其他 cygwin1.dll 不兼容。建议在一系统
内只保留最新版本的。

站点：http://wiki.freecode.com.cn 或 http://mirnshi.cublog.cn

历史版本：
   0.3     BSD许可
   0.20a   进一步增强IPv6，支持LinkLocal，无状态自动配置，手工eui-64
           支持更多参数的ping，实现了tcp从连接到关闭的完整状态
           支持保存/加载配置
           支持历史命令自动保存/加载
           
   0.16a   支持IPv6
   0.15a   增加DHCP获取IP地址功能
           配置主机地址时，可以不必指定网关地址
   0.14g   修订traceroute命令循环错误
   0.14f   修订traceroute命令TTL处理错误
   0.14e   修订echo、traceroute命令行处理错误
   0.14d   修订Arp处理错误，错误地将广播地址作为源地址应答Arp请求。  
   0.14c   修订TTL为64  
   0.14b   修订 I/O 队列错误
   0.14a   增加 arp 命令，可以显示当前的 arp 表，120秒的过期刷新
           增加 echo 命令，可以向远程主机发送 udp/tcp 数据包。这对于测试
           ACL 是比较有用的。
           修订同子网比较错误
   0.13a   增加 ping/tracert 本地 IP 回应
           修订 ping 任何 IP，均存在错误
   0.12s   修订 tracert 命令参数错误
   0.10s   支持 udp 方式
   0.02s   修订了一处字符串拷贝错误
   0.01s   初始版本
   