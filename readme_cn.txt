
    欢迎使用 VPCS, 最新版本为 0.6.

    VPCS 是免费软件，遵从 BSD 许可的条款分发。
    源代码和许可协议条款可以从 vpcs.sf.net 获取到。
    更多信息，请访问 wiki.freecode.com.cn.
   
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
   usage: vpcs [OPTIONS] [FILENAME]
   OPTIONS:
     -h             print this help then exit
     -v             print version information then exit
   
     -i num         number of vpc instances to start (default is 9)
     -p port        run as a daemon listening on the tcp port
     -m num         start byte of ether address, default from 0
     [-r] FILENAME  load and execute script file FILENAME
   
     -e             tap mode, using /dev/tapx by default (linux only)
     [-u]           udp mode, default
   
   udp mode options:
     -s port        local udp base port, default from 20000
     -c port        remote udp base port (dynamips udp port), default from 30000
     -t ip          remote host IP, default 127.0.0.1
   
   tap mode options:
     -d device      device name, works only when -i is set to 1
   
   hypervisor mode option:
     -H port        run as the hypervisor listening on the tcp port
   
     If no FILENAME specified, vpcs will read and execute the file named
     startup.vpc if it exists in the current directory.

   注意：
   1. VPCS 使用的 cygwin1.dll 可能与其他 cygwin1.dll 不兼容。建议在一系统
      内只保留最新版本的。
   2. 后台服务模式时，需设置telnet LINEMODE为'一次传送一字符'：
      'telnet> mode character'

站点：http://wiki.freecode.com.cn 或 http://mirnshi.cublog.cn

历史版本：
   0.6     错误修订：
             1. 后台应答请求时，未使用网关的MAC地址
             2. 命令超过20个参数，导致崩溃
             3. 历史命令溢出，导致崩溃
           功能增补修订：
             1. 移除'ip mtu'，替换为'set mtu'
             2. 支持将relay的数据包转储到文件，文件格式为pcap。
                可以动态变更拓扑并可分析各节点的数据流向及内容。
             3. dhcp4可以自动续租
             4. 支持IP分片/重组
             5. ping命令支持'-D'选项，强制不分片
             6. 发送数据和接收数据包均比对MTU，超出MTU做相应提示处理
             7. 回环地址、组播地址和零地址均判断为非法地址，不可以再配置使用
             8. 重新格式化帮助
             9. echo命令支持彩色文字显示，增加'@'隐藏显示
             10. 增加保存dns、域名、relay等
              
   0.5b2   错误修订：使用getenv+access方式获取VPCS的真实路径
           Debian GNU/kFreeBSD的补丁（Daniel Lintott）
           运行echo命令时，刷新输出
           增大tcp会话数，减小tcp保持时间
           错误修订：源MAC地址未保存到arp表中

   0.5b1   支持设置vpc的启动个数
           支持设置TAP设备名（限只启动1个VPC）
           load和save命令支持缺省文件名

   0.5b0   支持hypervisor
   
   0.4b2   支持DNS
           支持数据包协议输出显示
           支持远程登录其他设备，热键返回
           其他增强及修订
           
   0.4a    增加后台服务模式
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
   