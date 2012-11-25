
   Welcome to Virtual PC Simulator, Ver 0.4b2.
   
   VPCS is free software, distributed under the terms of the "BSD" licence.
   Source code and license can be found at vpcs.sf.net.
   For more information, please visit wiki.freecode.com.cn.

   The VPCS can simulate up to 9 PCs. You can ping/traceroute them, or 
ping/traceroute the other hosts/routers from the VPCS when you study the Cisco 
routers in the dynamips. VPCS is not the traditional PC, it is just a program 
running on the Linux, Windows or OS X(need more testing), and only few network 
commands can be used in it. But VPCS can give you a big hand when you study 
the Cisco devices in the Dynamips. VPCS can replace the routers or VMware boxes
which are used as PCs in the dynamips network.

   Now, VPCS can be run in udp or ether mode. In the udp mode, VPCS sends or 
receives the packets via udp. In the ether mode, via /dev/tap, not support 
on the Windows.

   When VPCS started, it listens the ports from 20000 to 20008 and waits the 
dynamips to connect, and sends the packets to the ports from 30000 to 30008 which 
should be listened by the dynamips. 
   
   VPCS will look for the file named 'startup.vpc' in the current directory, and 
execute the commands in it if you are not set the startup file from the command 
line. All the commands in the startup file are the internal commands of the VPCS.
The line started with '#' or '!' will be discarded.

   usage: vpcs [options] [scriptfile]
   Option:
       -h         print this help then exit
       -v         print version information then exit
   
       -p port    run as a daemon listening on the tcp 'port'
       -m num     start byte of ether address, default from 0
       -r file    load and execute script file
                  compatible with older versions, DEPRECATED.
   
       -e         tap mode, using /dev/tapx (linux only)
       -u         udp mode, default
   
   udp mode options:
       -s port    local udp base port, default from 20000
       -c port    remote udp base port (dynamips udp port), default from 30000
       -t ip      remote host IP, default 127.0.0.1
   
     If no 'scriptfile' specified, vpcs will read and execute the file named
     'startup.vpc' if it exsits in the current directory.

   NOTE: 
   1. The cygwin1.dll used by VPCS maybe conflicted with other version. Please 
      keep the latest cygwin1.dll in your system.
   2. Set telnet LINEMODE to 'character at a time' while running as the daemon
      'telnet> mode character'
 
Website: http://wiki.freecode.com.cn or http://mirnshi.cublog.cn
   
History:
   0.4b2   support DNS
           support 'dump' packets
           add 'rlogin' command to connect the remote host
           
   0.4a    support daemon mode
   0.3     under BSD license
   0.20a   support IPv6 linklocal, stateless autoconfiguration
           new 'ping' with many optins, and implement the tcp state machine
           support load/save the VPCS configuration
           support save/load the command history automaticlly
           
   0.16a   Support IPv6
   0.15a   Add configure the host ip using dhcp
   0.14g   Fix the traceroute loop running bug 
   0.14f   Fix the traceroute TTL bug 
   0.14e   Fix the bug, parse 'echo' and 'traceroute' command line error. 
   0.14d   Fix the bug which reply the arp request with broadcast address as 
           the source MAC address.
   0.14c   Change the TTL to 64.
   0.14b   Fix the bug about the I/O queue.
   0.14a   Add arp function that shows the current arp table, 120 seconds expired. 
           Add echo function that sends upd/tcp packet to the remote hosts. Now, 
           you can test acl in your routers network. 
   0.13a   Add ping localhost
           Fix a ping bug: get reply from any host ip.
   0.12s   Fix the tracert argument bug
   0.10s   Support udp mode
   0.02s   Fix a string copy bug
   0.01s   First version
