#!/bin/sh
#-----------------------------------------------------------------
#
#  PC: 192.168 , 2001:ip4(3)::ip4(4)
#  Rt: 172.16, 2002:ip4(2:3)::ip4(4)
#
#         1.1                    172.16                   8.1   8.2
#  PC1 - f1/0 -*        1.1  1.2         2.2  2.1     *- f1/0 - PC8 
#  vlan10      +-- R1 - f0/0:f0/0 - R0 - f0/1:f0/0 - R2
#              |  1.254                               *- f1/1 - PC9 
#  PC2 - f1/1 -*                                          9.1   9.2
#  vlan10 1.2  |      
#              |
#  PC3 - f1/2 -*
#  vlan11 2.1  |
#              |
#  PC4 - f1/3 -*
#  vlan11 2.2  |
#              |
#  PC5 - f1/4 -*
#         3.2
#
#-----------------------------------------------------------------
C=`pwd`/dynamips
B=`pwd`/c3660-jk9o3s-mz.124-15.T5.bin.unzip

mkdir -p r1
cd r1
$C -i R1 -T 2001 -P 3600 -t 3660 -X -r 160 -c 0x2102 --sparse-mem --idle-pc=0x607789b8 \
 -p 0:NM-1FE-TX -p 1:NM-16ESW $B \
 -s 0:0:udp:7000:127.0.0.1:7001 \
 -s 1:0:udp:30000:127.0.0.1:20000 \
 -s 1:1:udp:30001:127.0.0.1:20001 \
 -s 1:2:udp:30002:127.0.0.1:20002 \
 -s 1:3:udp:30003:127.0.0.1:20003 \
 -s 1:4:udp:30004:127.0.0.1:20004
cd ..

mkdir -p r2
cd r2
$C -i R2 -T 2002 -P 3600 -t 3660 -X -r 128 -c 0x2102 --sparse-mem --idle-pc=0x607789b8 \
 -p 1:NM-4E $B  \
 -s 0:0:udp:7003:127.0.0.1:7002 \
 -s 1:0:udp:30007:127.0.0.1:20007 \
 -s 1:1:udp:30008:127.0.0.1:20008 
cd ..

mkdir -p r0
cd r0
start ..\dynamips -i R0  -T 2000 -P 3600 -t 3660 -X -r 128 -c 0x2102 --sparse-mem --idle-pc=0x607789b8 \
 $B \
 -s 0:0:udp:7001:127.0.0.1:7000 \
 -s 0:1:udp:7002:127.0.0.1:7003 
cd .. 

exit
--------------------------------------------------------
R0
-------
conf t
hostname R0
ipv6 unicast-routing
interface FastEthernet0/0
 no shutdown
 ip address 172.16.1.2 255.255.255.0
 full-duplex
 ipv6 address 2002:16:1::2/64
 ipv6 enable
 ipv6 rip cisco enable
interface FastEthernet0/1
 no shutdown
 ip address 172.16.2.2 255.255.255.0
 full-duplex
 ipv6 address 2002:16:2::2/64
 ipv6 enable
 ipv6 rip cisco enable
router rip
 version 2
 network 172.16.0.0
 no auto-summary
ipv6 router rip cisco
end
--------------------------------------------------------
R1
-------
conf t
hostname R1
ip dhcp pool global
   network 192.168.1.0 255.255.255.0
   default-router 192.168.1.1
ipv6 unicast-routing
ipv6 cef
interface FastEthernet0/0
 ip address 172.16.1.1 255.255.255.0
 speed auto
 full-duplex
 ipv6 address 2002:16:1::1/64
 ipv6 enable
 ipv6 rip cisco enable
interface FastEthernet1/0
 switchport access vlan 10
 speed 100
interface FastEthernet1/1
 switchport access vlan 10
interface FastEthernet1/2
 switchport access vlan 11
interface FastEthernet1/3
 switchport access vlan 11
interface FastEthernet1/4
 no switchport
 ip address 192.168.3.1 255.255.255.0
 ipv6 address 2001:3::1/64
 ipv6 enable
 ipv6 rip cisco enable
interface Vlan10
 ip address 192.168.1.1 255.255.255.0
router rip
 version 2
 network 172.16.0.0
 network 192.168.1.0
 network 192.168.2.0
 network 192.168.3.0
 no auto-summary
ipv6 router rip cisco
end
--------------------------------------------------------
R2
-------
conf t
hostname R2
ipv6 unicast-routing
interface FastEthernet0/0
 no shutdown
 ip address 172.16.2.1 255.255.255.0
 full-duplex
 ipv6 address 2002:16:2::1/64
 ipv6 enable
 ipv6 rip cisco enable
interface Ethernet1/0
 no shutdown
 ip address 192.168.8.1 255.255.255.0
 full-duplex
 ipv6 address 2001:8::1/64
 ipv6 enable
 ipv6 rip cisco enable
interface Ethernet1/1
 no shutdown
 ip address 192.168.9.1 255.255.255.0
 full-duplex
 ipv6 address 2001:9::1/64
 ipv6 enable
 ipv6 rip cisco enable 
router rip
 version 2
 network 172.16.0.0
 network 192.168.8.0
 network 192.168.9.0
 no auto-summary
ipv6 router rip cisco
end