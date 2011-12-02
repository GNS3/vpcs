#!/bin/sh
#-----------------------------------------------------------------
# topology:
# 
# 20000    30000                  T2000               30002         20002
# PC1 ---- s0/0 -*                   ^                    *- s0/0 - PC3
#                |                   |                    |
#                |                   ^                    |
#     T2001<-<   R1 --- s1/0:s0/0 -- R0 --- s0/1:s1/0 --- R2  >-> T2002
#                ||    21000 21001   |     21002 21003    |
# PC2 ---- s0/1 -/|                  |                    *- s0/1 - PC4
# 20001    30001  |    *----*-----*------*-------*    PC9   30003   20003
#                 | 30004 30005 30006  30007   41000 20008
# RealPC --------/     |    |     |      |       |     |
#                   20004 20005 20006  20007   41003 30008
#                     PC5   PC6   PC7    PC8     |     |
#                                                *-----*
#                                                   |
#                                                   R3 >-> T2003  
#-----------------------------------------------------------------
C=`pwd`/dynamips
B=`pwd`/c3660-jk9o3s-mz.124-15.T5.bin.unzip
B1=`pwd`/c2600-ik8s-mz.122-11.T.bin.unzip
B2=`pwd`/c2600-i-mz.113-3a.T1.bin.unzip
B3=`pwd`/c7200-adventerprisek9-mz.124-22.T.bin.unzip
mkdir -p r61
cd r61
$C -i R1 -T 2001 -P 7200 -t npe-400  -X --sparse-mem -r 192 -c 0x2102 \
  --idle-pc=0x60646da8 -p 0:C7200-IO-2FE -p 1:PA-2FE-TX \
  -s 0:0:udp:30000:127.0.0.1:20000 \
  -s 0:1:udp:30001:127.0.0.1:20001 \
  -s 1:0:udp:21000:127.0.0.1:21001 \
  -s 1:1:linux_eth:eth1 \
  $B3 &
cd -

mkdir -p r62
cd r62
$C -i R2 -T 2002 -P 7200 -t npe-400 -X --sparse-mem -r 192 -c 0x2102 \
  --idle-pc=0x60646da8 -p 0:C7200-IO-2FE -p 1:PA-2FE-TX \
  -s 0:0:udp:30002:127.0.0.1:20002 \
  -s 0:1:udp:30003:127.0.0.1:20003 \
  -s 1:0:udp:21003:127.0.0.1:21002 \
  $B3 &
cd -
mkdir -p r60
cd r60
$C -i R0 -T 2000 -P 3600 -t 3660 -X --sparse-mem -r 192 -c 0x2102 \
  --idle-pc=0x607789b8 -p 0:NM-1FE-TX -p 1:NM-1FE-TX -p 2:NM-16ESW \
  -s 0:0:udp:21001:127.0.0.1:21000 \
  -s 1:0:udp:21002:127.0.0.1:21003 \
  -s 2:0:udp:30004:127.0.0.1:20004 \
  -s 2:1:udp:30005:127.0.0.1:20005 \
  -s 2:2:udp:30006:127.0.0.1:20006 \
  -s 2:3:udp:30007:127.0.0.1:20007 \
  -s 2:4:udp:41000:127.0.0.1:41003 \
  $B &
cd ..

mkdir -p r63
cd r63
$C -i R3 -T 2003 -P 3600 -t 3660 -X --sparse-mem -r 192 -c 0x2102 \
  --idle-pc=0x607789b8 -p 0:NM-16ESW \
  -s 0:0:udp:41003:127.0.0.1:41000 \
  -s 0:1:udp:30008:127.0.0.1:20008 \
  $B &
cd ..
exit
------------------------------------
R1
------------------------------------
conf t
interface FastEthernet0/0
 ip address 172.16.1.2 255.255.255.0
 no shut
interface FastEthernet1/0
 ip address 172.16.2.2 255.255.255.0
 no shut
exit
router rip
 version 2
 no auto-summary
 network 172.16.1.0
 network 172.16.2.0
hostname R0
exit
wr
sh run
------------------------------------
R1
------------------------------------
conf t
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shut
interface FastEthernet0/1
 ip address 192.168.2.1 255.255.255.0
 no shut
interface FastEthernet1/0
 ip address 172.16.1.1 255.255.255.0
 no shut
router rip
 version 2
 no auto-summary
 network 172.16.1.0
 network 192.168.1.0
 network 192.168.2.0
 hostname R1
 exit
 wr
 sh run
------------------------------------
R2
------------------------------------
conf t
interface FastEthernet0/0
 ip address 192.168.11.1 255.255.255.0
 no shut
interface FastEthernet0/1
 ip address 192.168.12.1 255.255.255.0
 no shut
interface FastEthernet1/0
 ip address 172.16.2.1 255.255.255.0
 no shut
router rip
 version 2
 no auto-summary
 network 172.16.2.0
 network 192.168.11.0
 network 192.168.12.0
 hostname R2
 exit
 wr
 sh run

