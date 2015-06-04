/*
 * Copyright (c) 2007-2014, Paul Meng (mirnshi@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
**/

#include <stdio.h>
#include <string.h>
#include "help.h"
#include "utils.h"

extern int num_pths;

int help_clear(int argc, char **argv)
{
	esc_prn("\n{Hclear} {Hip}|{Hipv6}|{Harp}|{Hneighbor}|{Hhist}\n"
		"  Clear ip/ipv6 address, arp/neighbor table, command history.\n");

	return 1;
}


int help_echo(int argc, char **argv)
{
	return 1;
}

int help_hist(int argc, char **argv)
{
	return 1;
}

int help_relay(int argc, char **argv)
{
	char *s[2] = {
		"[{Uip1}:]{Uport1} [{Uip2}:]{Uport2}",
		"{Uip1} and {Uip2}"};
		
	esc_prn("\n{Hrelay} {UARG}\n"
		"  The relay command allows the VPCS to become a virtual patch panel where\n"
		"  connections can be dynamically changed using the {Hrelay} command.\n"
		"  There are three steps required to use VPCS as a virtual patch panel.\n"
		"  1. A relay {Hhub port} must be defined using the {Hrelay port} {Uport} command.\n"
		"  2. Remote NIO_UDP connections (cloud connections in GNS3) use this {Hhub}\n"
		"     {Hport} as the remote port, ensuring each NIO_UDP connection has a unique \n"
		"     {Hlocal} port (The local {Hport} numbers will be used to 'patch' the\n" 
		"     connection). VPC instances can be directed to use this hub port as\n"
		"     their remote port using the command {Hset rport} {Uport}.\n"
		"  3. The 'patching' is completed using the command:\n"
		"     {Hrelay add} [{Uip1}:]{Uport1} [{Uip2}:]{Uport2}, where {Uport1} and {Uport2} are the\n"
		"     {Hlocal} port numbers used in step 2.\n"
		"  ARG:\n"
		"     {Hadd} %s   Relay the packets between %s\n"
		"     {Hdel} %s   Delete the relay rule\n"
		"     {Hdel} {Uid}                        Delete the relay rule\n"
		"     {Hdump} [{Hon}|{Hoff}]                 Dump relay packets to file\n"
		"     {Hport} {Uport}                     Set relay hub port\n"
		"     {Hshow}                          Show the relay rules\n"
		"  Note: %s are 127.0.0.1 by default\n",
		s[0], s[1], s[0], s[1]);

	return 1;
}

int help_ip(int argc, char **argv)
{
	if (!strncmp(argv[0], "dhcp", strlen(argv[0])) ||
	    (argc == 3 && !strncmp(argv[1], "dhcp", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2]))))) {
		esc_prn("\n{Hip dhcp} [{UOPTION}]\n"
			"  Attempt to obtain IPv4 address, mask, gateway and DNS via DHCP\n"
			"  OPTION:\n"
			"    {H-d}         Show DHCP packet decode\n"
			"    {H-r}         Renew DHCP lease\n"
			"    {H-x}         Release DHCP lease\n");

		return 1;
	}

	if (argc == 3 && (!strncmp(argv[1], "dns", strlen(argv[1])) ||
	    !strncmp(argv[1], "dns6", strlen(argv[1]))) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("\n{Hip [dns | dns6]} {Uip}\n"
			"  Set DNS server {Uip}, delete if {Uip} is '0'.\n");
		
		return 1;
	}
	
	if (argc == 3 && !strncmp(argv[1], "domain", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("\n\{Hip domain} {Uname}\n"
			"  Sets local domain name. \n"
			"  If there's no '.' in the host name: the name is assumed within the local\n"
			"  domain, it is a short name relative to the local domain. The resolver\n"
			"  will append the local domain name to the hostname to resolve it.\n");

		return 1;
	}

	esc_prn("\n{Hip} {UARG} ... [{UOPTION}]\n"
		"  Configure the current VPC's IP settings\n"
		"    ARG ...:\n"
		"    {Uaddress} [{Umask}] [{Ugateway}]\n"
		"    {Uaddress} [{Ugateway}] [{Umask}]\n"
		"                   Set the VPC's ip, default gateway ip and network mask\n"
		"                   Default IPv4 mask is /24, IPv6 is /64. Example:\n"
		"                   {Hip 10.1.1.70/26 10.1.1.65} set the VPC's ip to 10.1.1.70,\n"
		"                   the gateway to 10.1.1.65, the netmask to 255.255.255.192.\n"
		"                   In tap mode, the ip of the tapx is the maximum host ID\n"
		"                   of the subnet. In the example above the tapx ip would be \n"
		"                   10.1.1.126\n"
		"                   {Umask} may be written as /26, 26 or 255.255.255.192\n"
		"    {Hauto}           Attempt to obtain IPv6 address, mask and gateway using SLAAC\n"
		"    {Hdhcp} [{UOPTION}]  Attempt to obtain IPv4 address, mask, gateway, DNS via DHCP\n"
		"          {H-d}         Show DHCP packet decode\n"
		"          {H-r}         Renew DHCP lease\n"
		"          {H-x}         Release DHCP lease\n"
		"    {Hdns} {Uip}         Set DNS server {Uip}, delete if {Uip} is '0'\n"
		"    {Hdns6} {Uipv6}       Set DNS server {Uipv6}, delete if {Uipv6} is '0'\n"
		"    {Hdomain} {UNAME}    Set local domain name to {UNAME}\n");

	return 1;
}

int help_load(int argc, char **argv)
{
	esc_prn("\n{Hload} [{UFILENAME}[.vpc]]\n"
		"  Load the configuration/script from the file {UFILENAME}. If {UFILENAME} ends with\n"
		"  '.vpc', then the '.vpc' can be omitted. If {UFILENAME} is omitted then \n"
		"  {Ustartup.vpc} will be loaded if it exists. When the file is loaded, each\n"
		"  line of the file is executed as a VPCS command. If the state of the echo flag\n"
		"  is on, the command will be echoed to the console before execution, except: \n"
		"  * If the command is prefixed with a '@' symbol (eg {H@set echo color red});\n"
		"  * If the command is an echo command;\n"
		"  * If the command is a sleep command \n"
		"    Note: The command {Hsleep 0} will be echoed if the echo flag is on\n"
		"  See {Hset echo} and {Hshow echo}\n\n"
		"  Note: Press Ctrl+C to interrupt the running script.\n");

	return 1;
}

int help_neighbor(int argc, char **argv)
{
	return 1;
}

int help_ping(int argc, char **argv)
{

	esc_prn("\n{Hping} {UHOST} [{UOPTION} ...]\n"
		"  Ping the network {UHOST}. {UHOST} can be an ip address or name\n"
		"    Options:\n"        
		"     {H-1}             ICMP mode, default\n"
		"     {H-2}             UDP mode\n"
		"     {H-3}             TCP mode\n"
		"     {H-c} {Ucount}       Packet count, default 5\n"
		"     {H-D}             Set the Don't Fragment bit\n"
		"     {H-f} {UFLAG}        Tcp header FLAG |{HC}|{HE}|{HU}|{HA}|{HP}|{HR}|{HS}|{HF}|\n"
		"                               bits |7 6 5 4 3 2 1 0|\n"
		"     {H-i} {Ums}          Wait {Ums} milliseconds between sending each packet\n"
		"     {H-l} {Usize}        Data size\n"
		"     {H-P} {Uprotocol}    Use IP {Uprotocol} in ping packets\n"
		"                      {H1} - ICMP (default), {H17} - UDP, {H6} - TCP\n"
		"     {H-p} {Uport}        Destination port\n"
		"     {H-s} {Uport}        Source port\n"
		"     {H-T} {Uttl}         Set {Uttl}, default 64\n"
		"     {H-t}             Send packets until interrupted by Ctrl+C\n"
		"     {H-w} {Ums}          Wait {Ums} milliseconds to receive the response\n\n"
		"  Notes: 1. Using names requires DNS to be set.\n"
		"         2. Use Ctrl+C to stop the command.\n");
		
	return 1;
}

int help_trace(int argc, char **argv)
{
	esc_prn("\n{Htrace} {UHOST} [{UOPTION} ...]\n"
		"  Print the path packets take to the network {UHOST}. {UHOST} can be an ip address or\n"
		"  name.\n"
		"    Options:\n"
		"      {H-P} {Uprotocol}    Use IP {Uprotocol} in trace packets\n"
		"                       {H1} - icmp, {H17} - udp (default), {H6} - tcp\n"
		"      {H-m} {Uttl}         Maximum {Uttl}, default 8\n\n"
		"  Notes: 1. Using names requires DNS to be set.\n"
		"         2. Use Ctrl+C to stop the command.\n");

	return 1;
}

int help_rlogin(int argc, char **argv)
{
	esc_prn("\n{Hrlogin} [{Uip}] {Uport}\n"
		"  Telnet to {Uport} at {Uip} (default 127.0.0.1) relative to host PC. \n"
		"  To attach to the console of a virtual router running on port 2000 of this\n"
		"  host PC, use {Hrlogin 2000}\n"
		"  To telnet to the port 2004 of a remote host 10.1.1.1, use\n"
		"  {Hrlogin 10.1.1.1 2004}\n");
		
	return 1;
}

int help_save(int argc, char **argv)
{
	esc_prn("\n{Hsave} [{UFILENAME}[.vpc]]\n"
		"  Save the configuration to the file {UFILENAME.vpc}. If there is no '.' in\n"
		"  {UFILENAME} then a '.vpc' extension is added. If {UFILENAME} is omitted then the\n"
		"  configuration will be saved to {Ustartup.vpc}\n");

	return 1;
}

int help_set(int argc, char **argv)
{
	if (argc == 3 && !strncmp(argv[1], "dump", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("\n{Hset dump} {Hall}|{Hdetail}|{Hfile}|{Hoff}|{Hmac}|{Hraw}\n"
			"  Set the packet dump flags for this VPC\n"
			"    {Hall}             All the packets including incoming\n"
			"                    must use {Udetail}|{Umac}|{Uraw} as well as 'all'\n"
			"    {Hdetail}          Print protocol\n"
			"    {Hfile}            Dump packets to file 'vpcs[id]_yyyymmddHHMMSS.pcap'\n"
			"    {Hmac}             Print harware MAC address\n"
			"    {Hoff}             Clear all the flags\n"
			"    {Hraw}             Print the first 40 bytes\n");
	
		return 1;
	}
	
	if (argc == 3 && !strncmp(argv[1], "echo", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("\n{Hset echo} {Hon}|{Hoff}|[{Hcolor} {Hclear}|{UFGCOLOR} [{UBGCOLOR}]]\n"
			"  Sets the state of the echo flag used when executing script files,\n"
			"  or sets the color of text to {UFGCOLOR} with optional {UBGCOLOR}\n"
			"  Color list: black, red, green, yellow, blue, magenta, cyan, white\n"
			"  See {Hload ?}.\n");
		
		return 1;
	}

	if (argc == 3 && !strncmp(argv[1], "mtu", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("\n{Hset mtu} {Uvalue}\n"
			"  Set the maximum transmission unit of the interface, at least 576.\n");

		return 1;
	}

	esc_prn("\n{Hset} {UARG} ...\n"
		"  Set hostname, connection port, ipfrag state, dump options and echo options\n"
		"    ARG:\n"
		"    {Hdump} {UFLAG} [[{UFLAG}]...]    Set the packet dump flags for this VPC. \n"
		"         FLAG:\n"
		"             {Hall}             All the packets including incoming.\n"
		"                               must use [detail|mac|raw] as well as 'all'\n"
		"             {Hdetail}          Print protocol\n"
		"             {Hfile}            Dump packets to file 'vpcs[id]_yyyymmddHHMMSS.pcap'\n"
		"             {Hoff}             Clear all the flags\n"		
		"             {Hmac}             Print hardware MAC address\n"
		"             {Hraw}             Print the first 40 bytes\n"
		"    {Hecho} {Hon}|{Hoff}|{Ucolor} ...    Set echoing options. See {Hset echo ?}\n"
		"    {Hlport} {Uport}               Local port\n"
		"    {Hmtu} {Uvalue}                Set the maximum transmission unit of the interface\n"
		"    {Hpcname} {UNAME}              Set the hostname of the current VPC to {UNAME}\n"
		"    {Hrport} {Uport}               Remote peer port\n"
		"    {Hrhost} {Uip}                 Remote peer host IPv4 address\n");
	
	return 1;
}

int help_shell(int argc, char **argv)
{
	esc_prn("\n{H!} {UCOMMAND} [{UARG} ...]\n"
		" Invoke an OS command {UCOMMAND} with optional [{UARG} ...] as arguments\n");

	return 1;
}

int help_show(int argc, char **argv)
{
	char *harp[2] = {
		"\n{Hshow arp} [{Udigit}|{Hall}]\n"
		"  Show arp table for VPC {Udigit} (default this VPC) or all VPCs\n",
		"\n{Hshow arp}\n"
		"  Show arp table\n"};
	char *hdump[2] = {
		"\n{Hshow dump} [{Udigit}|{Hall}]\n"
		"  Show dump flags for VPC {Udigit} (default this VPC) or all VPCs\n",
		"\n{Hshow dump}\n"
		"  Show dump flags\n"};
	char *hip[2] = {
		"\n{Hshow ip} [{Udigit}|{Hall}]\n"
		"  Show IPv4 details for VPC {Udigit} (default this VPC) or all VPCs, including\n"
		"  VPC Name, IP address, mask, gateway, DNS, MAC, lport, rhost:rport and MTU.\n",
		"\n{Hshow ip} [{Hall}]\n"
		"  Show IPv4 details for including:\n"
		"  VPC Name, IP address, mask, gateway, DNS, MAC, lport, rhost:rport and MTU.\n"
		"  (reduced view in tablular format if 'all' option used)\n"};
	char *hip6[2] = {
		"\n{Hshow ipv6} [{Udigit}|{Hall}]\n"
		"  Show IPv6 details for VPC {Udigit} (default this VPC) or all VPCs, including\n"
		"  VPC Name, IPv6 addresses/mask, router link-layer, MAC, lport, rhost:rport and\n"
		"  MTU\n",
		"\n{Hshow ipv6} [{Hall}]\n"
		"  Show IPv6 details, including:\n"
		"  VPC Name, IPv6 addresses/mask, router link-layer, MAC, lport, rhost:rport and\n"
		"  MTU (reduced view in tablular format if 'all' option used)\n"};
	char *hmtu[2] = {
		"\n{Hshow mtu6} [{Udigit}|{Hall}]\n"
		"  Show IPv6 mtu table for VPC {Udigit} (default this VPC) or all VPCs\n",
		"\n{Hshow mtu6}\n"
		"  Show IPv6 mtu table\n"};
	char *hh[3] = {
		"\n{Hshow} [{UARG}]\n"
		"  Show information for ARG\n"
		"    ARG:\n",
		"       {Harp} [{Udigit}|{Hall}]    Show arp table for VPC {Udigit} or all VPCs\n"
		"       {Hdump} [{Udigit}|{Hall}]   Show dump flags for VPC {Udigit} or all VPCs\n"
		"       {Hecho}               Show the status of the echo flag. See {Hset echo ?}\n"
		"       {Hhistory}            List the command history\n"
		"       {Hip} [{Udigit}|{Hall}]     Show IPv4 details for VPC {Udigit} or all VPCs\n"
		"                          shows VPC Name, IP address, mask, gateway, DNS, MAC, \n"
		"                          lport, rhost:rport and MTU\n"
		"       {Hipv6} [{Udigit}|{Hall}]   Show IPv6 details for VPC {Udigit} or all VPCs\n"
		"                          shows VPC Name, IPv6 addresses/mask, gateway, MAC,\n"
		"                          lport, rhost:rport and MTU\n"
		"       {Hmtu6} [{Udigit}|{Hall}]   Show IPv6 mtu table for VPC {Udigit} or all VPCs\n"
		"       {Hversion}            Show the version information\n\n"
		"  Notes: \n"
		"  1. If no parameter is given, the key information of all VPCs will be displayed\n"
		"  2. If no parameter is given for {Harp}/{Hdump}/{Hip}/{Hipv6} information for the\n"
		"     current VPC will be displayed.\n",
		"       {Harp}                Show arp table\n"
		"       {Hdump}               Show dump flags \n"
		"       {Hecho}               Show the status of the echo flag. See {Hset echo ?}\n"
		"       {Hhistory}            List the command history\n"
		"       {Hip} [{Hall}]           Show IPv4 details\n"
		"                          Shows VPC Name, IP address, mask, gateway, DNS, MAC, \n"
		"                          lport, rhost:rport and MTU\n"
		"       {Hipv6} [{Hall}]         Show IPv6 details\n"
		"                          Shows VPC Name, IPv6 addresses/mask, gateway, MAC,\n"
		"                          lport, rhost:rport and MTU\n"
		"       {Hversion}            Show the version information\n\n"
		"  Notes: \n"
		"  1. If no parameter is given, the key information of the current VPC will be\n"
		"     displayed\n"
		"  2. If 'all' parameter is given for {Hip}/{Hipv6} a reduced view in tablular\n"
		"     format will be displayed.\n"};

	if (argc == 3 && !strncmp(argv[1], "arp", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("%s", num_pths > 1 ? harp[0] : harp[1]);

		return 1;
	}
	
	if (argc == 3 && !strncmp(argv[1], "dump", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("%s", num_pths > 1 ? hdump[0] : hdump[1]);

		return 1;
	}

	if (argc == 3 && !strcmp(argv[1], "ip") && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("%s", num_pths > 1 ? hip[0] : hip[1]);
		
		return 1;
	}
	
	if (argc == 3 && !strcmp(argv[1], "ipv6") && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("%s", num_pths > 1 ? hip6[0] : hip6[1]);
		
		return 1;
	}
	
	if (argc == 3 && !strncmp(argv[1], "mtu6", strlen(argv[1])) && 
	    (!strcmp(argv[2], "?") || !strncmp(argv[2], "help", strlen(argv[2])))) {
		esc_prn("%s", num_pths > 1 ? hmtu[0] : hmtu[1]);

		return 1;
	}
	
	if (argc > 1 && 
	    (!strcmp(argv[argc - 1], "?") || !strncmp(argv[argc - 1], "help", strlen(argv[argc - 1])))) {
		esc_prn("%s", hh[0]);
		esc_prn("%s", num_pths > 1 ? hh[1] : hh[2]);
		
		return 1;
	}
	
	return 0;	
}

int help_version(int argc, char **argv)
{
	return 1;
}

int help_sleep(int argc, char **argv)
{
	esc_prn("\n{Hsleep} [{Useconds}] [{Utext}]\n"
		"  Print {Utext} and pause execution of script for {Utime} seconds.\n"
		"  If {Useconds} is zero or missing, pause until a key is pressed. \n"
		"  Default text when no parameters given: 'Press any key to continue'\n"
		"  See {Hload} [{Ufilename}]\n");

	return 1;
}

int help_help(int argc, char **argv)
{
	esc_prn("\n{H%s}, Print help. Use {UCOMMAND} {H?} or "
		"{HCOMMAND} {UARG} {H?} for more help\n", argv[0]);

	return 1;
}

int help_shut(int argc, char **argv)
{
	esc_prn("\n{H%s}, shutdown the process (only in daemon mode)\n", argv[0]);

	return 1;
}

int run_help(int argc, char **argv) 
{
	esc_prn("\n"
		"{H?}                        Print help\n"
		"{H!} {UCOMMAND} [{UARG} ...]      Invoke an OS {UCOMMAND} with optional {UARG(s)}\n");
	
	if (num_pths > 1) {
		esc_prn("{Udigit}                    Switch to the VPC{Udigit}. "
			"{Udigit} range 1 to %d\n", num_pths); 
	}
	
	esc_prn("{Harp} %s          Shortcut for: {Hshow arp}. "
		"Show arp table\n", (num_pths > 1) ? "[{Udigit}|{Hall}]" : "             ");
	esc_prn("{Hclear} {UARG}                Clear IPv4/IPv6, arp/neighbor cache, command history\n"
		"{Hdhcp} [{UOPTION}]            Shortcut for: {Hip dhcp}. Get IPv4 address via DHCP\n"
		"{Hdisconnect}               Exit the telnet session (daemon mode)\r\n"
		"{Hecho} {UTEXT}                Display {UTEXT} in output. See also  {Hset echo ?}\n"
		"{Hhelp}                     Print help\n"
		"{Hhistory}                  Shortcut for: {Hshow history}. List the command history\n"
		"{Hip} {UARG} ... [{UOPTION}]      Configure the current VPC's IP settings. See {Hip ?}\n"
		"{Hload} [{UFILENAME}]          Load the configuration/script from the file {UFILENAME}\n"
		"{Hping} {UHOST} [{UOPTION} ...]   Ping {UHOST} with ICMP (default) or TCP/UDP. See {Hping ?}\n"
		"{Hquit}                     Quit program\n"
		"{Hrelay} {UARG} ...            Configure packet relay between UDP ports. See {Hrelay ?}\n"
		"{Hrlogin} [{Uip}] {Uport}         Telnet to {Uport} on host at {Uip} (relative to host PC)\n"
		"{Hsave} [{UFILENAME}]          Save the configuration to the file {UFILENAME}\n"
		"{Hset} {UARG} ...              Set VPC name and other options. Try {Hset ?}\n"
		"{Hshow} [{UARG} ...]           Print the information of VPCs (default). See {Hshow ?}\n"
		"{Hsleep} [{Useconds}] [TEXT]   Print TEXT and pause running script for {Useconds}\n"
		"{Htrace} {UHOST} [{UOPTION} ...]  Print the path packets take to network {UHOST}\n"
		"{Hversion}                  Shortcut for: {Hshow version}\n\n"
		"To get command syntax help, please enter '{H?}' as an argument of the command.\n");
	
	return 1;
}

/* end of file */
