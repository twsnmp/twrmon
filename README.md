# twrmon
SNMP RMON Probe for TWSNMP

## Overview

RMON probe software that makes network information available via SNMP by means of packet capture.

パケットキャプチャーによってネットワークの情報をSNMPで取得可能にするRMONプローブのソフトです。

## Status

v1.0.0 Release
v1.0.0をリリースしました。(2022/11/08)  

## Build

To build on Debian, net-snmp and pcap libraries are required. Install them with the following commands.

Debian上でビルドするためには、net-snmpとpcapのライブラリなどが必要です。以下のコマンドでインストールします。

```
apt-get update 
apt-get install -y build-essential git libpcap-dev libsnmp-dev snmpd
```

Clone source code from git.
スースコードをgitからcloneします。

```
git clone https://github.com/twsnmp/twrmon.git
```
You can build it with the make command.

makeコマンドでビルドできます。

```
make
```

## Run

Start the SNMP agent of NET-SNMP as master of AgentX.
If you find the following line in /etc/snmp/snmpd.conf, you are OK.

NET-SNMPのSNMPエージェントをAgentXのmasterとして起動してください。
/etc/snmp/snmpd.confに、以下の行があれば、OKです。

```
#
#  AgentX Sub-agents
#
                                           #  Run as an AgentX master agent
 master          agentx
                                           #  Listen for network connections (from localhost)
                                           #    rather than the default named socket /var/agentx/master
```

start
起動
```
twrmon -i eth0
```


Parameters
起動パラメータ

```
usage: twrmond [-i <Monitor IF>] [-D<tokens>] [-f] [-L] [-M] [-H] [-v] [-s <Scan Level>] [-T <TimemarkMode>] [LISTENING ADDRESSES]
	-f      Do not fork() from the calling shell.
	-v      Show version
	-s <Scan Level>  0:Data Link(Ether) 1:Network(IP) 2:Application
	-DTOKEN[,TOKEN,...]
		Turn on debugging output for the given TOKEN(s).
		Without any tokens specified, it defaults to printing
		all the tokens (which is equivalent to the keyword 'ALL').
		You might want to try ALL for extremely verbose output.
		Note: You can't put a space between the -D and the TOKENs.
	-H	Display a list of configuration file directives
		understood by the agent and then exit.
	-M	Run as a normal SNMP Agent instead of an AgentX sub-agent.
	-x ADDRESS	connect to master agent at ADDRESS (default /var/agentx/master).
	-L	Do not open a log file; print all messages to stderr.
```

## Copyright

see ./LICENSE

```
Copyright 2007-2022 Masayuki Yamai
```
