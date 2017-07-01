# Packet-Decapsulation

**Usage: python2 main.py <tcp|udp|icmp|ip|eth>**

An early prototype of a decapsulation module written in pure Python with sockets, thusfar supports layer inspection for TCP, UDP, ICMP packets, IP headers and Ethernet frames.
In its current state I do not plan on extending or planning more features upon it unless it's deemable as a necessity.

Latest version finally implements graphing for packets received over each second.

![scan example](http://i.imgur.com/utLIjAa.png)

Above example shows of the traffic sent & received from the [Masscan](https://github.com/robertdavidgraham/masscan) tool.
Under settings 

`masscan -p 80 --range 192.168.0.0/8 --rate 10000000`
