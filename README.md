#### Copyright 2024 Stoica Mihai-Bogdan 325CA (bogdanstoicasn@yahoo.com)

# Project Dataplane Router

## Overview

A router consists of 2 things:

> - a control plane where routing algorithms are implemented
(RIP, OSPF, BGP, etc.)

> - a data plane where the actual routing is done

In this project we only implement the data plane of a router.

## Table of contents

- [Overview](#Overview)
- [Table of contents](#Table-of-contents)
- [ICMP](#ICMP)
- [ARP](#ARP)
- [IP](#IP)
- [Design choices](#Design-choices)
- [How to run](#How-to-run)
- [Acknowledgements](#Acknowledgements)
- [Resources](#Resources)


## ICMP

ICMP (Internet Control Message Protocol) is a protocol used to send error
messages and operational information indicating, for example, that a requested
service is not available or that a host or router could not be reached.

In this project we have 3 types of ICMP responses:

> - **`ICMP echo request/reply`**

> - **`ICMP time exceeded(code 11)`**

> - **`ICMP destination unreachable(code 3)`**

All the functionalities above are implemented in the function
`send_icmp_packet`.

If the router ip is the same as the one in the packet, the router will send an
echo reply to the sender. We do the checking in the `send_ip_packet` function.

Both the time exceeded and destination unreachable are implemented in the
function `send_icmp_packet`. Here we create the icmp body in which we add 64
bytes of the ip packet that caused the error. The icmp header has 8 bytes.
The function is called inside `ip_packet_for_host` when the TTL is 0 or the
destination ip is not in the routing table.

## ARP

ARP (Address Resolution Protocol) is a protocol used for mapping an IP address
to a MAC address that is recognized in the local network.

The arp related functions are `send_arp_packet`
and `send_arp_request`. The second function is used when we don't have the
mac address of the destination ip. We put the packet in the queue and we send
an arp request to the destination ip(mac from final destination back to the
source). The first function handles the reply (dequeues the packet and sends
it) and normal arp packets.

## IP

IP (Internet Protocol) is a protocol used for sending packets from one host
to another.

Common points between the ip related functions:

- checksum calculation and verification

- field completition

Different points between the ip related functions:

- `ip_packet_for_host`: searching best route using binary search and longest
prefix match, inserting the arp packet in the queue if needed
(macs not in cache).

## Design choices

Some of the design choices are:

- using binary search and qsort for searching the best route

- using a queue for the arp packets

- using a rudimentary memory pool for handling some of the allocations(speeds
up the program by reducing the number of mallocs)

- using an array for the routing table
that has exactly the number of entries needed(`alloc_rtable`)

- caching the mac addresses

## How to run

For all tests use -> **./checker/checker.sh**

For 1 test use -> **sudo python3 checker/topo.py run name_of_test**

For debugging use -> **hosts_output** directory.
Every test has some **.err**, some **.out** files and a **.pcap** file for
debugging. The **.pcap** file can be opened with wireshark(use sudo guyzz).

## Acknowledgements

I would like to thank the PCOM team of UPB ACS for providing the necessary
resources for this project. The checker is very easy to use and the tests are very well structured.

## Resources

- [Book: Computer Networks - A Tanenbaum](https://www.amazon.com/Computer-Networks-5th-Andrew-Tanenbaum/dp/0132126958)
- [Playlist](https://youtube.com/playlist?list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW&si=5J23PKLih33J-OsU)
- [Basic Information](https://networkdirection.net/articles/network-theory/controlanddataplane/)

