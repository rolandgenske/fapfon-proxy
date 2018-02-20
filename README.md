# fapfon-proxy

Workaround for FRITZ!App Fon SIP via VPN

FRITZ!Box and FRITZ!App Fon are trademarks of AVM Computersysteme Vertriebs GmbH, Berlin, Germany.

## Table of contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Technical Details](#technical-details)
- [Command Line Usage](#command-line-usage)
- [Copyright and License](#copyright-and-license)

## Introduction

This is a special proxy to use FRITZ!App Fon via VPN. It manages multiple simultaneous FRITZ!App Fon connections, provided that each uses a different FRITZ!Box phone device user name.

In my home network I already have a Raspberry Pi acting as OpenVPN server, so I thought it should be possible to use FRITZ!App Fon remotely via OpenVPN. It worked to a certain degree, the registration process succeeded, but I could not hear any audio on outgoing calls, and the Fon app did not ring on incoming calls.

If you are interested in the technical details, see [below](#technical-details).

I could not use the IPsec-based FRITZ!Box VPN functionality because it requires a public IPv4 address which I don't have because my internet connection uses Dual-Stack Lite (DS Lite) technology which tunnels IPv4 over IPv6.

## Installation

Install fapfon-proxy on the system where your VPN server runs. The tested configuration is Raspbian 9 (stretch) with gcc 6.3.0. You can run it on your Box with Freetz if this is where your VPN server is located.

The example below clones the repository into the `/usr/local/src/fapfon-proxy` directory:

```
cd /usr/local/src/
git clone https://github.com/rolandgenske/fapfon-proxy.git
cd fapfon-proxy/
make
```

The installation I suggest uses a systemd service which invokes the `fapfon-proxy.nat` script to setup/cleanup either port redirection or destination NAT before fapfon-proxy is started and after it is stopped.

Port redirection is used if you run fapfon-proxy on your Box. Destination NAT is used if you run fapfon-proxy on a separate system with your VPN server.

Now install the fapfon-proxy executable along with the scripts and the configuration file:

```
cp -p fapfon-proxy /usr/local/bin/
cp -p install/fapfon-proxy.nat /usr/local/bin/
cp -p install/fapfon-proxy.service /etc/systemd/system/
cp -p install/fapfon-proxy /etc/default/
```

Next, reload the systemd manager configuration and enable the fapfon-proxy service:

```
systemctl daemon-reload
systemctl enable fapfon-proxy.service
```

Before starting the service, edit the `/etc/default/fapfon-proxy` configuration. Change `BOX=` to the Fritz!Box address in your network, change `VPN=` to the address range(s) of your VPN clients. The configuration example shows my two separate address ranges, one for OpenVPN TCP clients and the other for UDP clients.

If you run fapfon-proxy on your Box you need to uncomment the `SIP_REDIRECT_PORT=` setting so that fapfon-proxy binds to TCP/UDP ports other than 5060 (sip). The configuration example uses port 6060, use a different port number if 6060 is already in use.

If you want to see connect/disconnect messages in the log file, configure `OPTIONS="--verbose=2"`.

Then start the service:

```
systemctl start fapfon-proxy.service
```

Check the log file whether fapfon-proxy has been started. If you have `OPTIONS="--verbose=2"` configured you can use this to watch while your FRITZ!App Fon connects and disconnects:

```
tail -f /var/log/fapfon-proxy.log
```

To check how port redirection or destination NAT is set up, use:

```
iptables -t nat -L PREROUTING
```

## Technical Details

This is a dump of the initial SIP REGISTER message FRITZ!App Fon sends to my Box. The involved addresses are:

- **10.64.72.11** : private mobile phone provider address (Telekom), FRITZ!App Fon binds to TCP/UDP port **61211**
- **172.20.11.6** : address of OpenVPN endpoint on mobile phone, TCP message sent from port **62895**
- **172.30.10.1** : Box address in my network, TCP message sent to SIP port **5060**
- **172.30.10.2** : Address of the Raspberry Pi in my network, running the VPN server and fapfon-proxy

```
REGISTER sip:172.30.10.1;transport=TCP SIP/2.0\r\n
Via: SIP/2.0/TCP 172.20.11.6:61211;rport;branch=***;alias\r\n
Max-Forwards: 70\r\n
From: <sip:USERNAME@172.30.10.1>;tag=***\r\n
To: <sip:USERNAME@172.30.10.1>\r\n
Call-ID: ***\r\n
CSeq: 24441 REGISTER\r\n
User-Agent: FRITZ!AppFon/2549 sip/1.16.0\r\n
Supported: outbound, path\r\n
Contact: <sip:USERNAME@10.64.72.11:61211;transport=TCP;ob>;reg-id=1;+sip.instance="<urn:uuid:***>"\r\n
Expires: 900\r\n
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n
Content-Length:  0\r\n
\r\n
```

The main problem here is that _Contact_ uses the private mobile phone provider address **10.64.72.11** which does not route back to FRITZ!App Fon via OpenVPN and furthermore cannot be reached on the Internet. This is the reason why incoming calls cannot be routed to the Fon app.

If this would be the originating **172.20.11.6** address with port **62895** all would be fine.

Next comes a dump of a SIP INVITE message FRITZ!App Fon sends to my Box to initiate an outgoing call. This time I focus on the SDP data only:

```
INVITE sip:PHONENUMBER@172.30.10.1;transport=TCP SIP/2.0\r\n
...
Content-Type: application/sdp\r\n
Content-Length:   295\r\n
\r\n
v=0\r\n
o=- 3727522826 3727522826 IN IP4 10.64.72.11\r\n
s=pjmedia\r\n
c=IN IP4 10.64.72.11\r\n
t=0 0\r\n
a=X-nat:0\r\n
m=audio 4000 RTP/AVP 8 0 3 101\r\n
a=rtcp:4001 IN IP4 10.64.72.11\r\n
a=rtpmap:8 PCMA/8000\r\n
a=rtpmap:0 PCMU/8000\r\n
a=rtpmap:3 GSM/8000\r\n
a=sendrecv\r\n
a=rtpmap:101 telephone-event/8000\r\n
a=fmtp:101 0-15\r\n
```

Here, the originator / session identifier `o=` and the connection info `c=` as well as the RTP attribute `a=rtcp` all refer to the private mobile phone provider address **10.64.72.11**, which is why RTP audio does not route back to FRITZ!App Fon via OpenVPN. The Box routes it to the Internet where it gets lost because the private **10.64.72.11** address cannot be reached.

So the goal is to modify the messages, which is what fapfon-proxy does. In the example above it replaces the **10.64.72.11[:61211]** address in the SIP header with the fapfon-proxy local address and TCP/UDP port, so that SIP responses go back through the proxy, which then reverts the address replacement before the message is sent to the Fon app.

Furthermore, in SDP data it replaces the **10.64.72.11** address with the FRITZ!App Fon OpenVPN endpoint address (**172.20.11.6** in this example) so that RTP audio goes directly to the Fon app, no need to send it through the proxy.

For messages from FRITZ!App Fon we do not touch the SIP _Via_ header line, but on its way back the Box has added the _rport_ field (RFC 3581) using the fapfon-proxy local TCP/UDP port:

```
Via: SIP/2.0/TCP 172.20.11.6:61211;rport=43202;branch=***;alias;received=172.30.10.2\r\n
```

Before sending this to the Fon app the _rport_ is replaced with the original _Via_ port, otherwise FRITZ!App Fon won't accept this message:

```
Via: SIP/2.0/TCP 172.20.11.6:61211;rport=61211;branch=***;alias;received=172.30.10.2\r\n
```

The _USERNAME_ identifier obtained in the initial SIP REGISTER message is used to manage individual address/port replacement for multiple simultaneous connections from different devices. Set `--verbose=3` to see this in the log.

## Command Line Usage

```
usage: fapfon-proxy [options] BOX_ADDRESS[:SIP_PORT]
SIP_PORT default: 5060
options:
  -h            --help             This list
  -p PORT       --port=PORT        Server SIP_PORT, TCP and UDP
  -t PORT       --tcp-port=PORT    Server SIP_PORT, TCP
  -u PORT       --udp-port=PORT    Server SIP_PORT, UDP
  -v [level]    --verbose[=level]  Verbosity 0:ERROR 1:INFO 2:DETAIL 3:VERBOSE
  -l LOGFILE    --logfile=LOGFILE  Log file or - (stdout), default: stderr
  -D {FON|BOX}  --dump={FON|BOX}   Dump FON/BOX messages to stdout
  -V            --version          Version information
```

## Copyright and license

(C) 2018 by Roland Genske. Code released under the terms of the GNU General Public License version 2 as published by the Free Software Foundation. Please refer to the file `COPYING` for details.
