# EFknockr

## WARNING: This is simply a PROOF-OF-CONCEPT that outlines major flaws in how we use IRC currently!

![](.screens/gun.png)

## WARNING: This repository was made for testing against your own server(s). I am not responsible for the public use.

## Information
This is basically an IRC drive-by. It takes a list of IRC servers, connects to all of them & joins every channel to send a custom message. You can also have it mass highlight & mass private message the channels for more attention to your message. It will do various things to make sure it does not get banned, throttled, or detected.

Proxy scanning is included as an option, which will find thousands of new proxies on every loop. Combine that with the daemon mode *(24/7 knocking)* & this becomes un-stoppable. Tied with a residential proxy service & this becomes a problem.

The humor behind this script is that anyone can mass portscan **0.0.0.0/0** *(the entire IPv4 range)* for port **6667** & essentially send a message to every IRC server on the internet. **But I have heard a rumor that doing so will only affect channels that are boring, lame, & shitty :) :) :)**

I am not going to get into how to set this up or use it. This is simply here to serve as a proof-of-concept.

## Previews
Here are some examples of people using EFknockr:

![](.screens/driveby.png)

## Disclaimer
The proof-of-concept here is a classic example of the on going problem wtih using standard ports for known services on IPv4.

Both SSH & Telnet world-wide get thousands of login attempts daily because of this. IRC is no different & is certainly not excluded from this problem.

**Welcome to the fucking state of the Internet boyz**

I am well aware that people might use this script for malicious purposes....as they should. We cannot just be oblivious to major problems with networked services. IRC is a very small space in modern day. Becasue of that, it seems like setting up an IRCd is all people cared to learn...skipping over what it means to be a network operator.

**It is no different than being a sysadmin**

I have dealt with IRC flooding for years. Most times, I rarely have to tocuh the keyboard to handle it. Everything is laid out in the IRCd documentation. Big shout outs to [UnrealIRCd](https://www.unrealircd.org/) for ~~being the BEST FUCKING IRC DAEMON EVER!~~

Anyways...at the end of the day...it is text on a screen. It is just **text** on a **screen**. Quite often lost in the backlog after a short period...

###### Todo
* Invite support
* Parse `MAXTARGETS` & `MAXCHANNELS` from **005** responses for fine tuned spamming
* UTF-16 Bot crashing for improper unicode decoding
* Weechat DCC buffer-overlfow exploit *(See [here](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8073))*
* OpenSSL crash exploit *(See [here](https://forums.unrealircd.org/viewtopic.php?f=1&t=9085))*
* `/LIST` tarpit detection & evasion
* Scramble the order of operations to be entirely random to thwart fingerprinting
* Drop unicode for normal letters to thwart spamfilters
* Add unifuck option
* Do not knock on channels we registered

___

###### Mirrors
[acid.vegas](https://git.acid.vegas/efknockr) • [GitHub](https://github.com/acidvegas/efknockr) • [GitLab](https://gitlab.com/acidvegas/efknockr) • [SourceHut](https://git.sr.ht/~acidvegas/efknockr) • [SuperNETs](https://git.supernets.org/acidvegas/efknockr)
