#!/usr/bin/env python
# efknockr (internet relay chat beacon) - developed by acidvegas in python (https://git.acid.vegas/efknockr)

import asyncio
import ipaddress
import os
import random
import re
import ssl
import sys
import time
import urllib.request

class settings:
	chan_first           = False          # Finish knocking channels before sending private messages
	confuse              = True           # Use unicode confusables in messages to avoid spamfilters
	daemon               = False          # Run in daemon mode (24/7 throttled knocking)
	errors               = True           # Show errors in console
	errors_conn          = False          # Show connection errors in console
	exploits             = False          # Use a exploit payloads
	mass_hl              = True           # Hilite all the users in a channel before parting
	part_msg             = 'Smell ya l8r' # Send a custom part message when leaving channels
	proxies              = False          # Connect with proxies
	proxies_only         = False          # Only connect with proxies
	proxies_scan         = False          # Scan for new proxies
	proxies_local        = False          # Use proxies from proxies.txt
	register             = True           # Register with NickServ before joining channels
	register_chan        = '#EFKnockr'    # Set to None to disable channel registrations
	register_chan_topic = 'EFK'           # Topic to set for the registered channel

class throttle:
	channels  = 3   if not settings.daemon else 2   # Maximum number of channels to knock at once
	connect   = 15  if not settings.daemon else 60  # Delay between each connection attempt on a diffferent port
	delay     = 300 if not settings.daemon else 600 # Delay before registering nick (if enabled) & sending /LIST
	jdelay    = 3   if not settings.daemon else 10  # Delay before messaging a channel
	join      = 10  if not settings.daemon else 30  # Delay between channel JOINs
	message   = 1.5 if not settings.daemon else 3   # Delay between each message sent
	nick      = 300 if not settings.daemon else 600 # Delay between every random NICK change
	nicks     = 5   if not settings.daemon else 15  # Delay between each nick private messaged
	private   = 5   if not settings.daemon else 15  # Delay between private messages
	pthreads  = 500 if not settings.daemon else 300 # Maximum number of threads for proxy checking
	ptimeout  = 15  if not settings.daemon else 30  # Timeout for all sockets
	seconds   = 300 if not settings.daemon else 600 # Maximum seconds to wait when throttled for JOIN or PM
	users     = 10  if not settings.daemon else 5   # Minimum number of users in a channel to knock
	threads   = 500 if not settings.daemon else 50  # Maximum number of threads running
	timeout   = 30  if not settings.daemon else 60  # Timeout for all sockets
	ztimeout  = 200 if not settings.daemon else 300 # Timeout for zero data from server ;) ;) ;)

messages = (
	'This message has been brought to you by EFknockr!',
	'WHAT IS UP PORT 6667!?',
	['multi','lined','message','example'],
	['cant','    stop','        me','cause','    im a','        pumper'],
	'b i g   a c i d v e g a s   h a s   u'
)

class bad:
	donotscan = (
		'irc.terahertz.net', '165.254.255.25', '2001:728:1808::25',
		'irc.dronebl.org',       'irc.alphachat.net',
		'5.9.164.48',            '45.32.74.177',          '104.238.146.46',               '149.248.55.130',
		'2001:19f0:6001:1dc::1', '2001:19f0:b001:ce3::1', '2a01:4f8:160:2501:48:164:9:5', '2001:19f0:6401:17c::1'
	)
	chan = {
		'403' : 'ERR_NOSUCHCHANNEL',    '405' : 'ERR_TOOMANYCHANNELS',
		'435' : 'ERR_BANONCHAN',        '442' : 'ERR_NOTONCHANNEL',
		'448' : 'ERR_FORBIDDENCHANNEL', '470' : 'ERR_LINKCHANNEL',
		'471' : 'ERR_CHANNELISFULL',    '473' : 'ERR_INVITEONLYCHAN',
		'474' : 'ERR_BANNEDFROMCHAN',   '475' : 'ERR_BADCHANNELKEY',
		'476' : 'ERR_BADCHANMASK',      '477' : 'ERR_NEEDREGGEDNICK',
		'479' : 'ERR_BADCHANNAME',      '480' : 'ERR_THROTTLE',
		'485' : 'ERR_CHANBANREASON',    '488' : 'ERR_NOSSL',
		'489' : 'ERR_SECUREONLYCHAN',   '519' : 'ERR_TOOMANYUSERS',
		'520' : 'ERR_OPERONLY',         '926' : 'ERR_BADCHANNEL'
	}
	error = {
		'install identd'                 : 'Identd required',
		'trying to reconnect too fast'   : 'Throttled',
		'trying to (re)connect too fast' : 'Throttled',
		'reconnecting too fast'          : 'Throttled',
		'access denied'                  : 'Access denied',
		'not authorized to'              : 'Not authorized',
		'not authorised to'              : 'Not authorized',
		'password mismatch'              : 'Password mismatch',
		'dronebl'                        : 'DroneBL',
		'dnsbl'                          : 'DNSBL',
		'g:lined'                        : 'G:Lined',
		'z:lined'                        : 'Z:Lined',
		'timeout'                        : 'Timeout',
		'closing link'                   : 'Banned',
		'banned'                         : 'Banned',
		'client exited'                  : 'QUIT',
		'quit'                           : 'QUIT'
	}

# Globals
all_proxies  = list()
good_proxies = list()

def confuse(data):
	if settings.confuse:
		chars = ''
		for char in data:
			if random.choice((True,False,False)):
				if char == ' ':
					chars += '\u00A0'
				elif char.lower() in ('abcdefghijklmnopqrstvwyz'):
					chars += char + random.choice(('\u200B','\u2060','\x0f','\x03\x0f'))
				else:
					chars += char
			else:
				chars += char
		return ''.join(chars)
	else:
		return data

def debug(data):
	print('{0} \033[1;30m|\033[0m [\033[35m~\033[0m] {1}'.format(time.strftime('%I:%M:%S'), data))

def error(data, reason=None):
	if settings.errors:
		print('{0} \033[1;30m|\033[0m [\033[31m!\033[0m] {1} \033[1;30m({2})\033[0m'.format(time.strftime('%I:%M:%S'), data, str(reason))) if reason else print('{0} \033[1;30m|\033[0m [\033[31m!\033[0m] {1}'.format(time.strftime('%I:%M:%S'), data))

def get_proxies():
	urls = (
		'https://find-your-own-proxies.com/socks5.txt',
		'https://find-your-own-proxies.com/socks5.txt',
		'https://find-your-own-proxies.com/socks5.txt'
	)
	proxies = list()
	for url in urls:
		try:
			req = urllib.request.Request(url)
			req.add_header('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
			source  = urllib.request.urlopen(req, timeout=10).read().decode()
			proxies+= list(set([proxy for proxy in re.findall('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+', source, re.MULTILINE) if proxy not in proxies]))
		except Exception as ex:
			error('failed to grab new proxies!', ex)
	return proxies if proxies else False

async def check_proxy(semaphore, proxy):
	async with semaphore:
		ip, port = proxy.split(':')
		options = {
			'proxy'      : aiosocks.Socks5Addr(proxy.split(':')[0], int(proxy.split(':')[1])),
			'proxy_auth' : None,
			'dst'        : ('www.google.com',80),
			'limit'      : 1024,
			'ssl'        : None,
			'family'     : 2
		}
		try:
			await asyncio.wait_for(aiosocks.open_connection(**options), throttle.ptimeout)
		except:
			pass
		else:
			debug('\033[1;32mGOOD\033[0m \033[1;30m|\033[0m ' + proxy)
			if ip not in all_proxies:
				all_proxies.append(ip)
				good_proxies.append(proxy)

def rndnick():
	prefix = random.choice(['st','sn','cr','pl','pr','fr','fl','qu','br','gr','sh','sk','tr','kl','wr','bl']+list('bcdfgklmnprstvwz'))
	midfix = random.choice(('aeiou'))+random.choice(('aeiou'))+random.choice(('bcdfgklmnprstvwz'))
	suffix = random.choice(['ed','est','er','le','ly','y','ies','iest','ian','ion','est','ing','led','inger']+list('abcdfgklmnprstvwz'))
	return prefix+midfix+suffix

def ssl_ctx():
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	return ctx

class probe:
	def __init__(self, semaphore, server, proxy=None):
		self.semaphore = semaphore
		self.server    = server
		self.proxy     = proxy
		self.display   = server.ljust(18)+' \033[1;30m|\033[0m unknown network           \033[1;30m|\033[0m '
		self.nickname  = rndnick()
		self.channels  = {'all':list(), 'current':list(), 'users':dict(), 'bad':list()}
		self.nicks     = {'all':list(), 'chan':dict(),    'check':list(), 'bad':list()}
		self.loops     = {'init':None, 'chan':None, 'nick':None, 'pm':None}
		self.jthrottle = throttle.join
		self.nthrottle = throttle.private
		self.reader    = None
		self.write     = None

	async def sendmsg(self, target, msg):
		await self.raw(f'PRIVMSG {target} :{msg}')

	async def run(self):
		async with self.semaphore:
			try:
				await self.connect() # 6697
			except Exception as ex:
				if settings.errors_conn:
					error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect using SSL/TLS!', ex)
				await asyncio.sleep(throttle.connect)
				try:
					await self.connect(True) # 6667
				except Exception as ex:
					if settings.errors_conn:
						error(self.display + '\033[1;31mdisconnected\033[0m - failed to connect!', ex)

	async def raw(self, data):
		self.writer.write(data[:510].encode('utf-8') + b'\r\n')
		await self.writer.drain()

	async def connect(self, fallback=False):
		if self.proxy:
			auth = self.proxy.split('@')[0].split(':') if '@' in self.proxy else None
			proxy_ip, proxy_port = self.proxy.split('@')[1].split(':') if '@' in self.proxy else self.proxy.split(':')
			options = {
				'proxy'      : aiosocks.Socks5Addr(proxy_ip, proxy_port),
				'proxy_auth' : aiosocks.Socks5Auth(*auth) if auth else None,
				'dst'        : (self.server,6667) if fallback else (self.server,6697),
				'limit'      : 1024,
				'ssl'        : None if fallback else ssl_ctx(),
				'family'     : 2
			}
			self.reader, self.writer = await asyncio.wait_for(aiosocks.open_connection(**options), throttle.timeout)
		else:
			options = {
				'host'   : self.server,
				'port'   : 6667 if fallback else 6697,
				'limit'  : 1024,
				'ssl'    : None if fallback else ssl_ctx(),
				'family' : 2
			}
			self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(**options), throttle.timeout)
		del options
		await self.raw('USER {0} 0 * :{1}'.format(rndnick(), rndnick()))
		await self.raw('NICK ' + self.nickname)
		await self.listen()
		for item in self.loops:
			if self.loops[item]:
				self.loops[item].cancel()
		debug(self.display + 'finished knocking')

	async def loop_initial(self):
		try:
			await asyncio.sleep(throttle.delay)
			mail = rndnick() + '@' + random.choice(('gmail.com','hotmail.com','yahoo.com','outlook.com','protonmail.com','mail.com',rndnick()+random.choice(('com','org','net'))))
			cmds = [f'PRIVMSG NickServ :REGISTER {rndnick()} {mail}', 'LIST']
			for command in cmds:
				try:
					await self.raw(command)
				except:
					break
				else:
					await asyncio.sleep(3)
			if not self.channels['all']:
				error(self.display + '\033[31merror\033[0m - no channels found')
				await self.raw('QUIT')
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_initial', ex)

	async def loop_channels(self):
		try:
			while self.channels['all']:
				while len(self.channels['current']) >= throttle.channels:
					await asyncio.sleep(1)
				await asyncio.sleep(self.jthrottle)
				chan = random.choice(self.channels['all'])
				self.channels['all'].remove(chan)
				try:
					await self.raw('JOIN ' + chan)
				except:
					break
			if settings.chan_first:
				self.loops['pm'] = asyncio.create_task(self.loop_private())
			while self.nicks['check']:
				await asyncio.sleep(1)
			self.loops['nick'].cancel()
			self.loops['pm'].cancel()
			await self.raw('QUIT')
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_channels', ex)

	async def loop_nick(self):
		try:
			while True:
				await asyncio.sleep(throttle.nick)
				self.nickname = rndnick()
				await self.raw('NICK ' + self.nickname)
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_nick', ex)

	async def loop_private(self):
		try:
			while True:
				if self.nicks['check']:
					nick = random.choice(self.nicks['check'])
					self.nicks['check'].remove(nick)
					try:
						msg = random.choice(messages)
						if type(msg) == list:
							for i in msg:
								if nick in self.nicks['bad']:
									self.nicks['bad'].remove(nick)
									break
								else:
									await self.sendmsg(nick, confuse(i))
									await asyncio.sleep(throttle.message)
						else:
							await self.sendmsg(nick, confuse(msg))
					except:
						break
					else:
						del nick
						await asyncio.sleep(throttle.nicks)
				else:
					await asyncio.sleep(1)
		except asyncio.CancelledError:
			pass
		except Exception as ex:
			error(self.display + '\033[31merror\033[0m - loop_private', ex)

	async def listen(self):
		while True:
			try:
				if self.reader.at_eof():
					break
				data  = await asyncio.wait_for(self.reader.readuntil(b'\r\n'), throttle.ztimeout)
				line  = data.decode('utf-8').strip()
				args  = line.split()
				event = args[1].upper()
				if event in bad.chan and len(args) >= 4:
					chan = args[3]
					if chan in self.channels['users']:
						del self.channels['users'][chan]
					if chan in self.nicks['chan']:
						del self.nicks['chan'][chan]
					error(f'{self.display}\033[31merror\033[0m - {chan}', bad.chan[event])
				elif line.startswith('ERROR :'):
					check = [check for check in bad.error if check in line.lower()]
					if check:
						raise Exception(bad.error[check[0]])
				elif args[0] == 'PING':
					await self.raw('PONG ' + args[1][1:])
				elif event == '001': #RPL_WELCOME
					host = args[0][1:]
					if len(host) > 25:
						self.display = f'{self.server.ljust(18)} \033[1;30m|\033[0m {host[:22]}... \033[1;30m|\033[0m '
					else:
						self.display = f'{self.server.ljust(18)} \033[1;30m|\033[0m {host.ljust(25)} \033[1;30m|\033[0m '
					debug(self.display + f'\033[1;32mconnected\033[0m')
					self.loops['init'] = asyncio.create_task(self.loop_initial())
				elif event == '315' and len(args) >= 3: #RPL_ENDOFWHO
					chan = args[3]
					await asyncio.sleep(throttle.jdelay)
					msg = random.choice(messages)
					if type(msg) == list:
						for i in msg:
							if chan in self.channels['bad']:
								self.channels['bad'].remove(chan)
								break
							else:
								await self.sendmsg(chan, confuse(i))
								await asyncio.sleep(throttle.message)
					else:
						await self.sendmsg(chan, confuse(msg))
					if settings.exploits:
						pass # TODO: add exploits
					if settings.mass_hl:
						self.nicks['chan'][chan] = ' '.join(self.nicks['chan'][chan])
						if len(self.nicks['chan'][chan]) <= 400:
							await self.sendmsg(chan, self.nicks['chan'][chan])
						else:
							while len(self.nicks['chan'][chan]) > 400:
								if chan in self.channels['bad']:
									self.channels['bad'].remove(chan)
									break
								else:
									segment = self.nicks['chan'][chan][:400]
									segment = segment[:-len(segment.split()[len(segment.split())-1])]
									await self.sendmsg(chan, segment)
									self.nicks['chan'][chan] = self.nicks['chan'][chan][len(segment):]
									await asyncio.sleep(throttle.message)
					await self.raw(f'PART {chan} :{settings.part_msg}')
					self.channels['current'].remove(chan)
					del self.nicks['chan'][chan]
					if chan in self.channels['bad']:
						self.channels['bad'].remove(chan)
				elif event == '322' and len(args) >= 4: # RPL_LIST
					chan  = args[3]
					users = args[4]
					if len(self.channels['all']) >= 20000:
						error(self.display + 'LIST tarpit detected!') # Make it     wuddup
						error(self.display + 'LIST tarpit detected!') # stand out           pi55
						error(self.display + 'LIST tarpit detected!') # more                       n3t
						self.snapshot['TARPIT'] = True
						await self.raw('QUIT')
					if users != '0': # no need to JOIN empty channels...
						if chan not in ('#dronebl','#help','#opers'): # lets avoid the channels that are going to get use banned/blacklisted
							self.channels['all'].append(chan)
							self.channels['users'][chan] = users
				elif event == '323': # RPL_LISTEND
					if self.channels['all']:
						debug(self.display + '\033[36mLIST\033[0m found \033[93m{0}\033[0m channel(s)'.format(str(len(self.channels['all']))))
						self.loops['chan'] = asyncio.create_task(self.loop_channels())
						self.loops['nick'] = asyncio.create_task(self.loop_nick())
						if not settings.chan_first:
							self.loops['pm']   = asyncio.create_task(self.loop_private())
				elif event == '352' and len(args) >= 8: # RPL_WHORPL
					chan = args[3]
					nick = args[7]
					self.nicks['chan'][chan].append(nick)
					if nick not in self.nicks['all']+[self.nickname,]:
						self.nicks['all'].append(nick)
						self.nicks['check'].append(nick)
				elif event == '366' and len(args) >= 4: # RPL_ENDOFNAMES
					chan = args[3]
					self.nicks['chan'][chan] = list()
					self.channels['current'].append(chan)
					if chan in self.channels['users']:
						debug('{0}\033[32mJOIN\033[0m {1} \033[1;30m(found \033[93m{2}\033[0m users)\033[0m'.format(self.display, chan, self.channels['users'][chan]))
						del self.channels['users'][chan]
					await self.raw('WHO ' + chan)
				elif event == '404' and len(args) >= 5: # ERR_CANNOTSENDTOCHAN
					chan = args[3]
					msg  = ' '.join(args[4:])[1:]
					error(self.display + '\033[31merror\033[0m - failed to knock ' + chan, msg)
					if chan not in self.channels['bad']:
						self.channels['bad'].append(chan)
				elif event == '421' and len(args) >= 3: # ERR_UNKNOWNCOMMAND
					msg = ' '.join(args[2:])
					if 'You must be connected for' in msg:
						error(self.display + '\033[31merror\033[0m - delay found', msg)
				elif event == '433': # ERR_NICKINUSE
					self.nickname = rndnick()
					await self.raw('NICK ' + self.nickname)
				elif event == '439' and len(args) >= 11: # ERR_TARGETTOOFAST
					target = args[3]
					msg    = ' '.join(args[4:])[1:]
					seconds = args[10]
					if target[:1] in ('#','&'):
						self.channels['all'].append(target)
						if seconds.isdigit():
							self.jthrottle = throttle.seconds if int(seconds) > throttle.seconds else int(seconds)
					else:
						self.nicks['check'].append(target)
						if seconds.isdigit():
							self.nthrottle = throttle.seconds if int(seconds) > throttle.seconds else int(seconds)
					error(self.display + '\033[31merror\033[0m - delay found for ' + target, msg)
				elif event == '465': # ERR_YOUREBANNEDCREEP
					check = [check for check in bad.error if check in line.lower()]
					if check:
						raise Exception(bad.error[check[0]])
				elif event == '464': # ERR_PASSWDMISMATCH
					raise Exception('Network has a password')
				elif event == '487': # ERR_MSGSERVICES
					if '"/msg NickServ" is no longer supported' in line: # TODO: need to do this for ChanServ aswell
						await self.raw('/NickServ REGISTER {0} {1}'.format(rndnick(), f'{rndnick()}@{rndnick()}.com'))
				elif args[1] in ('716','717'): # RPL_TARGUMODEG / RPL_TARGNOTIFY
					nick = args[2] #TODO: verify this is the correct arguement
					if nick not in self.nicks['bad']:
						self.nicks['bad'].append(nick)
				elif event == 'KICK' and len(args) >= 4:
					chan   = args[2]
					kicked = args[3]
					if kicked == self.nickname:
						if chan in self.channels['current']:
							self.channels['current'].remove(chan)
				elif event == 'KILL':
					nick = args[2]
					if nick == self.nickname:
						raise Exception('KILL')
				elif event == 'MODE' and len(args) == 4:
					nick = args[2]
					if nick == self.nickname:
						mode = args[3][1:]
						if mode == '+r':
							chan = settings.register_chan + '_' + str(random.randint(10,99))
							await self.raw('JOIN ' + chan)
							await self.raw(f'TOPIC {chan} :' + settings.register_chan_topic)
							await self.sendmsg('ChanServ', 'REGISTER ' + chan)
							await self.sendmsg('ChanServ', f'SET {chan} KEEPTOPIC ON')
							await self.sendmsg('ChanServ', f'SET {chan} NOEXPIRE ON')
							await self.sendmsg('ChanServ', f'SET {chan} PERSIST ON')
							await self.sendmsg('ChanServ', f'SET {chan} DESCRIPTION ' + settings.register_chan_topic)
							await self.raw('PART ' + chan)
				elif event in ('NOTICE','PRIVMSG') and len(args) >= 4:
					nick   = args[0].split('!')[1:]
					target = args[2]
					msg    = ' '.join(args[3:])[1:]
					if target == self.nickname:
						for i in ('proxy','proxys','proxies'):
							if i in msg.lower():
								check = [x for x in ('bopm','hopm') if x in line]
								if check:
									error(f'{self.display}\033[93m{check.upper()} detected\033[0m')
								else:
									error(self.display + '\033[93mProxy Monitor detected\033[0m')
						for i in ('You must have been using this nick for','You must be connected for','not connected long enough','Please wait', 'You cannot list within the first'):
							if i in msg:
								error(self.display + '\033[31merror\033[0m - delay found', msg)
								break
						if msg[:8] == '\001VERSION':
							version = random.choice(('http://www.mibbit.com ajax IRC Client','mIRC v6.35 Khaled Mardam-Bey','xchat 0.24.1 Linux 2.6.27-8-eeepc i686','rZNC Version 1.0 [02/01/11] - Built from ZNC','thelounge v3.0.0 -- https://thelounge.chat/'))
							await self.raw(f'NOTICE {nick} \001VERSION {version}\001')
						elif '!' not in args[0]:
							if 'dronebl.org/lookup' in msg:
								error(self.display + '\033[93mDroneBL detected\033[0m')
								raise Exception('DroneBL')
							else:
								if [i for i in ('You\'re banned','You are permanently banned','You are banned','You are not welcome','Temporary K-line') if i in msg]:
									raise Exception('K-Lined')
			except (UnicodeDecodeError, UnicodeEncodeError):
				pass
			except Exception as ex:
				error(self.display + '\033[1;31mdisconnected\033[0m', ex)
				break

async def main_b(targets):
	sema = asyncio.BoundedSemaphore(throttle.pthreads) # B O U N D E D   S E M A P H O R E   G A N G
	jobs = list()
	for target in targets:
		jobs.append(asyncio.ensure_future(check_proxy(sema, target)))
	await asyncio.gather(*jobs)

async def main_a(targets):
	sema = asyncio.BoundedSemaphore(throttle.threads) # B O U N D E D   S E M A P H O R E   G A N G
	jobs = list()
	if settings.proxies:
		if settings.proxies_scan:
			proxies = None
			del all_proxies[:len(all_proxies)]
			del good_proxies[:len(good_proxies)]
			while not good_proxies:
				debug('scanning for fresh Socks5 proxies...')
				proxies = get_proxies()
				if proxies:
					debug(f'testing {len(proxies):,} proxies...')
					await main_b(proxies)
					if not good_proxies:
						await asyncio.sleep(300)
				else:
					await asyncio.sleep(300)
			debug(f'found {len(good_proxies):,} proxies')
		elif settings.proxies_local:
			with open('proxies.txt', 'r') as f:
				good_proxies = [line.rstrip() for line in f.readlines() if line]
		else:
			raise SystemExit('error: invalid proxy mode (must use either proxy scanning or local proxies)')
	for target in targets:
		try:
			ipaddress.IPv4Address(target)
		except:
			error('invalid ip address', target)
		else:
			if settings.proxies:
				for proxy in good_proxies: # Todo: we should check if this is empty before running
					jobs.append(asyncio.ensure_future(probe(sema, target, proxy).run()))
			if not settings.proxies_only:
				jobs.append(asyncio.ensure_future(probe(sema, target).run()))
	random.shuffle(jobs)
	await asyncio.gather(*jobs)

# Main
print('#'*56)
print('#{:^54}#'.format(''))
print('#{:^54}#'.format('EFknockr (internet relay chat beacon)'))
print('#{:^54}#'.format('Developed by acidvegas in Python'))
print('#{:^54}#'.format('https://git.acid.vegas/efknockr'))
print('#{:^54}#'.format(''))
print('#'*56)
if True:
	raise SystemExit('those who are not skids may figure out how to use this...') # ;) by removing this you agree to only test this on your own server(s) LOLOLOOL
if settings.proxies:
	try:
		import aiosocks
	except ImportError:
		raise SystemExit('missing required library \'aiosocks\' (https://pypi.org/project/aiosocks/)')
if len(sys.argv) != 2:
	raise SystemExit('error: invalid arguments')
targets_file = sys.argv[1]
if not os.path.isfile(targets_file):
	raise SystemExit('error: invalid file path')
targets = [line.rstrip() for line in open(targets_file).readlines() if line and line not in bad.donotscan]
del targets_file
debug(f'loaded {len(targets):,} targets')
while True:
	asyncio.run(main_a(targets))
	debug('EFknockr has finished knocking!!')
	if not settings.daemon:
		break
