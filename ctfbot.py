#!/usr/bin/env python
# -----------------------------------------------------------------------------
# CTFBot by Themistokle "mrt-prodz" Benetatos
# -------------------------------------------
# Small IRC bot listing upcoming CTF events from ctftime.org
# 
# Features: - upcoming CTFs from ctftime.org RSS feed
#           - can join multiple servers/channels
#           - anti spam/flood protection with temporary ban of user
#           - small list of resources related to computer security
#
# ------------------------
# http://www.mrt-prodz.com
# https://github.com/mrt-prodz/CTFBot
# -----------------------------------------------------------------------------

import sys, signal, feedparser, socket, time, ssl, re
from HTMLParser import HTMLParser
from threading import Thread
import threading

# exit flag to signal all threads to exit
exitFlag = False

# tiny database
database = {
		'h':
			{
				'title':'list of commands',
				'data':
						[
							["!l  ","list of upcoming ctf"],
							["!s #","details of upcoming ctf by its id"],
							["!m  ","list of ctf material"],
							["!w  ","list of ctf writeup"],
							["!i  ","list of vulnerable ISO"],
							["!t  ","list of teaching material"],
							["!wg ","list of sites hosting wargames"]
						]
			},
		'm':
			{
				'title':'list of ctf material',
				'data':
						[
							["http://trailofbits.github.io/ctf","CTF field guide"],
							["http://www.captf.com            ","dump of CTF material"],
							["http://shell-storm.org/repo/CTF ","dump of CTF material"]
						]
			},
		'w':
			{
				'title':'list of ctf writeup',
				'data':
						[
							["https://ctftime.org/writeups                ","ctftime writeups"],
							["https://github.com/ctfs/write-ups           ","collection of CTF write-ups on github"],
							["http://www.defcon.org/html/links/dc-ctf.html","collection of DEF CON CTF write-ups"]
						]
			},
		'i':
			{
				'title':'list of vulnerable ISO',
				'data':
						[
							["http://www.pentesterlab.com                   ","pentesterlab exercises"],
							["http://vulnhub.com                            ","collection of vulnerable ISO"],
							["http://sourceforge.net/projects/metasploitable","start learning metasploit"],
							["http://exploit-exercises.com/download         ","exploit exercises ISO"]
						]
			},
		't':
			{
				'title':'list of teaching material',
				'data':
						[
							["http://code.google.com/p/pentest-bookmarks            ","huge collection of url"],
							["https://www.pentesterlab.com/bootcamp                 ","pentesterlab bootcamp"],
							["https://www.owasp.org                                 ","open web application security project"],
							["http://www.offensive-security.com/metasploit-unleashed","learn metasploit"],
							["http://www.opensecuritytraining.info/Training.html    ","classes about RE"],
							["http://thelegendofrandom.com/blog/sample-page         ","RE tutorials"]
						]
			},
		'wg':
			{
				'title':'list of sites hosting wargames',
				'data':
						[
							["http://overthewire.org/wargames  ","overthewire wargames"],
							["http://smashthestack.org/wargames","smasthestack wargames"]       
						]
			}
		}


# we are going to store temporary banned user in this dictionary
banlist = {}

# DEBUG/LOG Output ------------------------------------------------------------
def printErr(msg):
	print '\033[91m'+"[!] "+'\033[0m'+msg+'\n'
def printInf(msg):
	print '\033[92m'+"[+] "+'\033[0m'+msg+'\n'

# RSS CLeaner -----------------------------------------------------------------
# clean html tags and entities
class RSSCleaner(HTMLParser):
	def __init__(self):
		self.reset()
		self.fed = []
	def handle_data(self, d):
		self.fed.append(d)
	def get_data(self):
		return ''.join(self.fed)

# CTF CLASS -------------------------------------------------------------------
# class to store upcoming CTF event
class CTF:
	def __init__(self, idval):
		self._id = idval
		self._name = ""
		self._date = ""
		self._format = ""
		self._location = ""
		self._online = ""
		self._url = ""
		self._rating = 0.0

	@property
	def id(self):
		return self._id
	
	@property
	def name(self):
		return self._name
	@name.setter
	def name(self, value):
		self._name = value
	
	@property
	def date(self):
		return self._date
	@date.setter
	def date(self, value):
		self._date = value
	
	@property
	def format(self):
		return self._format
	@format.setter
	def format(self, value):
		self._format = value
	
	@property
	def location(self):
		return self._location
	@location.setter
	def location(self, value):
		self._location = value
	
	@property
	def online(self):
		return self._online
	@online.setter
	def online(self, value):
		self._online = value
	
	@property
	def url(self):
		return self._url
	@url.setter
	def url(self, value):
		self._url = value
	
	@property
	def rating(self):
		return self._rating
	@rating.setter
	def rating(self, value):
		self._rating = value

	def all_data(self):
		data = []
		data.append(self.name)
		data.append(self.date)
		data.append(self.format)
		if self.location:
			data.append(self.location)
		data.append(self.online)
		if self.url:
			data.append(self.url)
		data.append(str(self.rating))
		return data

# CTF TIME --------------------------------------------------------------------
# class to store CTF events from ctftime.org
class CTFTime:
	def __init__(self):
		self._ctflist = []
		self._timestamp = 0
		self.get_rss()

	def clean_rss(self, rss):
		s = RSSCleaner()
		s.feed(rss)
		d = s.get_data()
		return [line.strip().split(': ') for line in d.split('\n') if line.strip()]

	def get_rss(self):
		timeout = 30
		feed = "https://ctftime.org/event/list/upcoming/rss/"
		data = feedparser.parse(feed, timeout)
		self._ctflist = []
		ctfid = 0
		for rss_data in data.entries:
			description = self.clean_rss(unicode(rss_data.description).encode("utf-8"))
			ctf = CTF(ctfid)
			ctf.name = description[0][len(description[0])-1]
			ctf.date = description[1][len(description[1])-1][:-17]
			ctf.format = description[2][len(description[2])-1]
			ctf.online = description[3][0]
			for x in xrange(4, len(description)):
				if description[x][0] == "Offical URL":
					ctf.url = description[x][len(description[x])-1]
				if description[x][0] == "Location":
					ctf.location = description[x][len(description[x])-1]
				if description[x][0] == "Rating weight":
					ctf.rating = float(description[x][len(description[x])-1])
					break
			self._ctflist.append(ctf)
			ctfid += 1
		# save timestamp of when the rss has been parsed
		self._timestamp = time.time()

	def get_list(self):
		return self._ctflist

	def get_timestamp(self):
		return self._timestamp

# IRC BOT ---------------------------------------------------------------------
class IRCBot (threading.Thread):
	def __init__(self, host, port, ssl, nick, channel, password=None):
		threading.Thread.__init__(self)
		self.host = host
		self.port = port
		self.ssl = ssl
		self.nick = nick
		self.nickpass = password
		self.chan = channel
		self.rbuffer = ""
		# socket buffer size
		self.sbuffer = 512
		self.ctflist = CTFTime()
		self.irc = None
		#self.threads = []
		self.queuecurrent = 0
		# command queue
		self.queue = {}
		self.requests = {}
		# number of maximum requests per requeststime before temp ban
		self.requestslimit = 2
		# 4 seconds between requests (3 requests each 4 seconds max)
		self.requeststime = 4
		# temporary ban time (120 sec default)
		self.bantime = 120
		self.exitcode = 0

	def run(self):
		while not exitFlag:
			self.connect()
			self.loop()
			if self.exitcode == -1:
				break
			threadLock.acquire()
			printErr("reconnecting to %s in 20 seconds..\n" % self.host)
			threadLock.release()
			time.sleep(20)
			
		threadLock.acquire()
		printErr("%s main thread stopped..\n" % self.host)
		threadLock.release()

	# connect to server
	def connect(self):
		try:
			if self.ssl:
				ircc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				ircc.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
				ircc.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)
				ircc.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 4)
				ircc.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15)
				self.irc = ssl.wrap_socket(ircc)
			else:
				self.irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error as error:
			threadLock.acquire()
			printErr("Cannot create socket: %s" % (error))
			threadLock.release()
			self.exitcode = 1
			return

		try:
			self.irc.connect((self.host, self.port))
		except socket.gaierror as error:
			threadLock.acquire()
			printErr("Cannot connect to %s on port %s\n    %s" % (self.host, self.port, error))
			threadLock.release()
			self.exitcode = 2
			return

		self.irc.send("USER %s %s %s :ctfbot\n" % (self.nick, self.nick, self.nick))
		self.irc.send("NICK %s\n" % self.nick)
		#start thread processing queue
		t = Thread(target=self.processqueue)
		t.daemon = True
		t.start()
		#self.threads.append(t)

	# disconnect from server
	def disconnect(self):
		try:
			threadLock.acquire()
			printErr("Disconnecting from %s" % self.host)
			threadLock.release()
			self.irc.send("PRIVMSG %s :[user sent sigint] terminating.\r\n" % self.chan)
			self.irc.send("QUIT plop!\r\n")
			self.irc.shutdown(socket.SHUT_RDWR)
			self.irc.close()
		except socket.error as error:
			threadLock.acquire()
			printErr("Socket error: %s" % (error))
			threadLock.release()

	# get elapsed time
	def timeseconds(self, last):
		timediff = round(time.time() - last)
		return (timediff)

	# check if user is temporary banned (avoid flood)
	def isbanned(self, senderip):
		# remove people from banlist after self.bantime
		unbanlist = []
		for ip in banlist:
			if (self.timeseconds(banlist[ip]) > self.bantime):
				unbanlist.append(ip)
		for ip in unbanlist:
			threadLock.acquire()
			printInf("Unban %s" % ip)
			threadLock.release()
			banlist.pop(ip, None)
			self.irc.send("SILENCE -*!*@%s\r\n" % ip)

		if (senderip in banlist.keys()):
			return True
		else:
			return False

	# push command into queue
	def send(self, cmd, sendto, senderip):
		if self.isbanned(senderip):
			if senderip in self.queue.keys():
				self.queue.pop(senderip, None)
			return
		if senderip not in self.queue.keys():
			self.queue[senderip] = []
		self.queue[senderip].append(cmd)

	# process command queue into separate thread
	def processqueue(self):
		# keep processing until exitFlag is True
		while not exitFlag:
			try:
				delempty = []
				for senderip in self.queue.keys():
					if (senderip not in banlist.keys()) and (self.queue[senderip]):
						cmd = self.queue[senderip].pop(0)
						# send reply / if on a channel set a 1 second delay between replies
						if cmd[8] == "#":
							time.sleep(1)
						self.irc.send(cmd)
					else:
						#if senderip in self.queue.keys():
						delempty.append(senderip)
				for senderip in delempty:
					self.queue.pop(senderip, None)
			# socket error, close thread and set exitcode
			except socket.error:
				threadLock.acquire()
				printErr("Couldn't write to the socket")
				threadLock.release()
				self.exitcode = 3
				return

		threadLock.acquire()
		printErr("%s process queue stopped." % self.host)
		threadLock.release()
		self.exitcode = -1
		self.disconnect()

	def parsecmd(self, cmd, buffparts):
		senderip = buffparts[0].split('@')[1]
		# send to channel by default
		sendto = buffparts[2]
		# if buffparts[2] is the botname send to user
		if (buffparts[2] == self.nick):
			sendto = buffparts[0].split('!')[0][1:]

		# ip in banlist, don't send anything
		if not self.isbanned(senderip):
			# ip already in requests list increment counter
			if senderip in self.requests.keys():
				# increment counter
				self.requests[senderip]['count'] += 1
			else:
				# ip never done any request, create key and set counter
				self.requests[senderip] = {'time':time.time(), 'count':1}

			senduser = buffparts[0].split('!')[0][1:]

			# if counter is over requestslimit and under requeststime seconds ban the ip for self.bantime seconds
			if (self.requests[senderip]['count'] >= self.requestslimit) and (self.timeseconds(self.requests[senderip]['time']) <= self.requeststime):
				banlist[senderip] = time.time()
				self.requests.pop(senderip, None)
				if senderip in self.queue.keys():
					self.queue.pop(senderip, None)
				self.irc.send("PRIVMSG %s :[flood detected] %s seconds ban for %s\r\n" % (sendto, self.bantime, senduser))
				self.irc.send("SILENCE +*!*@%s\r\n" % senderip)
				threadLock.acquire()
				printInf("Flood detected %s seconds ban for %s @ %s\r\n" % (self.bantime, senduser, senderip))
				threadLock.release()
				return
			elif (self.requests[senderip]['count'] <= self.requestslimit) and (self.timeseconds(self.requests[senderip]['time']) > self.requeststime):
				self.requests.pop(senderip, None)
				#printInf("Resetting counter for %s @ %s" % (senduser,senderip)) 

			# list upcoming CTFs
			if (cmd == "l"):
				self.send("PRIVMSG %s :%s upcoming ctf:\r\n" % (sendto, len(self.ctflist.get_list())), sendto, senderip)
				self.send("PRIVMSG %s :--------------------\r\n" % sendto, sendto, senderip)
				for ctf in self.ctflist.get_list():
					self.send("PRIVMSG %s :%s | %s | %s | %s\r\n" % (sendto,str(ctf.id),str(ctf.rating) if len(str(ctf.rating)) >= 4 else "0"+str(ctf.rating),ctf.online,ctf.name), sendto, senderip)
				self.send("PRIVMSG %s :--------------------\r\n" % sendto, sendto, senderip)
				self.send("PRIVMSG %s :end of listing\r\n" % sendto, sendto, senderip)
				return

			# show CTF event with ID
			if (cmd == "s") and (len(buffparts) >= 5):
				arg = buffparts[4]
				if (arg.isdigit()) and (int(arg) < len(self.ctflist.get_list())):
					data = self.ctflist.get_list()[int(arg)]
					self.send("PRIVMSG %s :--------------------\r\n" % sendto, sendto, senderip)
					for ctfdata in data.all_data():
						self.send("PRIVMSG %s :%s\r\n" % (sendto,ctfdata), sendto, senderip)
					self.send("PRIVMSG %s :--------------------\r\n" % sendto, sendto, senderip)
					return
				else:
					self.send("PRIVMSG %s :invalid #ID\r\n" % sendto, sendto, senderip)
					return

			# force reload CTF list
			if (cmd == "reload"):
				self.ctflist.get_rss()
				return

			# if command is in database run it
			if cmd in database.keys():
				self.send("PRIVMSG %s :%s\r\n" % (sendto,database[cmd]['title']), sendto, senderip)
				self.send("PRIVMSG %s :--------------------\r\n" % sendto, sendto, senderip)
				for item in database[cmd]['data']:
					self.send("PRIVMSG %s :%s | %s\r\n" % (sendto, item[0], item[1]), sendto, senderip)
				self.send("PRIVMSG %s :--------------------\r\n" % sendto, sendto, senderip)

	# main bot loop, receive and parse server replies
	def loop(self):
		# always check for main exitFlag if we need to stop thread
		while not exitFlag:
			try:
				self.rbuffer = self.irc.recv(self.sbuffer)
				# uncomment to get server replies
				#threadLock.acquire()
				#print self.rbuffer
				#threadLock.release()
			except socket.timeout:
				threadLock.acquire()
				printErr("Socket Timeout..")
				threadLock.release()
				continue
			except socket.error:
				threadLock.acquire()
				printErr("Lost connection..")
				threadLock.release()
				self.exitcode = 4
				return

			# grab the feed again after 3600 seconds (faster access and avoids flooding server with request)
			if (self.timeseconds(self.ctflist.get_timestamp()) > 3600):
				threadLock.acquire()
				#printInf("Grabbing feed again after 3600 seconds")
				self.ctflist.get_rss()
				threadLock.release()

			# store server reply in a list (split by whitespace)
			buffparts = self.rbuffer.split()

			# only process buffparts if not empty
			if len(buffparts) > 1:
				# reply to PING
				if buffparts[0] == "PING":
					#self.irc.send("PONG %s\r\n" % (buffparts[1]))
					self.send("PONG %s\n" % buffparts[1], buffparts[1], buffparts[1])

				# quit on error
				if buffparts[0] == "ERROR":
					threadLock.acquire()
					printErr("Error from the server")
					threadLock.release()
					self.exitcode = 1
					return

				# auto join on connect
				if buffparts[1] == "001" or buffparts[1] == "376":
					# if password auth with nickserv
					if self.nickpass is not None:
						self.irc.send("PRIVMSG nickserv :IDENTIFY %s\n" % self.nickpass)
					# join channels
					for chan in self.chan:
						self.irc.send("JOIN %s\n" % chan)

				# auto rename if nickname already in use and ghost nick to regain it
				if buffparts[1] == "433":
					self.irc.send("NICK ctf_____\n")
					self.irc.send("PRIVMSG nickserv :GHOST %s %s\n" % (self.nick, self.nickpass))
					self.irc.send("NICK %s\n" % self.nick)
					self.irc.send("PRIVMSG nickserv :IDENTIFY %s\n" % self.nickpass)

				# auto join after kick
				if buffparts[1] == "KICK":
					self.irc.send("JOIN %s\n" % buffparts[2])
					self.irc.send("PRIVMSG %s :Hey! Why would you do that?\n" % buffparts[2])

				# on privmsg parse cmd
				if buffparts[1] == "PRIVMSG":
					buffparts[3] = buffparts[3][1:]
					if buffparts[3][:1][-1:] == "!":
						buffparts[3] = buffparts[3][1:]
						cmd = buffparts[3]
						self.parsecmd(cmd, buffparts)

			if self.exitcode < 0:
				break

		threadLock.acquire()
		printErr("%s main loop stopped." % self.host)
		threadLock.release()

if __name__ == '__main__':
	# CTFBot configuration dictionary
	config = {
		'freenode':
			{
				'host':'irc.freenode.net',
				'port': 6667,
				'ssl' : False,
				'nick': 'ctfbot',
				'chan': ['#ctfbot'],
				'pwd': ''
			},
		'other_server':
			{
				'host':'127.0.0.1',
				'port': 7000,
				'ssl' : True,
				'nick': 'ctfbot',
				'chan': ['#ctfbot'],
				'pwd': 'ctfbot_password'
			},
	}

	# threads list
	threads = []
	threadLock = threading.Lock()
	
	# parse config and run bot in threads
	for server, setting in config.items():
		t = IRCBot(setting['host'], setting['port'], setting['ssl'], setting['nick'], setting['chan'], setting['pwd'])
		threads.append(t)
		t.daemon = True
		t.start()

	# catch sigint to terminate all threads with exitFlag
	#while len(threads) > 0:
	while not exitFlag:
		try:
			try:
				threads = [t.join(1) for t in threads if t is not None and t.isAlive()]
			except KeyboardInterrupt:
				printErr("User sent sigint.. terminating.")
				raise
		except (KeyboardInterrupt, SystemExit):
			exitFlag = True

	# ugly until I find a cleaner way to wait for all threads to properly exit before quitting
	time.sleep(2)
	printInf("CTFBot ended.")
