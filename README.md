#CTFBot
 
####IRC Bot listing upcoming CTF from ctftime.org

This is a small IRC bot listing upcoming CTF from ctftime.org and some resources related to them.

The bot will parse the RSS feed every hour and allows IRC users to have a quick look to organise themselves for upcoming CTF.

##Dependencies:

[feedparser](https://pypi.python.org/pypi/feedparser)

##Features:

* List upcoming CTFs from ctftime.org using their RSS feed
* Join multiple servers/channels
* Anti spam/flood protection with temporary ban of user
* Small list of resources related to computer security
* Easy to add remove features

##List of commands:

| cmd  | description                       |
| ---- | --------------------------------- |
| !l   | list of upcoming ctf              |
| !s # | details of upcoming ctf by its id |
| !m   | list of ctf material              |
| !w   | list of ctf writeup               |
| !i   | list of vulnerable ISO            |
| !t   | list of teaching material         |
| !wg  | list of sites hosting wargames    |

##Reference:
...