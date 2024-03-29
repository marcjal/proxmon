"Summarize cookie information"
import pdb
from pmcheck import *
from pmutil import *

# CookieSummary stuff
def summarize_cookie(cookie):
	"Print a one line summary of what is in this cookie."
	if (len(cookie["value"]) > 40): suffix = "..."
	else: suffix = ""
	cmsg("name: %s value: %s" % (
			cookie["name"].ljust(16), cookie["value"][:40], suffix))

def summarize_setcookie_param(name, cookies):
	"Gives summary information for the parameter in the provided cookies"
	valuelist = []
	for cookie in cookies:
		try:
			value = cookie[name]
		except:
			value = 'blank'
		if value not in valuelist:
			valuelist.append(value)

	if (len(valuelist) > 1):
		vstring = ', '.join(valuelist)
		return "The %s varies, the values found were: %s" % (name, vstring)
	else:
		return "The %s is consistently %s" % (name, valuelist[0])

def summarize_setcookie_flags(cookies):
	"Computes a one line statement about the flags in the cookies provided "
	"in the cookies parameter"

	secure_found, non_secure_found = False, False
	httponly_found, non_httponly_found = False, False

	for cookie in cookies:
		secure, httponly = False, False

		for parameter in cookie:
			if parameter.lower() == "secure": secure = True
			if parameter.lower() == "httponly": httponly = True

		if secure: secure_found = True
		else: non_secure_found = True

		if httponly: httponly_found = True
		else: non_httponly_found = True

	if (secure_found and not non_secure_found):
		result = "The cookie is consistently secure"
	elif (secure_found and non_secure_found):
		result = "The cookie is inconsistently secure"
	elif (not secure_found):
		result = "The cookie is insecure"

	if (httponly_found and not non_httponly_found):
		result += " and consistently httponly."
	elif (httponly_found and non_httponly_found):
		result += " and inconsistently httponly."
	elif (not httponly_found):
		result += " and not httponly."

	return result

class cookie_summary(postruncheck):
	"Summarize cookie information"

	def report(self, pmd):
		setcookienames = uniq_cookies(pmd.SetCookies)
		cookienames = uniq_cookies(pmd.SetCookies+pmd.SentCookies)
		setcookiesbyname = cookies_by_name(pmd.SetCookies)
		cookiesbyname = cookies_by_name(pmd.SetCookies+pmd.SentCookies)
		# XXX: unused - sentcookiesbyname = cookies_by_name(pmd.SentCookies)
		# XXX: unused - sentcookienames = uniq_cookies(pmd.SentCookies)

		cmsg('-' * 40)
		cmsg('Cookie Summary')
		cmsg('-' * 40)
		cmsg("Saw %d unique cookie names in %d conversations" % (len(cookienames), len(pmd.Transactions)))
		cmsg("Saw %d Set-Cookie headers, %d cookies sent by browser" % (len(pmd.SetCookies), len(pmd.SentCookies)))

		cmsg('-'*40)
		cmsg("Listing unique cookie names")
		for n in cookienames:
			serverlist = []
			for x in xrange(len(cookiesbyname[n])):
				if cookiesbyname[n][x]['httpparams']['server'] in serverlist:
					continue
				serverlist.append(cookiesbyname[n][x]['httpparams']['server'])
			cmsg("  %s: %s" % (n, ', '.join(serverlist)))

		cmsg('-'*40)
		cmsg('Listing Set-Cookie properties')
		for n in setcookienames:
			cmsg('-'*20)
			tidlist = []
			for c in cookiesbyname[n]:
				for x in xrange(len(cookiesbyname[n])):
					tid = cookiesbyname[n][x]['httpparams']['id']
					if tid in tidlist: continue
					tidlist.append(tid)
			cmsg("Cookie: %s (TIDs %s)" % (n, ', '.join(tidlist)))
			cmsg(summarize_setcookie_param('domain', setcookiesbyname[n]))
			cmsg(summarize_setcookie_param('path', setcookiesbyname[n]))
			cmsg(summarize_setcookie_flags(setcookiesbyname[n]))

		if(self.verbosity > 1):
			cmsg('-'*40)
			# XXX - should this be done for sent cookies?
			# XXX - don't report dupes
			for c in pmd.SetCookies:
				summarize_cookie(c)

