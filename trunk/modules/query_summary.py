"Summarize query string information"
import logging
from pmcheck import *
from pmutil import *

log = logging.getLogger("proxmon")

class query_summary(postruncheck):
	"Summarize query string information"

	def report(self, pmd):
		# show parameter counts
		cmsg('-' * 40)
		qs_counts = {}
		for q in pmd.QueryStrings:
			if q['name'] not in qs_counts:
				qs_counts[q['name']] = 1
			else:
				qs_counts[q['name']] += 1
		keys = qs_counts.keys()
		keys.sort()
		for k in keys:
			cmsg("Parameter %s occurs %d times" % (k, qs_counts[k]))

		# Show a list of Paths and their query strings for each host
		cmsg('-' * 40)
		paths_by_host = {}
		dirs_by_host = {}
		params_by_url = {}
		for t in pmd.Transactions:
			# Build list of paths on each host
			if t['server'] in paths_by_host:
				if t['path'] not in paths_by_host[t['server']]:
					paths_by_host[t['server']].append(t['path'])
			else:
				paths_by_host[t['server']] = [t['path']] 

			# Build list of query strings for each host and path
			hp = t['server']+t['path']
			if t['qsf'] != '':
				if hp in params_by_url:
					params_by_url[hp].append(t['qsf'])
				else:
					params_by_url[hp] = [t['qsf']]

			# build list of known and implied directories for each host
			dirs = implied_dirs(t['path'])
			if t['server'] in dirs_by_host:
				for d in dirs:
					if d not in dirs_by_host[t['server']]:
						dirs_by_host[t['server']].append(d)
			else:
				dirs_by_host[t['server']] = []
				dirs_by_host[t['server']].extend(dirs)

		hosts = paths_by_host.keys()
		hosts.sort()
		for h in hosts:
			cmsg('Host: ' + h)
			cmsg('  Directories: %s' % ' '.join(dirs_by_host[h]))
			for p in paths_by_host[h]:
				if h+p in params_by_url:
					cmsg('  Path: %s %d query strings' % (p, len(params_by_url[h+p])))
					for q in params_by_url[h+p]:
						cmsg('    QS: %s' % q)
				else:
					cmsg('  Path: %s' % p)
			cmsg('-' * 20)
