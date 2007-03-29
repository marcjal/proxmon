"Summarize query string information"
from pmcheck import *
from pmutil import *

class query_summary(postruncheck):
	"Summarize query string information"

	def report(self, pmd):
		# show parameter counts
		print '-' * 40
		qs_counts = {}
		for q in pmd.QueryStrings:
			if q['name'] not in qs_counts:
				qs_counts[q['name']] = 1
			else:
				qs_counts[q['name']] += 1
		keys = qs_counts.keys()
		keys.sort()
		for k in keys:
			print "Parameter %s occurs %d times" % (k, qs_counts[k])

		# Show a list of Paths and their query strings for each host
		print '-' * 40
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
			print 'Host: ' + h
			print '  Directories:',
			for d in dirs_by_host[h]:
				print d,
			print
			for p in paths_by_host[h]:
				if h+p in params_by_url:
					print '  Path: %s %d query strings' % (p, len(params_by_url[h+p]))
					for q in params_by_url[h+p]:
						print '    QS:' + q
				else:
					print '  Path: ' + p
			print '-' * 20


