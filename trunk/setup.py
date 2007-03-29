# ProxMon - Monitors proxies to automate web application penetration tests
# Copyright (C) 2007, Jonathan Wilkins - See accompanying LICENSE for info
from distutils.core import setup
import os, sys
import proxmon

options = {}
try:
	if sys.platform == 'win32':
		import py2exe
		options={'py2exe': { 'packages': ['socket', 'urltesting', 'pycurl',
								'BeautifulSoup', 'OpenSSL', 'config', 'select'], 
							 'unbuffered': True }}
	if sys.platform == 'darwin':
		import py2app
		options={'py2app': {'argv_emulation': True}}
except ImportError:
	pass

if sys.version < '2.4':
	print '[*] This has only been tested on Python 2.4 and above, good luck...'

checks = ['modules/'+x for x in os.listdir('modules') if x.endswith('.py')]
if 'ssl_toolbar.py' in checks: checks.remove(checks.index('ssl_toolbar.py'))
if 'nop.py' in checks: checks.remove(checks.index('nop.py'))
checkcfg = ['modules/'+x for x in os.listdir('modules') if x.endswith('.cfg')]
proxies = ['proxies/'+x for x in os.listdir('proxies') if x.endswith('.py')]

setup(
	name='proxmon',
	version=proxmon.__version__,
	author='Jonathan Wilkins',
	author_email='jwilkins[at]isecpartners[dot]com',
	url='http://proxmon.isecpartners.com',
	description='ProxMon Web Tools',
	classifiers=['Development Status :: 4 - Beta',
				 'Environment :: Console',
				 'Intended Audience :: End Users/Desktop',
				 'License :: OSI Approved :: GNU General Public License (GPL)',
				 'Natural Language :: English',
				 'Programming Language :: Python',
				 'Operating System :: Microsoft :: Windows',
				 'Operating System :: POSIX',
				 'Operating System :: Unix',
				 'Topic :: Internet :: WWW/HTTP',
				 'Topic :: Internet :: Proxy Servers',
				 'Topic :: Security' ],
	options=options,
	# py2exe stuff
	console=['proxmon.py'],
	# non-win32 stuff
	data_files=[('', ['LICENSE', 'ChangeLog', 'README', 'pmcheck.py', 
						'pmdata.py', 'pmproxy.py','pmutil.py', 
						'doc/proxmon.pdf', 'proxmon.py', 
						'setup.py', 'transaction.py',
						'urltesting.py' ]),
				('modules', checks+checkcfg),
				('proxies', proxies)]
)
