Formerly announced as [ScarabMon](http://www.blackhat.com/html/bh-europe-07/bh-eu-07-speakers.html#Wilkins) as part of [BlackHat EU 2007](http://www.blackhat.com/html/bh-europe-07/bh-eu-07-index.html), proxmon monitors proxy logs and reports on security issues it discovers.  ProxMon was also presented at [CanSecWest 2007](http://www.cansecwest.com/).

**Download at: http://www.isecpartners.com/tools.html**

More soon on the wiki: [ProxMon ](.md)

I also post information at my blog [bitland.net](http://bitland.net)

Here's sample output to give you an idea of it's capabilities:

```
[*] starting ProxMon v1.0.15 (http://www.isecpartners.com)
[*] Copyright (C) 2007, Jonathan Wilkins, iSEC Partners Inc.
[*] Proxmon comes with ABSOLUTELY NO WARRANTY;
[*] This is free software, and you are welcome to redistribute it
[*] under certain conditions; see accompanying file LICENSE for 
[*] details on warranty and redistribution details.
[*] Loading support for: WebScarab
[*] Loading Checks ... 
 - Find interesting comments
 - Find cookie values that also are sent on the query string
 - Find HTTP Basic or Digest Authentication usage
 - Identify frameworks and scripts in use by server
 - Find dangerous functions in JavaScript code
 - Find offsite redirects
 - Find cookies with the secure flag that also get sent cleartext
 - Find values set over SSL that later go cleartext
 - Find values sent to other domains
 - Find common undesirable directories
 - Find files that indicate common vulnerabilities
 - Find directories that allow directory listing
 - Find SSL server configuration issues
 - Find directories writable via PUT
[*] 14 checks loaded
[*] Finding available sessions ...
[*] Processing session test/webscarab in test
[*] Running in monitor mode
[*] Monitoring test/webscarab
[*] Parsing existing conversations ...
[*] Interesting comment: XXX in http://scratch.bitland.net:80/ (TIDs: 35)
[*] Interesting comment: bug in http://www.bitland.net:80/ (TIDs: 532)
[*] Interesting comment: TODO in http://scratch.bitland.net:80/ (TIDs: 35)
[*] Interesting comment: ??? in http://scratch.bitland.net:80/ (TIDs: 35)
[*] Interesting comment: !!! in http://scratch.bitland.net:80/ (TIDs: 35)
[*] Cookie value seen on QS: secret1 (Secure, SSL) (TIDs: 16)
[*] Cookie value seen on QS: secret2 (Secure, SSL) (TIDs: 9)
[*] Digest auth seen: Authorization: Digest username='jwilkins', realm='scratchdigest', [snip ...] (TIDs: 34)
[*] Basic auth seen: Authorization: Basic andpbGtpbnM6YXNkZmFzZGY= (TIDs: 31, 32)
[*] IDed framework: scratch.bitland.net:80 is using PHP/5.2.1 (http://www.php.net) (TIDs: 35)
[*] IDed framework: www.isecpartners.com:80 is using YUI/1.2.3 (http://developer.yahoo.com/yui) (TIDs: 16)
[*] Unsafe JavaScript found: eval at http://scratch.bitland.net:80/:15 (TIDs: 35)
[*] Unsafe JavaScript found: eval at http://scratch.bitland.net:80/:16 (TIDs: 35)
[*] Secure cookie value sent clear: secret2 (TIDs: 7, 9)
[*] Secure cookie value sent clear: secret1 (TIDs: 16, 36)
[*] Value set over SSL sent clear: secret2 as secure2 (TIDs: 7)
[*] Value set over SSL sent clear: secret2 as bar (TIDs: 9)
[*] Value set over SSL sent clear: secret1 as foobar (TIDs: 16)
[*] Value set over SSL sent clear: secret1 as asdf (TIDs: 36)
[*] Value (secret1) sent to multiple domains: bitland.net (TIDs: 5, 6, 36)
[*] Value (secret1) sent to multiple domains: isecpartners.com (TIDs: 16)
[*] Bad directory found: /backup/ on scratch.bitland.net:80 (TIDs: 0)
[*] Bad file found: /environ.pl on scratch.bitland.net:80 (TIDs: 0)
[*] Listing of /listable/ on scratch.bitland.net:80 succeeded (TIDs: 0)
[*] SSL Config issue https://www.bitland.net:443: aNULL null cipher (TIDs: 0)
[*] SSL Config issue https://www.bitland.net:443: Export strength ciphers (TIDs: 0)
[*] SSL Config issue https://www.bitland.net:443: 40 bit Export strength ciphers (TIDs: 0)
[*] SSL Config issue https://www.bitland.net:443: Low strength ciphers (TIDs: 0)
[*] SSL Config issue https://www.bitland.net:443: SSLv2 protocol (TIDs: 0)
[*] Upload to /put/ on scratch.bitland.net:80 succeeded (TIDs: 0)
[*] Parsed 38 existing conversations
[*] Session is not active, no point in monitoring
```