## Description ##
ProxMon automates certain aspects of web application penetration tests.  It monitors HTTP/HTTPS logs and reports on discovered vulnerabilities.

## Details ##

ProxMon handles routine tasks like
  * Checking server SSL configuration
  * Looking for directories that allow listing or upload

It's real strength is that it also helps with higher level analysis such as
  * Finding values initially sent over SSL that later go cleartext
  * Finding Secure cookie values also sent in the clear
  * Finding values that are sent to 3rd party sites