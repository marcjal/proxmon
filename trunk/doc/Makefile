all: pdf html

pdf: proxmon.pdf log/proxmon-o.txt

proxmon.pdf: proxmon.tex proxmon.idx latex log/proxmon-o.txt
	# The following is not a typo, latex needs to be run twice to handle all references
	-pdflatex proxmon.tex
	pdflatex proxmon.tex

proxmon.idx:
	makeindex proxmon.tex

latex:
	epydoc --latex -o latex/ -n ProxMon ../proxmon.py ../pmcheck.py ../pmdata.py ../pmproxy.py ../pmutil.py ../proxies ../modules/ ../transaction.py ../urltesting.py

html:
	epydoc --html -o html/ -n ProxMon ../proxmon.py ../pmcheck.py ../pmdata.py ../pmproxy.py ../pmutil.py ../proxies ../modules/ ../transaction.py ../urltesting.py

clean:
	-rm -rf proxmon.pdf proxmon.out proxmon.log proxmon.aux proxmon.idx proxmon.ilg proxmon.toc proxmon.ind html latex > /dev/null 2>&1
