NAME = proxmon
VERSION = `python proxmon.py -V | grep version | cut -f 3 -d ' '`
NSIS = /cygdrive/c/Program\ Files/NSIS/makensis

SRC = proxmon.py pmcheck.py pmdata.py pmproxy.py pmutil.py \
		transaction.py urltesting.py
PROXIES = proxies/*.py
CHECKS = modules/*.py modules/*.cfg
ALLSRC = $(SRC) $(PROXIES) $(CHECKS)
DOC = README LICENSE ChangeLog doc/proxmon.pdf
DOCSRC = doc/proxmon.tex doc/log/proxmon-o.txt doc/Makefile
BUILD = Makefile setup.py setup.nsi

doc/proxmon.pdf: $(FILES) $(DOCSRC)
	make -C doc

doc/log/proxmon-o.txt:
	python proxmon.py -o -d test > doc/log/proxmon-o.txt

tgz: $(ALLSRC) $(DOC) $(DOCSRC)
	-rm -rf $(NAME)-$(VERSION)
	mkdir $(NAME)-$(VERSION)
	mkdir $(NAME)-$(VERSION)/proxies
	mkdir $(NAME)-$(VERSION)/modules
	cp $(SRC) $(DOC) $(NAME)-$(VERSION)
	cp $(PROXIES) $(NAME)-$(VERSION)/proxies
	cp $(CHECKS) $(NAME)-$(VERSION)/modules
	tar -zcvf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	-rm -rf $(NAME)-$(VERSION)

nsis: py2exe $(ALLSRC) $(DOC) $(DOCSRC) $(BUILD)
	$(NSIS) setup.nsi

py2exe: $(ALLSRC) $(DOC) $(DOCSRC) $(BUILD)
	/cygdrive/c/Python24/python setup.py py2exe

all: nsis tgz

version:
	@echo $(VERSION)

run:
	python proxmon.py -d test

runo:
	python proxmon.py -o -d test

runa:
	python proxmon.py -A

.PHONY: clean version

clean:
	@echo '[*] Cleaning ..'
	-rm *.pyc proxmon.cj > /dev/null 2>&1
	-rm proxies/*.pyc > /dev/null 2>&1
	-rm modules/*.pyc > /dev/null 2>&1
	-rm -rf dist build > /dev/null 2>&1
	-rm doc/log/proxmon-o.txt > /dev/null 2>&1
	-make -C doc clean
