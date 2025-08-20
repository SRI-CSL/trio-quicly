DRAFT=draft-sri-quicly
SRC=quicly_specification.md
XML=$(DRAFT).xml
TXT=$(DRAFT).txt
HTML=$(DRAFT).html

.PHONY: all clean clobber
all: $(TXT) $(HTML)

$(XML): $(SRC)
	@set -euo pipefail; tmp="$@.tmp"; \
	kramdown-rfc --v3 $< > "$$tmp"; test -s "$$tmp"; mv "$$tmp" "$@"

$(TXT) $(HTML): $(XML)
	xml2rfc --text --html $<

clean:
	rm -f $(XML) $(TXT) $(HTML)

clobber: clean
	git clean -fdx
