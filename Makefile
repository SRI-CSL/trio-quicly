DRAFT=draft-sri-quicly
SRC=quicly_specification.md
XML=$(DRAFT).xml

all: $(DRAFT).txt $(DRAFT).html

$(XML): $(SRC)
	kramdown-rfc2629 $< > $@

$(DRAFT).txt $(DRAFT).html: $(XML)
	xml2rfc --text --html $<

clean:
	rm -f $(XML) $(DRAFT).txt $(DRAFT).html
