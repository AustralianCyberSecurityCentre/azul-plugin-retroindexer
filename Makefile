# BigGrep build adapted from azul-plugin-retrohunt/Makefile.
# The source archive is checked in: builds do not fetch BigGrep from the network.
.PHONY: biggrep clean-biggrep

BIGGREP_ARCHIVE := third_party/biggrep-2.7.2-source.zip
BIGGREP_DIR := .build/BigGrep-master
BIGGREP_TOOLS := bgindex
BIGGREP_OUTPUT := .build/bin/bgindex

$(BIGGREP_DIR)/.extracted: $(BIGGREP_ARCHIVE)
	mkdir -p .build
	unzip -oq $(BIGGREP_ARCHIVE) -d .build
	touch $@

$(BIGGREP_DIR)/src/bgindex: $(BIGGREP_DIR)/.extracted
	cd $(BIGGREP_DIR) && ./autogen.sh && ./configure && $(MAKE)
	test -x $@

$(BIGGREP_OUTPUT): $(BIGGREP_DIR)/src/bgindex
	mkdir -p $(dir $@)
	cp $< $@
	chmod 0755 $@

biggrep: $(BIGGREP_OUTPUT)

clean-biggrep:
	rm -rf .build
