MAKE_ORIG = ${MAKE} -f $(firstword ${MAKEFILE_LIST})

srcdir = $(dir $(firstword ${MAKEFILE_LIST}))
abs_srcdir = $(abspath ${srcdir})

VPATH = ${abs_srcdir}

check:	run-test .stamps/ca FORCE
	bash $<

.stamps:
	mkdir -p $@

.stamps/ca:	| .stamps
	$(MAKE_ORIG) _mode=ca init-ca CA_DIR=ca/ca0      CN='CA zero'
	$(MAKE_ORIG) _mode=ca init-ca CA_DIR=ca/ca1      CN='CA one'
	$(MAKE_ORIG) _mode=ca init-ca CA_DIR=ca/ca2      CN='CA two'
	$(MAKE_ORIG) _mode=ca init-ca CA_DIR=ca/ca0-dup0 CN='CA zero'
	$(MAKE_ORIG) _mode=ca init-ca CA_DIR=ca/ca0-dup1 CN='CA zero'
	@touch $@

.stamps/%: FORCE | .stamps
	$(MAKE_ORIG) _mode=$* $*

ifneq ($(_mode),)
include make-$(_mode).mk
endif

FORCE:
.PHONY:	FORCE
