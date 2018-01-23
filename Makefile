# This is the version string used when it isn't possible to do a git describe,
# which happens with a git-archive tarball for instance. A '+' is appended to
# the version string to mean that it's a development version eg. 3.0.0+ means
# somewhere between 3.0.0 and 3.0.1.
#
# The version should be bumped and the '+' sign removed just before tagging a
# new release.
# A '+' sign should be added in the commit just after tagging a new release.
VERSION := 0.1.1+
SOURCES := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')
MKDIR = $(dir $(lastword $(MAKEFILE_LIST)))

TARGET = cc-agent
DESTDIR :=
PREFIX := /usr
BINDIR := $(PREFIX)/bin

DESCRIBE := $(shell git describe 2> /dev/null || true)
DESCRIBE_DIRTY := $(if $(shell git status --porcelain --untracked-files=no 2> /dev/null),${DESCRIBE}-dirty,${DESCRIBE})
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
ifneq ($(GIT_COMMIT),)
VERSION_COMMIT := $(VERSION)-$(GIT_COMMIT)
endif
ifneq ($(DESCRIBE_DIRTY),)
VERSION_COMMIT := $(VERSION)$(DESCRIBE_DIRTY)
endif

HAVE_SYSTEMD := $(shell pkg-config --exists systemd 2>/dev/null && echo 'yes')

ifeq ($(HAVE_SYSTEMD),yes)
UNIT_DIR := $(shell pkg-config --variable=systemdsystemunitdir systemd)
UNIT_FILES = clear-containers.service
GENERATED_FILES := $(UNIT_FILES)
UNIT_FILES += clear-containers.target
endif

HAVE_LIBUDEV := $(shell pkg-config --exists libudev 2>/dev/null || echo 'no')
ifeq ($(HAVE_LIBUDEV),no)
$(error "Install libudev devel")
endif

SED = sed

.DEFAULT: $(TARGET)
$(TARGET): $(SOURCES) Makefile $(GENERATED_FILES)
	@build_flags="" ; \
	if [ "$$RACE_DETECTION" = true ] ; then \
		build_flags="-race" ; \
		echo "Building with $$build_flags" ; \
	fi ; \
	go build $$build_flags -ldflags "-X main.Version=$(VERSION_COMMIT)" -o $@ .

install:
	install -D $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
ifeq ($(HAVE_SYSTEMD),yes)
	@echo "Installing systemd unit files..."
	$(foreach f,$(UNIT_FILES),$(call INSTALL_FILE,$f,$(UNIT_DIR)))
endif

$(GENERATED_FILES): %: %.in Makefile
	@echo "Generating file: $@"
	@mkdir -p `dirname $@`
	$(QUIET_GEN)sed \
		-e 's|[@]bindir[@]|$(BINDIR)|g' \
		-e 's|[@]ccagent[@]|$(TARGET)|g' \
		"$<" > "$@"
dist:
	git archive --format=tar --prefix=clear-containers-agent-$(VERSION)/ \
		HEAD | xz -c > clear-containers-agent-$(VERSION).tar.xz

check:
	bash -c "$(MKDIR)/.ci/go-lint.sh"
	bash -c "$(MKDIR)/.ci/go-test.sh"

clean:
	rm -f $(TARGET) $(GENERATED_FILES)

define INSTALL_FILE
	$(QUIET_INST)install -D -m 644 $1 $(DESTDIR)$2/$1 || exit 1;

endef

