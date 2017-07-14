SOURCES := $(shell find . 2>&1 | grep -E '.*\.(c|h|go)$$')

TARGET = cc-agent
DESTDIR :=
PREFIX := /usr
BINDIR := $(PREFIX)/bin


HAVE_SYSTEMD := $(shell pkg-config --exists systemd 2>/dev/null && echo 'yes')

ifeq ($(HAVE_SYSTEMD),yes)
UNIT_DIR := $(shell pkg-config --variable=systemdsystemunitdir systemd)
UNIT_FILES = clear-containers.service
GENERATED_FILES := $(UNIT_FILES)
UNIT_FILES += clear-containers.target
endif

SED = sed

.DEFAULT: $(TARGET)
$(TARGET): $(SOURCES) Makefile $(GENERATED_FILES)
	go build -o $@ .

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

clean:
	rm -f $(TARGET) $(GENERATED_FILES)

define INSTALL_FILE
	$(QUIET_INST)install -D -m 644 $1 $(DESTDIR)$2/$1 || exit 1;

endef

