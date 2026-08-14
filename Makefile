.PHONY: build test install install-shim uninstall-shim install-watch uninstall-watch clean

WATCH_LABEL = dev.peter.op-cache.watch
WATCH_PLIST = $(HOME)/Library/LaunchAgents/$(WATCH_LABEL).plist

build:
	swift build -c release

test:
	swift test

install: build
	install -d "$(HOME)/.local/bin"
	install -m 0755 .build/release/op-cache "$(HOME)/.local/bin/op-cache"

# Everlast fork only. Puts `op` in ~/.local/bin, which must precede the real
# binary's directory in PATH for the shim to take effect.
install-shim: install
	install -d "$(HOME)/.local/bin"
	install -m 0755 shim/op "$(HOME)/.local/bin/op"
	@echo "Shim installed. Verify with: command -v op"

uninstall-shim:
	rm -f "$(HOME)/.local/bin/op"
	@echo "Shim removed; plain 'op' goes straight to the real binary again."

install-watch: install
	install -d "$(HOME)/Library/LaunchAgents" "$(HOME)/Library/Logs"
	sed "s|@HOME@|$(HOME)|g" launchd/$(WATCH_LABEL).plist > "$(WATCH_PLIST)"
	launchctl bootout gui/$$(id -u) "$(WATCH_PLIST)" 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) "$(WATCH_PLIST)"

uninstall-watch:
	launchctl bootout gui/$$(id -u) "$(WATCH_PLIST)" 2>/dev/null || true
	rm -f "$(WATCH_PLIST)"

clean:
	swift package clean
