.PHONY: build test install install-shim uninstall-shim install-watch uninstall-watch \
        install-notify uninstall-notify install-warm uninstall-warm clean

WATCH_LABEL = dev.peter.op-cache.watch
WATCH_PLIST = $(HOME)/Library/LaunchAgents/$(WATCH_LABEL).plist
NOTIFY_LABEL = dev.peter.op-cache.notify
NOTIFY_PLIST = $(HOME)/Library/LaunchAgents/$(NOTIFY_LABEL).plist
WARM_LABEL = dev.peter.op-cache.warm
WARM_PLIST = $(HOME)/Library/LaunchAgents/$(WARM_LABEL).plist

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

# Everlast fork only. Watches the audit log and notifies about rarely fetched
# references and request bursts - the signal a permanently warm cache no longer
# gives through approval prompts.
install-notify:
	install -d "$(HOME)/.local/bin" "$(HOME)/Library/LaunchAgents" "$(HOME)/Library/Logs"
	install -m 0755 tools/op-cache-notify "$(HOME)/.local/bin/op-cache-notify"
	sed "s|@HOME@|$(HOME)|g" launchd/$(NOTIFY_LABEL).plist > "$(NOTIFY_PLIST)"
	launchctl bootout gui/$$(id -u) "$(NOTIFY_PLIST)" 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) "$(NOTIFY_PLIST)"

uninstall-notify:
	launchctl bootout gui/$$(id -u) "$(NOTIFY_PLIST)" 2>/dev/null || true
	rm -f "$(NOTIFY_PLIST)" "$(HOME)/.local/bin/op-cache-notify"

# Everlast fork only. Re-runs 'unlock --all' when the prefetch has lapsed, so
# the cache stays warm without a per-call approval.
install-warm: install
	install -d "$(HOME)/.local/bin" "$(HOME)/Library/LaunchAgents" "$(HOME)/Library/Logs"
	install -m 0755 tools/op-cache-warm "$(HOME)/.local/bin/op-cache-warm"
	sed "s|@HOME@|$(HOME)|g" launchd/$(WARM_LABEL).plist > "$(WARM_PLIST)"
	launchctl bootout gui/$$(id -u) "$(WARM_PLIST)" 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) "$(WARM_PLIST)"

uninstall-warm:
	launchctl bootout gui/$$(id -u) "$(WARM_PLIST)" 2>/dev/null || true
	rm -f "$(WARM_PLIST)" "$(HOME)/.local/bin/op-cache-warm"

clean:
	swift package clean
