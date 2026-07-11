.PHONY: build test install install-watch uninstall-watch clean

WATCH_LABEL = dev.peter.op-cache.watch
WATCH_PLIST = $(HOME)/Library/LaunchAgents/$(WATCH_LABEL).plist

build:
	swift build -c release

test:
	swift test

install: build
	install -d "$(HOME)/.local/bin"
	install -m 0755 .build/release/op-cache "$(HOME)/.local/bin/op-cache"

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
