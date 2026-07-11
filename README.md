# op-cache

`op-cache` lets a local coding agent use a small, explicit set of 1Password
secrets for a short period without asking for Touch ID on every command.

It is intentionally not a drop-in replacement for `op`. You authenticate once
with `op-cache unlock`, the configured secrets are fetched, and only those
values are cached in macOS Keychain. The default authorization window is one
hour and the hard maximum is one day.

## Security model

- Every profile has an explicit environment-variable-to-`op://` allowlist.
- Private and work profiles use separate 1Password accounts and Keychain
  services.
- Cached values are encrypted at rest by macOS Keychain; no plaintext cache
  file is written.
- A changed `op://` reference invalidates its previous cached value, and each
  entry is bound to the profile's 1Password account: changing the account
  invalidates the cache instead of returning the old account's secret.
- Expired entries are rejected and deleted when accessed.
- `run` strips every configured secret name from the parent environment before
  injecting the selected ones, so `--only` genuinely limits what the child
  sees even when the parent shell already exports one of the names.
- The config must be owned by the current user with mode `0600` or stricter.
- `run --only` limits each child process to the secrets it actually needs.
- The stable installed binary accesses its own Keychain entries directly. The
  generic `/usr/bin/security` executable is not pre-authorized.

This does not make unattended access equivalent to approving every request.
During the unlock window, a process that can execute `op-cache` as your macOS
user can run a command that receives an allowlisted secret. Keep profiles
narrow, use scoped development tokens, prefer `--only`, and do not cache your
1Password password, personal passwords, production database credentials, or
private keys.

## Build and install

Requirements: macOS 13 or newer, Swift, and the 1Password CLI at
`/opt/homebrew/bin/op` with desktop-app integration enabled.

```bash
make test
make install
```

This installs `op-cache` to `~/.local/bin/op-cache`.

## Configure

```bash
mkdir -p ~/.config/op-cache
install -m 0600 config.example.json ~/.config/op-cache/config.json
```

Edit the copied file and use fixed secret references. A minimal profile is:

```json
{
  "defaultTTL": "1h",
  "profiles": {
    "private": {
      "account": "my.1password.eu",
      "secrets": {
        "CLOUDFLARE_API_TOKEN": "op://Development/Cloudflare/credential"
      }
    }
  }
}
```

TTL values support `s`, `m`, `h`, and `d`, for example `30m` or `1h`.

## Use

Authenticate once and prefetch the allowlist:

```bash
op-cache unlock private --ttl 1h
```

Run a command with only the required variables:

```bash
op-cache run private --only CLOUDFLARE_API_TOKEN -- npm run deploy
```

Inspect metadata without printing values, or clear a profile immediately:

```bash
op-cache status private
op-cache clear private
```

After the TTL expires, `run` fails closed and asks you to unlock again.

Remove stale keychain entries (expired, changed reference or account, removed
from the allowlist, or belonging to a profile deleted from the config):

```bash
op-cache sweep
```

## Auto-clear on sleep

`op-cache watch` runs in the foreground and clears every profile the moment
the Mac goes to sleep (for example when the lid closes), so the unlock window
never survives you walking away with the machine. It enumerates cached
profiles from the Keychain itself, so clearing works even when the config is
missing, unreadable, or a profile was removed — it never fails open. Install
it permanently as a LaunchAgent:

```bash
make install-watch     # installs the binary and starts the watcher
make uninstall-watch   # stops and removes the watcher
```

The watcher logs to `~/Library/Logs/op-cache-watch.log`.

By default only system sleep clears the cache, not screen lock: an agent
often keeps working while the screen is locked and you are nearby, and
clearing on every auto-lock would interrupt it. If you want the stricter
behavior, run the watcher with `--lock` (edit the `ProgramArguments` in
`~/Library/LaunchAgents/dev.peter.op-cache.watch.plist` and reload it).

## Why not cache a full 1Password session?

A full session would let the agent query any vault item available to your
account. `op-cache` instead fetches a reviewed allowlist during the single
authenticated operation. This gives repeated commands the convenience you
want while keeping the unattended access scope much smaller.
