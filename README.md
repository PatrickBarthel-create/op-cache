# op-cache

[Open the visual guide](./op-cache-guide.html) for a graphical explanation of
the unlock flow, Keychain boundary, cache lifecycle, and command interface.

`op-cache` lets a local coding agent use a small, explicit set of 1Password
secrets for a short period without asking for Touch ID on every command.

It is intentionally not a drop-in replacement for `op`. You authenticate once
with `op-cache unlock`, the configured secrets are fetched, and only those
values are cached in macOS Keychain. The default authorization window is eight
hours and the hard maximum is one day.

## Security model

- Every profile has an explicit environment-variable-to-`op://` allowlist.
- Each profile can point at its own 1Password account and gets its own
  Keychain service, so private and work secrets stay separated.
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

Requirements: macOS 13 or newer, Swift, and the 1Password CLI (`op`) at
`/opt/homebrew/bin/op` or `/usr/local/bin/op` with desktop-app integration
enabled.

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
  "defaultTTL": "8h",
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

TTL values support `s`, `m`, `h`, and `d`, for example `30m` or `8h`.

## Use

Authenticate once and prefetch the allowlist:

```bash
op-cache unlock private --ttl 8h
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

## Unlock every vault (Everlast fork only)

`unlock --all` prefetches every item of every vault in every account `op`
knows, so later calls are answered from cache even the first time a secret is
asked for:

```bash
op-cache unlock --all                      # every account
op-cache unlock --all --account everlast   # one account
op-cache status _items                     # what is open, and until when
op-cache clear _items                      # close it again
```

Measured on the machine this was built for: 991 items across 16 vaults in two
accounts, about two and a half minutes at six concurrent workers, one biometric
approval per account. Afterwards 991 of 992 items answer without any approval
(the remaining one is broken in 1Password itself).

This works because prefetched items are keyed by **where they live** - account,
vault, item - rather than by a digest of the argument vector. One stored copy
therefore answers `op read`, `op item get --fields` and `op item get --format
json` alike, addressed by title or by ID, with or without `--account`.

Three rules keep it honest, each of them measured against the real `op`:

- **A reference `op` refuses is refused here too.** Its parser accepts only
  letters, digits, space, `_`, `-`, `.` and `=` in a segment. Without that
  rule the cache answered 32 of 240 sampled calls that `op` itself rejects,
  for items named like `[CLI] N8N API Key | Ajdamirova`.
- **An ambiguous name is never resolved.** `op` matches items by their URLs as
  well as their titles, so `telnyx.com` can mean two items and `op` says so.
  The index carries the URLs to see the same ambiguity and forwards the call.
- **One-time passwords never come from cache.** `--format json` returns both
  the current code and the seed. The seed is stripped before storing, and any
  path that would return an OTP field is forwarded instead.

Output shapes that cannot be reproduced are forwarded rather than guessed: the
default human format prints relative timestamps, and `--fields` combined with
`--format json` is its own shape. Both still work, they just cost an approval.

### What this costs

For the duration of the TTL, every field of every item is readable from the
Keychain without an approval by any process running as this user. That is the
point of it, and it is a deliberate widening far beyond the upstream
allowlist. `op-cache status _items` says how much is open; `op-cache clear
_items` closes it.

One operational note: macOS grants Keychain access per entry and per program,
and a rebuilt binary is a different program. Items are therefore bundled one
entry per vault rather than one per item - 16 confirmations after an update
instead of 990 - and running `unlock --all` once after installing a new build
avoids them entirely, because then the running binary is the one that wrote
them.

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

## Audit log

`unlock` and `run` each append one JSON object to
`~/Library/Logs/op-cache-audit.jsonl`: which allowlisted secret was involved,
the `op://` reference naming its vault, item, and field, and for `run` the
child executable it was injected into.

```json
{"account":"team.1password.com","argumentCount":2,"caller":{"path":"/bin/zsh","pid":73907},"command":"npm","event":"run","profile":"work","secrets":[{"name":"CLOUDFLARE_API_TOKEN","reference":"op://Development/Cloudflare/credential"}],"timestamp":"2026-07-16T15:22:33Z"}
```

Values are never written. Neither are the child's arguments: a command line is
free-form and routinely carries secrets of its own, and a log that leaks them
defeats its own purpose.

Read it with `tail -f ~/Library/Logs/op-cache-audit.jsonl | jq`. Turn it off or
move it in the config:

```json
{ "audit": { "enabled": false } }
{ "audit": { "path": "~/logs/op-cache.jsonl" } }
```

### What it does and does not tell you

This is an injection log, not an access log.

- `unlock` is the only command that reaches 1Password, and it fetches the whole
  profile in one go. Its entry records what you authorized, not what anything
  turned out to need.
- `run` records what went into the child's environment. Without `--only` that is
  every secret in the profile, whether the child reads one of them or none. The
  log measures the call, not the use.
- Once a value is in the child's environment, op-cache is out of the picture.
  The log cannot show what the child did with it or where it sent it.
- A process that can run op-cache runs as your user and can rewrite this file.
  The log is not tamper-evident and will not catch a hostile agent.

It is useful for seeing what your own tooling actually touches, and for spotting
allowlisted secrets that nothing has needed in weeks. Those belong out of the
profile, and removing them shrinks the unattended blast radius in a way the log
itself does not.

A write failure warns on stderr and does not fail the command. The cache is the
security boundary; failing closed here would only hand any caller a way to break
`run` by deleting a file.

## Why not cache a full 1Password session?

A full session would let the agent query any vault item available to your
account. `op-cache` instead fetches a reviewed allowlist during the single
authenticated operation. This gives repeated commands the convenience you
want while keeping the unattended access scope much smaller.
