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
  path that would return an OTP field is forwarded instead. The forwarded
  result is then not stored either: the digest cache refuses `--otp`,
  `?attribute=otp` and `--fields type=otp` up front, and inspects everything
  else it is about to store - an `otpauth://` URI, a bare base32 seed, a JSON
  field of type OTP in any shape, or a six-to-eight-digit code (alone or as a
  CSV column) is forwarded but never kept.

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

### Proxied calls (Everlast fork only)

Every `op` call through the shim is recorded too, cached or not, and each entry
names what the call asked for: the `op://` reference for `read`, the item name
(with its vault when one was given) for `item get`, and for a call that names no
operand - `inject -i file`, `run`, `item list` - the subcommand itself. Never a
field value: an operand of the form `field=value` is an assignment and is
dropped, and after a verb `op` does not know the only thing taken is an `op://`
reference.

## Keeping the cache warm, and hearing what it answers (Everlast fork only)

Once every vault is prefetched nothing prompts, and the prompt was the only
signal that something read a credential. Two LaunchAgents replace it:

```bash
make install-warm      # re-runs unlock --all when the prefetch has lapsed
make install-notify    # watches the audit log and raises notifications
make uninstall-warm; make uninstall-notify
```

`op-cache-warm` runs hourly. It warms when `status _items` shows nothing
unlocked, or when the last unlock reported a skipped account (the marker in
`~/.local/state/op-cache-warm/`; a vault count would not do, because empty
vaults do not count as unlocked). Never while the screen is locked, and never outside
`OP_CACHE_WARM_START`-`OP_CACHE_WARM_END` (7-24: the screen lock is the real guard). An unreadable status is an
error, not a cold cache: a crashed status command must not turn into a
biometric prompt. The cost is one approval per account every three days -
plus one after every write to 1Password through `op` (`item edit`, `item
create`, …): a write drops the prefetch, because a renamed or rotated item
must not be answered from a stale copy (the digest cache goes with it), and
the proxy then kicks the agent so the rebuild happens while you are still at
the keyboard - subject to the same screen-lock and working-hours rules as any
run. A partial warm-up (an account did not approve, or listed no vaults) is
retried once on the next tick and after that at most every six hours. An
approval dialog left unanswered runs into op's own timeout; measured on the
first evening, one stood open for 70 minutes before that.

The first live run listed three accounts on this machine where the notes
knew two; every account `op` is signed into prompts on its own, so a full
warm-up costs one approval per account, not one.

`op-cache-notify` runs every minute and raises a macOS notification for:

- a reference or item asked for fewer than `rare_threshold` times (3) in the
  trailing `rare_window_days` (7) - the class a process you did not expect
  falls into, since the routine working set is small and repetitive. The
  banner says which request number this is and lists the least-seen first; the
  full list goes to `~/Library/Logs/op-cache-notify.log`.
- more than `rate_threshold` requests (50) in the trailing hour, at most once
  per `rate_cooldown_minutes` (60).

Settings live in `~/.config/op-cache/notify.json`; every key falls back to its
default when missing or wrongly typed. Counts live in
`~/.local/state/op-cache-notify/state.json` (0600), not in the log, so a log
rotation does not make every routine reference look new. The first run after
an install only records the baseline and stays silent.

Measured before choosing the burst threshold: the median hour on this machine
carries 55 requests and the busiest 523, so 50 warns in more than half of all
working hours. It is what was asked for; raise it once the banner stops
meaning anything.

Tests: `tools/tests/op-cache-notify-test` and `tools/tests/op-cache-warm-test`
run both tools against synthetic logs and a stub `op-cache`, so neither test
ever reaches 1Password.

## Why not cache a full 1Password session?

A full session would let the agent query any vault item available to your
account. `op-cache` instead fetches a reviewed allowlist during the single
authenticated operation. This gives repeated commands the convenience you
want while keeping the unattended access scope much smaller.
