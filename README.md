# op-wrapper.py

`op-wrapper.py` closes the gap left by 1Password's `op read` authorization prompt: it does not show which item or field is being requested. The wrapper adds that context, plus an optional reason, to the requesting application's label. This is a visual aid, not a limit on what an approval can access.

Requests for more context in CLI approval prompts have appeared in the [1Password community](https://www.1password.community/developers-69/add-more-detail-to-cli-access-request-modal-24695), with a similar [item-specific approval request dating to 2022](https://www.reddit.com/r/1Password/comments/tgn2r5/).

The wrapper is most useful for scripts and LLM agents, where the approval prompt can show what is being requested, such as an item or field, and why if a reason is supplied. For interactive use, running `op` directly can reuse an existing CLI authorization. The wrapper may prompt again even when the same command would run without a prompt in your terminal.

## Quick start

Requirements: Linux with a graphical session, Python 3, GTK 3 Python bindings (`gi`), and the 1Password CLI on `PATH`.

```sh
make check
./op-wrapper.py 'op://private/password-item/key'
./op-wrapper.py 'op://private/password-item/key' 'provided reason for request'
./op-wrapper.py item get 'password-item' --vault private --reason 'backup'
./op-wrapper.py item list --vault private --reason 'inventory'
./op-wrapper.py vault list --account my-account
./op-wrapper.py account list
```

Field reads label the request with the item path, for example `password-item/key`. Whole-item and list requests use labels such as `WHOLE ITEM: password-item: backup` and `LIST ITEMS: inventory`. Labels omit vault and account selectors and append the reason when supplied. Prompt appearance can vary by desktop and 1Password version. Listing locally configured accounts and reusing an authorized session may complete without a prompt.

`item get` requires `--vault` and retrieves every field in the item. `item list` returns item summaries and excludes archived items by default, subject to the CLI environment. Both accept `--account`, as does `vault list`. `account list` only accepts `--reason`. These commands validate the JSON response and write its original bytes to stdout.

## Python usage

With the repository on Python's import path, call from the main thread or a worker thread:

```python
from lib.opread import OpreadError, get_item, list_accounts, list_items, list_vaults, read

try:
    credential = read("op://private/password-item/key", "provided reason for request")
except OpreadError as error:
    print(f"Read failed with status {error.returncode}")
```

`read` returns the exact credential bytes on success and raises `OpreadError` with a `returncode` on failure. The optional keyword-only `env` mapping replaces the inherited environment, as with `subprocess`; it is copied once per call. If omitted, the current process environment is copied once. Include any required `PATH`, display, and 1Password configuration variables. A missing `PATH` uses the system default search path. Concurrent calls can use separate account or configuration settings without changing the process environment, but this does not isolate or alter 1Password sessions.

The Python APIs suppress subprocess stderr and write no library-controlled diagnostics or credential output to the caller's stdout or stderr. Ordinary exceptions during a read become `OpreadError` with a status and a fixed message. Invalid timeout values raise `ValueError` with a fixed message. These exceptions have no chained causes or contexts, and ordinary tracebacks omit the internal frames where the failure occurred. This guarantee covers diagnostics controlled by the library after function entry. Caller source lines, callback output, debugger locals, and argument-binding errors can still expose caller-supplied data. Process-control exceptions such as `KeyboardInterrupt` and `SystemExit` propagate to the caller with their original tracebacks. The CLI continues to report diagnostics on stderr, including subprocess stderr for legacy field reads. Whole-item and list commands suppress subprocess stderr.

The Python APIs accept keyword-only `timeout` and `cancel` (an Event-compatible object with `is_set()`). A timeout is a nonnegative number of seconds that yields a finite floating-point deadline. `None` means no total deadline. A zero timeout expires immediately. `OpreadTimeoutError` and `OpreadCancelledError` subclass `OpreadError`, with statuses 124 and 130. Cancellation wins if both controls are observed together. A single monotonic deadline covers CLI identity probes, helper setup, execution, and collection. Probes also have their own three-second maximum. Controls are rechecked after parsing and cleanup before a successful result is returned; an existing failure retains its status.

```python
from threading import Event

cancel = Event()  # Another thread can call cancel.set().
item = get_item("item name or ID", "backup", vault="vault name or ID",
                account="account name or ID", timeout=60, cancel=cancel)
items = list_items("inventory", vault="vault name or ID", timeout=60)
vaults = list_vaults(account="account name or ID", timeout=60)
accounts = list_accounts(timeout=60)
```

`get_item` returns a `dict` and the three list functions return lists of dicts. All four run their corresponding read-only `op` subcommands with `--format json` and parse the response once after strict UTF-8 decoding. Validation rejects unexpected response shapes, NaN, and Infinity. An explicit account overrides `OP_ACCOUNT` in the copied environment for the call. Item, vault, and account selectors must be nonempty, at most 4096 UTF-8 bytes, contain no control characters, and start with a character other than `-`.

Python callers own process signal handling and cancellation. `Future.cancel()` cannot stop a read that is already running. Normal exceptions clean up the helper, but an abrupt default SIGTERM or SIGHUP can terminate the process before cleanup. The CLI manages these signals itself, preserving its interrupt statuses and restoring previous handlers.

Cleanup sends TERM then KILL to each acquired helper/probe process group and shares one total five-second cleanup allowance across the call. Leader exit is monitored separately from pipe EOF so inherited pipes cannot cause an unlimited wait. Abandoned pipes are closed and incomplete output is rejected. Descendants that escape the process group cannot be killed through that group; retained pipes still have a bounded drain. Blocking operating-system calls (including process creation and filesystem operations) can delay observation of controls, so the timeout is cooperative rather than a hard wall-clock guarantee.

The CLI buffers the complete credential in memory and writes it to standard output only after a successful read; partial output from a failed read is suppressed. Large credentials therefore require corresponding memory. A later output write failure can still leave a partial write.

## Prompt comparison

Screenshots use made-up references (`op://private/item/key` for `op read` and `op://private/password-item/key` for `opread`); the vault name was replaced with “YourVaultName” and the account icon removed for privacy. Both prompts were dismissed without approval.

| `op read` | `opread` with a reason |
| --- | --- |
| ![Plain op read prompt](docs/images/op-read-prompt.png) | ![opread prompt showing password-item/key: provided reason for request](docs/images/opread-prompt.png) |

## Limits

- The label provides context only. It does not restrict an approval to an item or field. 1Password controls authorization scope and session reuse; see [CLI app integration security](https://www.1password.dev/cli/app-integration-security).
- `op-wrapper.py` supports field reads and the four JSON commands shown above. Each command accepts only its documented arguments. A reason must be 1–128 UTF-8 bytes and must not start with `-` or be `.` or `..`.
- The item path and reason appear in process and desktop metadata. Do not put secrets in either.
- The GUI helper uses a transparent, undecorated window in the graphical session. The Linux Wayland/Sway path has been exercised; X11 has not been verified live.
- `make check` probes the CLI and runtime without reading credentials. `make test` runs offline tests.

## TODO

- [ ] Explore making the helper window less visible (hidden, floating, or 1×1), or document window-manager support.

  Setting `set_resizable(False)` was observed to make 1Password show `footclient` instead of the requested description. The helper leaves resizing enabled; the underlying mechanism is not confirmed.
- [ ] Consider detecting and showing the original calling client (for example, Codex).
- [ ] Test and adjust for macOS.
- [ ] Provide a thin, transparent wrapper that can replace `op` for existing commands and scripts.
- [ ] Support existing `op` flags and options.

## How it works

- Validates the reference or selectors and optional reason and checks the `op` executable on `PATH`.
- Starts a temporary GTK helper with the request label as its window and application identity. The executable uses a filesystem-safe, length-limited name.
- Runs the fixed `op` command as the helper's child, closes the window 300 ms later, forwards output and exit status, and removes the temporary helper afterward. The prompt label with delayed closure still needs verification.

## Flag reference

This comparison uses the help output from 1Password CLI 2.41.1.

| Operation | Options accepted by the wrapper | Native command options rejected by the wrapper |
| --- | --- | --- |
| Field read (`REF [REASON]`) | Optional final positional reason | `--file-mode`, `-f` / `--force`, `-n` / `--no-newline`, `-o` / `--out-file` |
| `item get ITEM` | Required `--vault VAULT`, optional `--account ACCOUNT` and `--reason REASON` | `--fields`, `--include-archive`, `--otp`, `--reveal`, `--share-link` |
| `item list` | Optional `--vault VAULT`, `--account ACCOUNT`, and `--reason REASON` | `--categories`, `--favorite`, `--include-archive`, `--long`, `--tags` |
| `vault list` | Optional `--account ACCOUNT` and `--reason REASON` | `--group`, `--permission`, `--user` |
| `account list` | Optional `--reason REASON` | No additional native command options |

The wrapper handles `-h` / `--help` itself. When supplying `--reason REASON`, put it last.

The wrapper adds `--format json` internally for `item get` and all three list commands. Passing `--json`, `--format json`, or `--format=json` to the wrapper is unsupported. Field reads return the field bytes.

Other unsupported global `op` flags are `--cache`, `--config`, `--debug`, `--encoding`, `--iso-timestamps`, `--no-color`, `--session`, and `-v` / `--version`. Use `--account` only on the commands listed above.

Unsupported flags cause the wrapper to exit with status 2 before invoking `op`. For unsupported flags, the command parser reports `op-wrapper: invalid or unsupported arguments` without naming the rejected flag.
