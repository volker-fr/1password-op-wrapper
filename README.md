# opread

`opread` closes the gap left by 1Password's `op read` authorization prompt: it does not show which item or field is being requested. `opread` adds that context, plus an optional reason, to the requesting application's label. This is a visual aid, not a limit on what an approval can access.

Requests for more context in CLI approval prompts have appeared in the [1Password community](https://www.1password.community/developers-69/add-more-detail-to-cli-access-request-modal-24695), with a similar [item-specific approval request dating to 2022](https://www.reddit.com/r/1Password/comments/tgn2r5/).

## Quick start

Requirements: Linux with a graphical session, Python 3, GTK 3 Python bindings (`gi`), and the 1Password CLI on `PATH`.

```sh
make check
./opread.py 'op://private/password-item/key'
./opread.py 'op://private/password-item/key' 'provided reason for request'
```

The requested labels are `password-item/key` and `password-item/key: provided reason for request`. The vault name is omitted. The reason is supplied explicitly; it is not detected automatically. Prompt appearance can vary by desktop and 1Password version.

## Python usage

With the repository on Python's import path, call from the main thread or a worker thread:

```python
from lib.opread import OpreadError, read, get_item

try:
    credential = read("op://private/password-item/key", "provided reason for request")
except OpreadError as error:
    print(f"Read failed with status {error.returncode}")
```

`read` returns the exact credential bytes on success and raises `OpreadError` with a `returncode` on failure. Diagnostics go to standard error. The optional keyword-only `env` mapping replaces the inherited environment, as with `subprocess`; it is copied once per call. If omitted, the current process environment is copied once. Include any required `PATH`, display, and 1Password configuration variables. A missing `PATH` uses the system default search path. Concurrent calls can use separate account or configuration settings without changing the process environment, but this does not isolate or alter 1Password sessions.

Both APIs accept keyword-only `timeout` (finite, nonnegative seconds; `None` means no total deadline) and `cancel` (an Event-compatible object with `is_set()`). A zero timeout expires immediately. `OpreadTimeoutError` and `OpreadCancelledError` subclass `OpreadError`, with statuses 124 and 130. Cancellation wins if both controls are observed together. A single monotonic deadline covers CLI identity probes, helper setup, execution, and collection. Probes also have their own three-second maximum. Controls are rechecked after parsing and cleanup before a successful result is returned; an existing failure retains its status.

```python
from threading import Event

cancel = Event()  # Another thread can call cancel.set().
item = get_item("item name or ID", "backup", vault="vault name or ID",
                      account="account name or ID", timeout=60, cancel=cancel)
```

`get_item` runs only `op item get ITEM --vault VAULT --format json`, with `--account ACCOUNT` when provided. The vault is required; an explicit account overrides `OP_ACCOUNT` for the call. Item, vault, and account selectors must be nonempty, at most 4096 UTF-8 bytes, contain no control characters, and not start with `-`. The prompt label starts with `WHOLE ITEM:` and shows the item and optional reason, omitting account and vault. This request retrieves every field in the item. Success returns the Python `dict` produced by a single JSON parse after strict UTF-8 decoding and JSON object validation (including rejection of NaN and Infinity). Whole-item standard error is captured, drained, and suppressed, and failure diagnostics do not include subprocess or payload exception text. Field-read diagnostics continue to inherit standard error. The CLI remains limited to field references; whole-item reads use the Python API.

Neither API installs process signal handlers. The caller owns signal handling and cancellation; `Future.cancel()` cannot stop a read that is already running. Normal exceptions clean up the helper, but an abrupt default SIGTERM or SIGHUP can terminate the process before cleanup. The CLI manages these signals itself, preserving its interrupt statuses and restoring previous handlers.

Cleanup sends TERM then KILL to each acquired helper/probe process group and shares one total five-second cleanup allowance across the call. Leader exit is monitored separately from pipe EOF so inherited pipes cannot cause an unlimited wait. Abandoned pipes are closed and incomplete output is rejected. Descendants that escape the process group cannot be killed through that group; retained pipes still have a bounded drain. Blocking operating-system calls (including process creation and filesystem operations) can delay observation of controls, so the timeout is cooperative rather than a hard wall-clock guarantee.

The CLI buffers the complete credential in memory and writes it to standard output only after a successful read; partial output from a failed read is suppressed. Large credentials therefore require corresponding memory. A later output write failure can still leave a partial write.

## Prompt comparison

Screenshots use made-up references (`op://private/item/key` for `op read` and `op://private/password-item/key` for `opread`); the vault name was replaced with “YourVaultName” and the account icon removed for privacy. Both prompts were dismissed without approval.

| `op read` | `opread` with a reason |
| --- | --- |
| ![Plain op read prompt](docs/images/op-read-prompt.png) | ![opread prompt showing password-item/key: provided reason for request](docs/images/opread-prompt.png) |

## Limits

- The label provides context only. It does not restrict an approval to an item or field. 1Password controls authorization scope and session reuse; see [CLI app integration security](https://www.1password.dev/cli/app-integration-security).
- Only the reference and optional reason are supported; extra `op read` options are not forwarded. A reason must be 1–128 UTF-8 bytes and must not start with `-` or be `.` or `..`.
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

- Validates the reference and optional reason and checks the `op` executable on `PATH`.
- Starts a temporary GTK helper with the item path and reason as its window and application identity. The executable uses a filesystem-safe, length-limited name.
- Runs `op read` as the helper's child, closes the window 300 ms later, forwards output and exit status, and removes the temporary helper afterward. The prompt label with delayed closure still needs verification.
