# FIDO2 LUKS2 Unlock — Context for gvfs-udisks2 Implementation

This document is a handoff for a new session implementing the **client side** of
FIDO2 token-based LUKS2 unlocking in `gvfs-udisks2-volume-monitor`, building on
a custom `udisks2` fork that already provides the D-Bus API.

---

## Background

`udisks2` upstream does not support FIDO2 security tokens for unlocking LUKS2
encrypted devices (see https://github.com/storaged-project/udisks/issues/1317).
This fork adds that support at the daemon level. The goal of the gvfs work is to
make every GTK file manager (Nautilus, PCmanFM, Thunar, Caja, …) benefit
automatically, since they all delegate encrypted volume mounting to
`gvfs-udisks2-volume-monitor` via GIO.

---

## The udisks2 Fork

**Repository:** https://github.com/LeReverandNox/udisks  
**Branch:** `feat_fido2` (6 commits on top of upstream `8a29c2a4`)

### New D-Bus API on `org.freedesktop.UDisks2.Encrypted`

#### Property: `EnrolledTokenTypes` (`as`, read-only)

Returns the list of unique token type strings enrolled in the LUKS2 header
(e.g. `["systemd-fido2"]`). Empty array if no tokens are enrolled or the device
is not LUKS2.

Use this to decide whether to attempt token-based unlock before falling back to
the standard passphrase `Unlock()` call.

#### Method: `UnlockWithTokens`

```
UnlockWithTokens(options: a{sv}) → cleartext_device: o
```

**Options (all optional):**

| Key                | Type  | Description |
|--------------------|-------|-------------|
| `pin`              | `s`   | PIN for non-UV (non-biometric) FIDO2 tokens. UV tokens ignore this. |
| `passphrase`       | `s`   | Passphrase fallback if all tokens fail. |
| `keyfile_contents` | `ay`  | Keyfile fallback (alternative to passphrase). |
| `read-only`        | `b`   | Open device read-only. |
| `discard`          | `b`   | Enable discard/TRIM. |

**Returns:** Object path of the unlocked cleartext block device.

**Error codes:**

| D-Bus error name | Meaning |
|------------------|---------|
| `org.freedesktop.UDisks2.Error.TokenRequiresPin` | A PIN-requiring token is enrolled but no `pin` was supplied. Prompt user for PIN and retry. |
| `org.freedesktop.UDisks2.Error.TokenNotFound` | A `pin` was supplied but no matching token device was found. Ask user to insert their key. |
| `org.freedesktop.UDisks2.Error.Failed` | Other failure (device not LUKS2, libcryptsetup error, etc.). |

### Unlock behaviour

- Internally uses `crypt_activate_by_token_pin(CRYPT_ANY_TOKEN)` from
  libcryptsetup ≥ 2.6, which iterates all enrolled tokens in LUKS2 header order.
- Each token is handled by its plugin (e.g.
  `/usr/lib/cryptsetup/libcryptsetup-token-systemd-fido2.so`).
- UV tokens (biometric): user touches/scans — no PIN involved.
- PIN tokens: PIN passed directly, no `systemd-ask-password` agent needed.
- If all tokens fail and a `passphrase`/`keyfile_contents` option is present,
  falls back to libblockdev passphrase unlock.
- Authorization reuses the same PolicyKit action as `Encrypted.Unlock()`.

### New error types (udisks/udisksenums.h + udisks/udiskserror.c)

```c
UDISKS_ERROR_TOKEN_NOT_FOUND    → "org.freedesktop.UDisks2.Error.TokenNotFound"
UDISKS_ERROR_TOKEN_REQUIRES_PIN → "org.freedesktop.UDisks2.Error.TokenRequiresPin"
```

---

## What gvfs-udisks2-volume-monitor Needs to Do

### Where to intercept

The relevant code is in `monitor/udisks2/gvfsudisks2volume.c` (or similar path),
specifically the function that handles encrypted volume mounting — look for where
`org.freedesktop.UDisks2.Encrypted.Unlock` is called (likely triggered from
`g_volume_mount()` → `gvfs_udisks2_volume_mount()`).

### Desired flow

```
g_volume_mount() called by file manager
  │
  ├─ Query EnrolledTokenTypes property on the Encrypted interface
  │    └─ if empty or no "systemd-fido2" → skip to standard Unlock() flow
  │
  ├─ Show "Touch your security key…" UI (notification or dialog)
  │
  ├─ Call UnlockWithTokens({})
  │    ├─ SUCCESS → proceed to mount cleartext device (same as after Unlock())
  │    │
  │    ├─ TokenRequiresPin
  │    │    ├─ Show PIN entry dialog (reuse GMountOperation ask-password flow
  │    │    │   or a new dedicated dialog)
  │    │    └─ Retry: UnlockWithTokens({'pin': <user_pin>})
  │    │         ├─ SUCCESS → proceed to mount
  │    │         └─ TokenNotFound → "Insert your security key" message
  │    │
  │    └─ TokenNotFound → "Insert your security key" message
  │
  └─ On any token failure: fall through to standard Unlock() passphrase flow
       (show existing passphrase dialog — no UX regression)
```

### Key implementation notes

- **D-Bus calls**: Use GDBus (`GDBusProxy` or raw `g_dbus_connection_call_sync`).
  gvfs already has extensive GDBus usage — follow existing patterns.

- **PIN prompt**: `GMountOperation` already has `g_mount_operation_ask_password()`
  with `G_ASK_PASSWORD_NEED_PASSWORD`. You can reuse this signal with a custom
  message ("Enter PIN for security key:") to get the PIN from the user without
  new GTK widgets.

- **"Touch your key" feedback**: A short status message before calling
  `UnlockWithTokens` is enough. Could be a GNotification or just the existing
  mount progress callback.

- **LUKS2 check**: `EnrolledTokenTypes` only makes sense on LUKS2. The property
  returns an empty array for non-LUKS2 — no explicit version check needed; just
  check if the array contains `"systemd-fido2"`.

- **No passphrase in the first call**: Always call `UnlockWithTokens({})` first
  without a passphrase. Only add `passphrase` to the options if the token path
  fails entirely and you want a single combined retry — or just fall back to the
  existing `Unlock()` call.

- **Cleartext device mount**: After `UnlockWithTokens` returns the cleartext
  object path, mount it exactly as you would after a successful `Unlock()` call.
  The rest of the gvfs mount flow is unchanged.

---

## Testing Setup

To test locally without installing:

### 1. Run the udisks2 fork (system bus, requires root)

```bash
# Stop system daemon
sudo systemctl stop udisks2

# In the udisks2 fork directory
sudo ./src/udisksd  # (use libtool wrapper, not .libs/udisksd directly)
```

The libtool wrapper sets `LD_LIBRARY_PATH` to pick up the locally built
`libudisks2.so` instead of the system one.

### 2. Run the gvfs monitor (session bus)

```bash
# Kill the running system monitor (it will be D-Bus activated again otherwise)
pkill -f gvfs-udisks2-volume-monitor

# Prevent D-Bus from re-activating the system one (option A: override service file)
# Edit /usr/share/dbus-1/services/org.gtk.vfs.UDisks2VolumeMonitor.service
# to point Exec= at your local build.

# Or option B: replace the binary temporarily
sudo cp /usr/lib/gvfs/gvfs-udisks2-volume-monitor{,.bak}
sudo cp ./your-build/gvfs-udisks2-volume-monitor /usr/lib/gvfs/

# Then trigger re-activation by opening a file manager or:
gdbus call --session \
  --dest org.gtk.vfs.UDisks2VolumeMonitor \
  --object-path / \
  --method org.gtk.vfs.VolumeMonitor.IsSupported
```

### 3. Verify with the Python example

The `examples/fido2-unlock.py` script in the udisks2 fork demonstrates the full
two-step unlock flow using raw D-Bus calls (bypassing gvfs entirely). Use it to
confirm the udisks2 daemon is working correctly before debugging the gvfs layer.

```bash
python examples/fido2-unlock.py /dev/sdXY --passphrase-fallback
```

---

## Relevant Files in gvfs

Expected key files (verify paths in the actual gvfs source):

| File | Role |
|------|------|
| `monitor/udisks2/gvfsudisks2volume.c` | Volume mount logic — main intercept point |
| `monitor/udisks2/gvfsudisks2volumemonitor.c` | Monitor setup and volume discovery |
| `monitor/udisks2/gvfsudisks2utils.c` | GDBus helpers, error mapping |
| `monitor/udisks2/gvfsudisks2drive.c` | Drive/enclosure handling |

The FIDO2 changes will primarily live in `gvfsudisks2volume.c` with possibly a
small helper in `gvfsudisks2utils.c` for the D-Bus property query.

---

## Status

### udisks2 fork (`feat_fido2` branch)
**✅ Complete.** The D-Bus API (`EnrolledTokenTypes` property + `UnlockWithTokens` method), error types, PolicyKit wiring, and libblockdev/libcryptsetup integration are all implemented and tested.

### gvfs-udisks2 (`monitor/udisks2/gvfsudisks2volume.c`)
**✅ Complete.** Implemented and tested in the gvfs fork at
`/home/lereverandnox/src/perso/LeReverandNox/gvfs`.

Implementation highlights:
- Raw GDBus calls (`g_dbus_proxy_call` / `g_dbus_proxy_get_cached_property`) — no compile-time dependency on the fork's generated stubs; degrades gracefully with upstream udisks2.
- `has_fido2_token()` checks `EnrolledTokenTypes`; intercepts the mount flow before `do_unlock()`.
- `do_unlock_with_tokens()` / `unlock_with_tokens_cb()` handle the two-step flow (UV first, then PIN prompt on `TokenRequiresPin`, then passphrase fallback).
- `on_fido2_pin_operation_reply()` reads the PIN via the existing `GMountOperation` `ask-password` / `reply` signals — no new GTK widgets needed.
- Tested with PCmanFM and `gio mount`: UV token (touch-only) and PIN token both unlock correctly. PIN dialog appears in terminal (gio) and as a GUI prompt (PCmanFM).
- `fido2_pin` is freed securely with `secret_password_free()` (matching the passphrase pattern).


| Decision | Rationale |
|----------|-----------|
| `crypt_activate_by_token_pin()` not `crypt_activate_by_token()` | Avoids dependency on `systemd-ask-password` agent being present in the daemon's session |
| Two-step flow (try without PIN, retry with PIN) | Mirrors cryptsetup boot behavior; UV tokens succeed on first call without user friction |
| ENOANO heuristic for error distinction | libcryptsetup returns errno 55 for both "no token matched" and "PIN needed"; we distinguish by whether a PIN was already supplied |
| Passphrase fallback inside `UnlockWithTokens` | Allows a single D-Bus call to handle the full unlock sequence; gvfs can also choose to fall back to `Unlock()` instead |
| PolicyKit action reuse | No new policy files needed; token unlock requires same authorization as passphrase unlock |
