# GitHub Copilot Instructions for UDisks

UDisks is a C/GObject daemon, client library, and CLI tool for managing storage devices over D-Bus on Linux. The daemon (`udisksd`) exposes block devices, drives, filesystems, encrypted volumes, and RAID arrays via the `org.freedesktop.UDisks2` D-Bus service, with a pluggable module system for LVM2, iSCSI, Btrfs, and libStorageManagement.

## Build Commands

```bash
# Bootstrap (first time or after configure.ac changes)
./autogen.sh

# Standard development build with all modules and debug symbols
./autogen.sh --enable-modules --enable-debug && make

# Build specific module only
./configure --enable-lvm2 && make -C modules/lvm2

# Run daemon from build tree without installing
./udisksd --debug --uninstalled --force-load-modules
```

## Test Commands

```bash
# Unit tests (C-based, no root needed)
make unittests
cd src/tests && ./udisks-test

# D-Bus integration tests (require root and virtual SCSI devices via targetcli)
make dbus-tests
sudo python3 src/tests/dbus-tests/run_tests.py -l dbus_tests.log

# Run a single test file
sudo python3 src/tests/dbus-tests/run_tests.py -t test_50_block

# Run a single test class/method
sudo python3 -m pytest src/tests/dbus-tests/test_50_block.py::UDisksBlockTest::test_format

# Integration tests
make integration-tests

# Full CI suite
make ci
```

## Architecture

```
Client (udisksctl / libsudisks)
    └─► D-Bus system bus
            └─► udisksd daemon (src/)
                    ├── UDisksDaemon       – central orchestrator (udisksdaemon.c)
                    ├── UDisksLinuxProvider – monitors udev events, creates objects
                    ├── GDBus ObjectManager – exports objects at /org/freedesktop/UDisks2/
                    │       ├── block_devices/sda, sda1, ...
                    │       ├── drives/<serial>
                    │       ├── mdraids/<uuid>
                    │       └── jobs/1, 2, ...
                    ├── Job system          – SimpleJob / ThreadedJob / SpawnedJob
                    ├── State manager       – persistent state in ~/.local/share/udisks2/
                    └── ModuleManager       – loads .so plugins from $(libdir)/udisks2/modules/
                            ├── lvm2  module
                            ├── iscsi module
                            ├── btrfs module
                            └── lsm   module
```

**Layers to understand:**

- `src/` — daemon (GPLv2+): device objects, jobs, state, mount/crypt monitoring
- `udisks/` — client library (LGPLv2+): D-Bus proxies, `UDisksClient`, `UDisksObjectInfo`
- `modules/<name>/` — optional plugins: each provides a manager + per-device interface implementations
- `tools/` — `udisksctl` CLI, `umount-udisks` helper
- `data/org.freedesktop.UDisks2.xml` — authoritative D-Bus interface definitions (169 KB)

The generated file `udisks-generated.[ch]` (produced by `gdbus-codegen` from the XML) provides type-safe skeleton/proxy classes for every D-Bus interface. **Never edit it by hand.**

## Key Conventions

### Naming

| What | Pattern | Example |
|------|---------|---------|
| Types | `UDisks<Component>` | `UDisksLinuxBlock` |
| Functions | `udisks_<component>_<verb>` | `udisks_linux_block_update` |
| Macros / constants | `UDISKS_<COMPONENT>_<NAME>` | `UDISKS_TYPE_LINUX_BLOCK` |
| Linux-specific impls | `udisks_linux_*` | `UDisksLinuxFilesystem` |
| Module files | `udiskslinux<module>*.[ch]` | `udiskslinuxmanagerlvm2.c` |

### GObject pattern

Every object follows the standard GObject pattern:

```c
/* Required emacs/editor mode line at the top of every new file */
/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */

G_DEFINE_TYPE_WITH_CODE (UDisksLinuxBlock, udisks_linux_block,
                         UDISKS_TYPE_BLOCK_SKELETON, ...)

static void
udisks_linux_block_class_init (UDisksLinuxBlockClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize = udisks_linux_block_finalize;
}

static void
udisks_linux_block_init (UDisksLinuxBlock *block) { ... }
```

### Error handling

```c
/* Preconditions */
g_return_val_if_fail (object != NULL, FALSE);

/* Propagating GErrors — gboolean: TRUE = success */
if (!udisks_foo_do_thing (foo, &error))
  {
    g_dbus_method_invocation_take_error (invocation, error);
    return TRUE;  /* method handler always returns TRUE */
  }

/* Setting errors */
g_set_error (error, UDISKS_ERROR, UDISKS_ERROR_FAILED,
             "Failed to do X: %s", g_strerror (errno));
```

D-Bus method handlers always `return TRUE` (even on error) — returning FALSE is reserved for "not handled by this object".

### Memory management

Use GLib conventions: `g_autofree`, `g_autoptr()`, `g_object_ref()`/`g_object_unref()`, `g_strdup()`/`g_free()`. Avoid manual `free()`.

### Adding a D-Bus interface

1. Define the interface in `data/org.freedesktop.UDisks2.xml` (or `modules/<name>/data/`)
2. Re-run `make` to regenerate `udisks-generated.[ch]`
3. Implement the skeleton in `src/udiskslinux<component>.c`, inheriting from the generated `*Skeleton` class
4. Register the interface on the appropriate object in `udiskslinux<component>object.c`
5. Add a PolicyKit action in the `.policy.in` file if the method needs authorization

### FIDO2 / security token unlock

The `UDisksEncrypted` interface exposes two additions for FIDO2 support:

- **`EnrolledTokenTypes` (as)** — read-only property populated on LUKS devices during
  `udisks_linux_encrypted_update()`. Contains unique token type strings found in the LUKS2
  header (e.g. `["systemd-fido2"]`). Empty for non-LUKS2 or devices with no tokens.
  Implemented in `src/udisksfido2.c` using `crypt_token_status()` from libcryptsetup.

- **`UnlockWithTokens(options) → cleartext_device`** — unlocks via enrolled tokens (LUKS2 only).
  Calls `crypt_activate_by_token(CRYPT_ANY_TOKEN)` in a `ThreadedJob`; libcryptsetup iterates
  tokens in header order and the installed plugin (e.g. `libcryptsetup-plugin-systemd-fido2`)
  handles PIN prompting via `systemd-ask-password` and user-presence waiting via `libfido2`.
  Falls back to passphrase if `passphrase`/`keyfile_contents` provided in options and all
  tokens fail. Implemented in `src/udiskslinuxencrypted.c` (`handle_unlock_with_tokens`) and
  `src/udiskslinuxencryptedhelpers.c` (`luks_open_with_tokens_job_func`).

libcryptsetup is an explicit dependency (>= 2.4) added alongside libblockdev — libblockdev
does not support token-based unlock. The `Lock()` path is unchanged; the cleartext device
produced by `UnlockWithTokens()` is identical to one from `Unlock()`.

### Adding a module

A module is a shared library exposing two entry points:

```c
gchar       *udisks_module_id  (void);                        // unique name
UDisksModule *udisks_module_new (UDisksDaemon *, GCancellable *, GError **);
```

Override virtual methods on `UDisksModule` (`new_manager`, `new_block_object_interface`, `handle_uevent`, …) and add a conditional `AC_ARG_ENABLE` block in `configure.ac` plus an `if HAVE_<MODULE>` guard in `modules/Makefile.am`.

### Coding style

- **Spaces only** (no tabs); 2-space indent
- GNU brace style (opening `{` on the same line for control flow, new line for function bodies)
- The emacs/vi mode line `/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */` is required at the top of every new C file
- All external interfaces (D-Bus, file formats, network protocols) must be documented in man pages or the XML interface file

### Commit messages

```
Short one-line summary (capital first letter, no trailing period)

Longer explanation of what changed, why, and any interface changes.
Reference bug tracker issues where applicable.
```

When using LLM assistance, the commit message must include one of: `Assisted-by:`, `Generated-By:`, or `Co-Authored-By:` as a trailer.
