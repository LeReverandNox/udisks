#!/usr/bin/env python3
"""
fido2-unlock.py — Example client for UDisks2 FIDO2 token-based LUKS2 unlock.

Demonstrates how a graphical application (file manager, disk utility, …) should
use the UDisks2 D-Bus API to unlock a LUKS2 device with an enrolled FIDO2 key.

Flow:
  1. Discover LUKS2 block object for the given device.
  2. Check EnrolledTokenTypes — skip FIDO2 path if no "systemd-fido2" token enrolled.
  3. Call UnlockWithTokens({}) — succeeds immediately for UV (biometric) tokens.
  4. On TokenRequiresPin error — prompt for PIN and retry.
  5. On TokenNotFound error — inform user to insert their security key.
  6. On any other failure (or if user cancels PIN prompt) — fall back to passphrase.

Usage:
    python3 fido2-unlock.py /dev/sdXY
    python3 fido2-unlock.py /dev/sdXY --passphrase-fallback

Requires:
    - udisks2 with FIDO2 support (this fork)
    - python-dbus  (or dbus-python)
    - The systemd FIDO2 token plugin installed:
        Arch:   libcryptsetup-plugin-systemd-fido2  (part of systemd package)
        Debian: libcryptsetup-plugin-systemd (in systemd package)
"""

import argparse
import getpass
import sys

try:
    import dbus
except ImportError:
    sys.exit("Error: python-dbus is required. Install with: pip install dbus-python")

UDISKS2_BUS_NAME    = "org.freedesktop.UDisks2"
UDISKS2_OBJECT_PATH = "/org/freedesktop/UDisks2"
OBJECT_MANAGER_IFACE = "org.freedesktop.DBus.ObjectManager"
BLOCK_IFACE          = "org.freedesktop.UDisks2.Block"
ENCRYPTED_IFACE      = "org.freedesktop.UDisks2.Encrypted"

TOKEN_REQUIRES_PIN = "org.freedesktop.UDisks2.Error.TokenRequiresPin"
TOKEN_NOT_FOUND    = "org.freedesktop.UDisks2.Error.TokenNotFound"


def get_system_bus() -> dbus.SystemBus:
    return dbus.SystemBus()


def find_block_object(bus: dbus.SystemBus, device: str):
    """Return (object_path, encrypted_iface) for the given device path, or exit."""
    manager = bus.get_object(UDISKS2_BUS_NAME, UDISKS2_OBJECT_PATH)
    objects = manager.GetManagedObjects(dbus_interface=OBJECT_MANAGER_IFACE)

    for path, interfaces in objects.items():
        if BLOCK_IFACE not in interfaces:
            continue
        block = interfaces[BLOCK_IFACE]
        # UDisks2 exposes device as a byte array; decode for comparison
        dev_bytes = bytes(block.get("Device", b"")).rstrip(b"\x00")
        if dev_bytes.decode() == device:
            if ENCRYPTED_IFACE not in interfaces:
                sys.exit(f"Error: {device} is not an encrypted device.")
            return path, interfaces[ENCRYPTED_IFACE]

    sys.exit(f"Error: No UDisks2 block object found for {device}.")


def has_fido2_token(encrypted_props: dict) -> bool:
    token_types = list(encrypted_props.get("EnrolledTokenTypes", []))
    return "systemd-fido2" in token_types


def unlock_with_tokens(bus: dbus.SystemBus, object_path: str, pin: str | None = None) -> str:
    """Call UnlockWithTokens(). Returns cleartext device object path."""
    encrypted = bus.get_object(UDISKS2_BUS_NAME, object_path)
    options: dict = {}
    if pin is not None:
        options["pin"] = dbus.String(pin)
    cleartext = encrypted.UnlockWithTokens(
        options,
        dbus_interface=ENCRYPTED_IFACE,
    )
    return str(cleartext)


def unlock_with_passphrase(bus: dbus.SystemBus, object_path: str, passphrase: str) -> str:
    """Fall back to classic passphrase-based unlock."""
    encrypted = bus.get_object(UDISKS2_BUS_NAME, object_path)
    cleartext = encrypted.Unlock(
        passphrase,
        {},
        dbus_interface=ENCRYPTED_IFACE,
    )
    return str(cleartext)


def prompt_pin(device: str) -> str | None:
    """Prompt for FIDO2 token PIN. Returns None if user cancels."""
    try:
        return getpass.getpass(f"Enter PIN for security key ({device}): ")
    except (KeyboardInterrupt, EOFError):
        return None


def prompt_passphrase(device: str) -> str | None:
    """Prompt for fallback passphrase. Returns None if user cancels."""
    try:
        return getpass.getpass(f"Enter passphrase for {device}: ")
    except (KeyboardInterrupt, EOFError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("device", help="Device path (e.g. /dev/sda2)")
    parser.add_argument(
        "--passphrase-fallback",
        action="store_true",
        help="Prompt for passphrase if token-based unlock fails",
    )
    args = parser.parse_args()

    bus = get_system_bus()
    object_path, encrypted_props = find_block_object(bus, args.device)

    # ── Step 1: Check if any FIDO2 token is enrolled ────────────────────────
    if not has_fido2_token(encrypted_props):
        print(f"No FIDO2 tokens enrolled on {args.device}.")
        if not args.passphrase_fallback:
            sys.exit(1)
        passphrase = prompt_passphrase(args.device)
        if passphrase is None:
            sys.exit("Cancelled.")
        cleartext = unlock_with_passphrase(bus, object_path, passphrase)
        print(f"Unlocked (passphrase): {cleartext}")
        return

    # ── Step 2: Try token-based unlock (no PIN yet — works for UV tokens) ───
    print("Touch your security key…", flush=True)
    try:
        cleartext = unlock_with_tokens(bus, object_path)
        print(f"Unlocked: {cleartext}")
        return

    except dbus.DBusException as exc:
        error_name = exc.get_dbus_name()

        if error_name == TOKEN_REQUIRES_PIN:
            # ── Step 3: PIN required — prompt and retry ──────────────────
            pin = prompt_pin(args.device)
            if pin is None:
                sys.exit("Cancelled.")
            try:
                cleartext = unlock_with_tokens(bus, object_path, pin=pin)
                print(f"Unlocked: {cleartext}")
                return
            except dbus.DBusException as exc2:
                error_name2 = exc2.get_dbus_name()
                if error_name2 == TOKEN_NOT_FOUND:
                    print("Security key not found or not recognized.")
                else:
                    print(f"Token unlock failed: {exc2.get_dbus_message()}")

        elif error_name == TOKEN_NOT_FOUND:
            print("Security key not found. Insert your key and try again.")

        else:
            print(f"Token unlock failed: {exc.get_dbus_message()}")

    # ── Step 4: Optional passphrase fallback ────────────────────────────────
    if args.passphrase_fallback:
        print("Falling back to passphrase…")
        passphrase = prompt_passphrase(args.device)
        if passphrase is None:
            sys.exit("Cancelled.")
        try:
            cleartext = unlock_with_passphrase(bus, object_path, passphrase)
            print(f"Unlocked (passphrase): {cleartext}")
        except dbus.DBusException as exc:
            sys.exit(f"Passphrase unlock failed: {exc.get_dbus_message()}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
