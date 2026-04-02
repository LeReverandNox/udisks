/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Author: Vratislav Podzimek <vpodzime@redhat.com>
 *
 */

#include <glib.h>
#include "udisksblockdevcompat.h"
#include <libcryptsetup.h>

#include "udisksthreadedjob.h"
#include "udiskslinuxencryptedhelpers.h"
#include "udiskslogging.h"

gboolean luks_format_job_func (UDisksThreadedJob  *job,
                      GCancellable       *cancellable,
                      gpointer            user_data,
                      GError            **error)
{
  BDCryptoLUKSVersion luks_version;
  CryptoJobData *data = (CryptoJobData*) user_data;
  BDCryptoKeyslotContext *context = NULL;
  gboolean ret = FALSE;
  BDCryptoLUKSExtra *extra = NULL;

  if (g_strcmp0 (data->type, "luks1") == 0)
    luks_version = BD_CRYPTO_LUKS_VERSION_LUKS1;
  else if ((g_strcmp0 (data->type, "luks2") == 0))
    luks_version = BD_CRYPTO_LUKS_VERSION_LUKS2;
  else
    {
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "Unknown or unsupported encryption type specified: '%s'",
                   data->type);
      return FALSE;
    }

  context = bd_crypto_keyslot_context_new_passphrase ((const guint8 *) data->passphrase->str,
                                                      data->passphrase->len, error);
  if (!context)
    return FALSE;

  if (data->pbkdf || data->memory || data->iterations || data->time || data->threads || data->label)
    {
      extra = g_new0 (BDCryptoLUKSExtra, 1);
      extra->pbkdf = bd_crypto_luks_pbkdf_new (data->pbkdf, NULL, data->memory, data->iterations,
                                               data->time, data->threads);
      extra->label = g_strdup (data->label);
    }

  /* device, cipher, key_size, context, min_entropy, luks_version, extra, error */
  ret = bd_crypto_luks_format (data->device, NULL, 0, context, 0, luks_version, extra, error);
  bd_crypto_keyslot_context_free (context);
  bd_crypto_luks_extra_free (extra);
  return ret;
}

gboolean luks_open_job_func (UDisksThreadedJob  *job,
                    GCancellable       *cancellable,
                    gpointer            user_data,
                    GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  BDCryptoKeyslotContext *context = NULL;
  gboolean ret = FALSE;
  BDCryptoOpenFlags flags = 0;

  context = bd_crypto_keyslot_context_new_passphrase ((const guint8 *) data->passphrase->str,
                                                      data->passphrase->len, error);
  if (!context)
    return FALSE;

  if (data->read_only)
    flags |= BD_CRYPTO_OPEN_READONLY;
  if (data->discard)
    flags |= BD_CRYPTO_OPEN_ALLOW_DISCARDS;

  /* device, name, context, flags, error */
  ret = bd_crypto_luks_open_flags (data->device, data->map_name, context, flags, error);
  bd_crypto_keyslot_context_free (context);
  return ret;
}

gboolean luks_close_job_func (UDisksThreadedJob  *job,
                    GCancellable       *cancellable,
                    gpointer            user_data,
                    GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  return bd_crypto_luks_close (data->map_name, error);
}

gboolean luks_change_key_job_func (UDisksThreadedJob  *job,
                          GCancellable       *cancellable,
                          gpointer            user_data,
                          GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  BDCryptoKeyslotContext *context = NULL;
  BDCryptoKeyslotContext *ncontext = NULL;
  gboolean ret = FALSE;

  context = bd_crypto_keyslot_context_new_passphrase ((const guint8 *) data->passphrase->str,
                                                      data->passphrase->len, error);
  if (!context)
    return FALSE;
  ncontext = bd_crypto_keyslot_context_new_passphrase ((const guint8 *) data->new_passphrase->str,
                                                       data->new_passphrase->len, error);
  if (!ncontext)
    {
      bd_crypto_keyslot_context_free (context);
      return FALSE;
    }

  ret = bd_crypto_luks_change_key (data->device, context, ncontext, error);
  bd_crypto_keyslot_context_free (context);
  bd_crypto_keyslot_context_free (ncontext);
  return ret;
}

gboolean tcrypt_open_job_func (UDisksThreadedJob  *job,
                               GCancellable       *cancellable,
                               gpointer            user_data,
                               GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  BDCryptoKeyslotContext *context = NULL;
  gboolean ret = FALSE;
  BDCryptoOpenFlags flags = 0;

  /* We always use the veracrypt option, because it can unlock both VeraCrypt and legacy TrueCrypt volumes */
  gboolean  veracrypt = TRUE;

  /* passphrase can be empty for veracrypt with keyfiles */
  if (data->passphrase->len > 0)
    {
      context = bd_crypto_keyslot_context_new_passphrase ((const guint8 *) data->passphrase->str,
                                                          data->passphrase->len, error);
      if (!context)
        return FALSE;
    }

  if (data->read_only)
    flags |= BD_CRYPTO_OPEN_READONLY;
  if (data->discard)
    flags |= BD_CRYPTO_OPEN_ALLOW_DISCARDS;

  ret = bd_crypto_tc_open_flags (data->device, data->map_name, context,
                                 data->keyfiles, data->hidden, data->system, veracrypt, data->pim,
                                 flags, error);
  bd_crypto_keyslot_context_free (context);
  return ret;
}

gboolean tcrypt_close_job_func (UDisksThreadedJob  *job,
                                GCancellable       *cancellable,
                                gpointer            user_data,
                                GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  return bd_crypto_tc_close (data->map_name, error);
}

gboolean bitlk_open_job_func (UDisksThreadedJob  *job,
                              GCancellable       *cancellable,
                              gpointer            user_data,
                              GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  BDCryptoKeyslotContext *context = NULL;
  gboolean ret = FALSE;
  BDCryptoOpenFlags flags = 0;

  context = bd_crypto_keyslot_context_new_passphrase ((const guint8 *) data->passphrase->str,
                                                      data->passphrase->len, error);
  if (!context)
    return FALSE;

  if (data->read_only)
    flags |= BD_CRYPTO_OPEN_READONLY;
  if (data->discard)
    flags |= BD_CRYPTO_OPEN_ALLOW_DISCARDS;

  ret = bd_crypto_bitlk_open_flags (data->device, data->map_name, context, flags, error);
  bd_crypto_keyslot_context_free (context);
  return ret;
}

gboolean bitlk_close_job_func (UDisksThreadedJob  *job,
                               GCancellable       *cancellable,
                               gpointer            user_data,
                               GError            **error)
{
  CryptoJobData *data = (CryptoJobData*) user_data;
  return bd_crypto_bitlk_close (data->map_name, error);
}

/**
 * luks_open_with_tokens_job_func:
 *
 * ThreadedJob function that unlocks a LUKS2 device via enrolled security
 * tokens.  libcryptsetup iterates all enrolled tokens in header order and
 * calls each token type's plugin (e.g. the systemd-fido2 plugin, which
 * handles PIN prompting via systemd-ask-password and user-presence waiting
 * via libfido2 internally).
 *
 * If all tokens fail and a passphrase is present in @user_data, the function
 * falls back to passphrase-based unlock via libblockdev.
 */
gboolean
luks_open_with_tokens_job_func (UDisksThreadedJob  *job,
                                 GCancellable       *cancellable,
                                 gpointer            user_data,
                                 GError            **error)
{
  CryptoJobData *data = (CryptoJobData *) user_data;
  struct crypt_device *cd = NULL;
  uint32_t activate_flags = 0;
  int r;
  gboolean ret = FALSE;

  r = crypt_init (&cd, data->device);
  if (r < 0)
    {
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "Failed to initialise libcryptsetup for %s: %s",
                   data->device, g_strerror (-r));
      return FALSE;
    }

  crypt_set_log_callback (cd, NULL, NULL);

  r = crypt_load (cd, CRYPT_LUKS2, NULL);
  if (r < 0)
    {
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "%s is not a LUKS2 device; token-based unlock requires LUKS2",
                   data->device);
      goto out;
    }

  if (data->read_only)
    activate_flags |= CRYPT_ACTIVATE_READONLY;
  if (data->discard)
    activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

  /* Try all enrolled tokens in header order.  Each token plugin handles its
   * own user interaction (PIN prompts, user-presence wait, etc.).
   * Pass the PIN directly when provided so token plugins do not need to
   * use the systemd-ask-password agent (which is unavailable in the daemon
   * context without a running session agent). */
  if (data->pin != NULL && data->pin->len > 0)
    r = crypt_activate_by_token_pin (cd, data->map_name, NULL, CRYPT_ANY_TOKEN,
                                     data->pin->str, data->pin->len,
                                     NULL, activate_flags);
  else
    r = crypt_activate_by_token (cd, data->map_name, CRYPT_ANY_TOKEN, NULL, activate_flags);
  if (r >= 0)
    {
      ret = TRUE;
      goto out;
    }

  udisks_debug ("Token-based unlock of %s failed (errno %d: %s)%s",
                data->device, -r, g_strerror (-r),
                (data->passphrase && data->passphrase->len > 0)
                  ? ", falling back to passphrase" : "");

  /* Fall back to passphrase/keyfile if the caller provided one. */
  if (data->passphrase != NULL && data->passphrase->len > 0)
    {
      BDCryptoKeyslotContext *context = NULL;
      BDCryptoOpenFlags bd_flags = 0;

      crypt_free (cd);
      cd = NULL;

      context = bd_crypto_keyslot_context_new_passphrase (
                    (const guint8 *) data->passphrase->str,
                    data->passphrase->len, error);
      if (!context)
        goto out;

      if (data->read_only)
        bd_flags |= BD_CRYPTO_OPEN_READONLY;
      if (data->discard)
        bd_flags |= BD_CRYPTO_OPEN_ALLOW_DISCARDS;

      ret = bd_crypto_luks_open_flags (data->device, data->map_name,
                                       context, bd_flags, error);
      bd_crypto_keyslot_context_free (context);
      goto out;
    }

  /* No passphrase fallback available — report the token failure. */
  switch (-r)
    {
    case ENOANO:
      /* ENOANO means either no matching physical device was found, or the token
       * requires a PIN that was not supplied.  Use the presence of a PIN in the
       * job data as a heuristic to distinguish the two cases so that graphical
       * applications can show the appropriate dialog. */
      if (data->pin == NULL || data->pin->len == 0)
        g_set_error (error,
                     UDISKS_ERROR,
                     UDISKS_ERROR_TOKEN_REQUIRES_PIN,
                     "Token unlock of %s requires a PIN. "
                     "Retry the call with the 'pin' option.",
                     data->device);
      else
        g_set_error (error,
                     UDISKS_ERROR,
                     UDISKS_ERROR_TOKEN_NOT_FOUND,
                     "No FIDO2/security token matching any enrolled credential "
                     "was found on %s. Ensure the correct token is inserted.",
                     data->device);
      break;
    case ENOENT:
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "No token handler found for any enrolled token on %s. "
                   "Ensure the appropriate token plugin (e.g. "
                   "libcryptsetup-plugin-systemd-fido2) is installed.",
                   data->device);
      break;
    case EPERM:
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "Token authentication failed for %s: wrong PIN or "
                   "user verification rejected.",
                   data->device);
      break;
    case ETIMEDOUT:
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "Token unlock of %s timed out waiting for user presence.",
                   data->device);
      break;
    default:
      g_set_error (error,
                   UDISKS_ERROR,
                   UDISKS_ERROR_FAILED,
                   "Token unlock of %s failed: %s",
                   data->device, g_strerror (-r));
      break;
    }

 out:
  if (cd != NULL)
    crypt_free (cd);
  return ret;
}
