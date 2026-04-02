/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2024 The UDisks Project
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
 */

#include "config.h"

#include <libcryptsetup.h>

#include "udisksfido2.h"
#include "udiskslogging.h"

/**
 * udisks_luks2_get_token_types:
 * @device_path: Path to the block device (e.g. "/dev/sda1").
 * @error: Return location for a #GError, or %NULL.
 *
 * Reads the LUKS2 header of @device_path and returns the unique set of token
 * type strings found in it (e.g. "systemd-fido2", "systemd-tpm2").
 *
 * This is a read-only operation that does not require elevated privileges
 * beyond read access to the block device.
 *
 * Returns: A %NULL-terminated array of token type strings, or %NULL if the
 * device is not LUKS2 or on error.  Free with g_strfreev().
 */
gchar **
udisks_luks2_get_token_types (const gchar  *device_path,
                               GError      **error)
{
  struct crypt_device *cd = NULL;
  GPtrArray *types = NULL;
  gchar **result = NULL;
  int r;
  int max_tokens;

  g_return_val_if_fail (device_path != NULL, NULL);

  r = crypt_init (&cd, device_path);
  if (r < 0)
    {
      udisks_debug ("Failed to init libcryptsetup for %s: %s",
                    device_path, g_strerror (-r));
      goto out;
    }

  /* Suppress libcryptsetup log output — udisks has its own logging. */
  crypt_set_log_callback (cd, NULL, NULL);

  r = crypt_load (cd, CRYPT_LUKS2, NULL);
  if (r < 0)
    {
      /* Not LUKS2 — this is the normal case for LUKS1/TCRYPT/BITLK devices. */
      udisks_debug ("%s is not a LUKS2 device, skipping token enumeration",
                    device_path);
      goto out;
    }

  types = g_ptr_array_new_with_free_func (g_free);
  max_tokens = crypt_token_max (CRYPT_LUKS2);

  for (int i = 0; i < max_tokens; i++)
    {
      const gchar *type = NULL;
      crypt_token_info info;
      gboolean already_present;

      info = crypt_token_status (cd, i, &type);

      if (info == CRYPT_TOKEN_INVALID || info == CRYPT_TOKEN_INACTIVE)
        continue;

      if (type == NULL)
        continue;

      /* Deduplicate: only add each type once. */
      already_present = FALSE;
      for (guint j = 0; j < types->len; j++)
        {
          if (g_strcmp0 (g_ptr_array_index (types, j), type) == 0)
            {
              already_present = TRUE;
              break;
            }
        }

      if (!already_present)
        g_ptr_array_add (types, g_strdup (type));
    }

  g_ptr_array_add (types, NULL);
  result = (gchar **) g_ptr_array_free (types, FALSE);
  types = NULL;

 out:
  if (types != NULL)
    g_ptr_array_free (types, TRUE);
  if (cd != NULL)
    crypt_free (cd);

  return result;
}
