/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2025 The udisks Authors
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

#ifndef __UDISKS_BLOCKDEV_COMPAT_H__
#define __UDISKS_BLOCKDEV_COMPAT_H__

#include <blockdev/crypto.h>
#include <blockdev/nvme.h>

/*
 * libblockdev < 3.5 compatibility shims.
 *
 * The *_open_flags() variants and the BDCryptoOpenFlags type were added to
 * libblockdev after the 3.4.0 release.  When building against 3.4.x, provide
 * inline wrappers that delegate to the legacy boolean read_only argument.
 * The BD_CRYPTO_OPEN_ALLOW_DISCARDS flag cannot be represented in the old API
 * and is silently dropped on 3.4.x; all other behaviour is identical.
 */
#ifndef BD_CRYPTO_OPEN_ALLOW_DISCARDS

typedef guint BDCryptoOpenFlags;

#define BD_CRYPTO_OPEN_ALLOW_DISCARDS  (1u << 0)
#define BD_CRYPTO_OPEN_READONLY        (1u << 1)

static inline gboolean
bd_crypto_luks_open_flags (const gchar *device,
                            const gchar *name,
                            BDCryptoKeyslotContext *context,
                            BDCryptoOpenFlags flags,
                            GError **error)
{
  return bd_crypto_luks_open (device, name, context,
                               (flags & BD_CRYPTO_OPEN_READONLY) != 0,
                               error);
}

static inline gboolean
bd_crypto_tc_open_flags (const gchar *device,
                          const gchar *name,
                          BDCryptoKeyslotContext *context,
                          const gchar **keyfiles,
                          gboolean hidden,
                          gboolean system,
                          gboolean veracrypt,
                          guint32 veracrypt_pim,
                          BDCryptoOpenFlags flags,
                          GError **error)
{
  return bd_crypto_tc_open (device, name, context, keyfiles,
                             hidden, system, veracrypt, veracrypt_pim,
                             (flags & BD_CRYPTO_OPEN_READONLY) != 0,
                             error);
}

static inline gboolean
bd_crypto_bitlk_open_flags (const gchar *device,
                              const gchar *name,
                              BDCryptoKeyslotContext *context,
                              BDCryptoOpenFlags flags,
                              GError **error)
{
  return bd_crypto_bitlk_open (device, name, context,
                                (flags & BD_CRYPTO_OPEN_READONLY) != 0,
                                error);
}

/*
 * libblockdev < 3.5 NVMe sanitize status typo fix.
 *
 * BD_NVME_SANITIZE_STATUS_IN_PROGESS (missing 'R') was the original name in 3.4.x.
 * The typo was corrected to BD_NVME_SANITIZE_STATUS_IN_PROGRESS in master.
 * BD_NVME_SANITIZE_STATUS_IN_PROGESS is an enum value, not a macro, so we cannot
 * #ifdef on it; use BD_CRYPTO_OPEN_ALLOW_DISCARDS as a version proxy instead
 * (both missing → 3.4.x, both present → 3.5+).
 */
# define BD_NVME_SANITIZE_STATUS_IN_PROGRESS BD_NVME_SANITIZE_STATUS_IN_PROGESS

#endif /* !BD_CRYPTO_OPEN_ALLOW_DISCARDS */

#endif /* __UDISKS_BLOCKDEV_COMPAT_H__ */
