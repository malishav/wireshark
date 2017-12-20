/* packet-oscore.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_OSCORE_H__
#define __PACKET_OSCORE_H__

/* OSCORE uses AEAD algorithms defined in RFC8152 (COSE)
 * We only implement the default algorithm which corresponds to CCM*
 * */
typedef enum {
    COSE_AES_CCM_16_64_128 = 10,
} cose_aead_alg_t;

typedef enum {
    STATUS_ERROR_DECRYPT_FAILED                 = 0,
    STATUS_ERROR_CBCMAC_FAILED,
    STATUS_ERROR_TAG_CHECK_FAILED,
    STATUS_ERROR_MESSAGE_TOO_SMALL,
    STATUS_SUCCESS_DECRYPTION_TAG_CHECK,
} oscore_decryption_status_t;

/*  Structure containing information regarding all necessary OSCORE message fields. */
typedef struct oscore_context {
    /* Pre-Shared Parameters as Strings */
    gchar               *master_secret_prefs;
    gchar               *master_salt_prefs;
    gchar               *sender_id_prefs;
    gchar               *recipient_id_prefs;
    cose_aead_alg_t     algorithm;
    /* Pre-Shared Parameters as Byte Arrays */
    GByteArray          *master_secret;
    GByteArray          *master_salt;
    GByteArray          *sender_id;
    GByteArray          *recipient_id;
    /* Derived Parameters */
    GByteArray          *request_decryption_key;
    GByteArray          *response_decryption_key;
    GByteArray          *common_iv; /* IV used to generate the nonce */
} oscore_context_t;

/* Data from the lower layer (CoAP/HTTP) necessary for OSCORE to decrypt the packet */
typedef struct oscore_info {
    guint8              *kid;
    guint8              kid_len;
    guint8              *kid_context;
    guint8              kid_context_len;
    guint8              *piv;
    guint8              piv_len;
    gboolean            response;
} oscore_info_t;

#endif /* __PACKET_OSCORE_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
