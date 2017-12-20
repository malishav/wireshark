/* packet-oscore.c
 * Routines for Object Security for Constrained RESTful Environments dissection
 * Copyright 2017, Malisa Vucinic <malishav@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

/*
 *  draft-ietf-core-object-security-07
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/prefs.h>    /* Include only as needed */
#include <epan/to_str.h>

#include <wsutil/wsgcrypt.h>
#include "packet-ssl-utils.h"
#include "packet-ieee802154.h" /* We use CCM implementation available as part of 802.15.4 dissector */
#include "packet-oscore.h"

/* Prototypes */
static guint oscore_alg_get_key_len(cose_aead_alg_t);
static guint oscore_alg_get_iv_len(cose_aead_alg_t);
static guint oscore_alg_get_tag_len(cose_aead_alg_t);
static gboolean oscore_context_derive_params(oscore_context_t *);

/* CBOR encoder prototypes */
static guint8 cborencoder_put_text(guint8 *buffer, char *text, guint8 text_len);
static guint8 cborencoder_put_null(guint8 *buffer);
static guint8 cborencoder_put_unsigned(guint8 *buffer, guint8 value);
static guint8 cborencoder_put_bytes(guint8 *buffer, guint8 bytes_len, guint8 *bytes);
static guint8 cborencoder_put_array(guint8 *buffer, guint8 elements);

/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_oscore(void);
void proto_register_oscore(void);

/* Initialize the protocol and registered fields */
static int proto_oscore                 = -1;

static int hf_oscore_coap_data          = -1;
static int hf_oscore_tag                = -1;

static expert_field ei_oscore_key_id_not_found        = EI_INIT;
static expert_field ei_oscore_partial_iv_not_found    = EI_INIT;
static expert_field ei_oscore_context_not_set         = EI_INIT;
static expert_field ei_oscore_message_too_small       = EI_INIT;
static expert_field ei_oscore_tag_check_failed        = EI_INIT;
static expert_field ei_oscore_decrypt_error           = EI_INIT;
static expert_field ei_oscore_cbc_mac_failed          = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_oscore = -1;

/* UAT variables */
static uat_t            *oscore_context_uat = NULL;
static oscore_context_t *oscore_contexts = NULL;
static guint            num_oscore_contexts = 0;

/* Enumeration for COSE algorithms used by OSCORE */
static const value_string oscore_context_alg_vals[] = {
    { COSE_AES_CCM_16_64_128, "AES-CCM-16-64-128 (CCM*)"},
    { 0, NULL }
};

/* Field callbacks. */
UAT_CSTRING_CB_DEF(oscore_context_uat, master_secret_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, master_salt_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, sender_id_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, recipient_id_prefs, oscore_context_t)
UAT_VS_DEF(oscore_context_uat, algorithm, oscore_context_t, cose_aead_alg_t, COSE_AES_CCM_16_64_128, "AES-CCM-16-64-128 (CCM*)")

static void oscore_context_post_update_cb(void) {
    guint i;
    guint key_len;
    guint iv_len;

    for (i = 0; i < num_oscore_contexts; i++) {
        oscore_contexts[i].master_secret    = g_byte_array_new();
        oscore_contexts[i].master_salt      = g_byte_array_new();
        oscore_contexts[i].sender_id        = g_byte_array_new();
        oscore_contexts[i].recipient_id     = g_byte_array_new();

        /* Convert strings to byte arrays */
        hex_str_to_bytes(oscore_contexts[i].sender_id_prefs, oscore_contexts[i].sender_id, FALSE);
        hex_str_to_bytes(oscore_contexts[i].recipient_id_prefs, oscore_contexts[i].recipient_id, FALSE);
        hex_str_to_bytes(oscore_contexts[i].master_secret_prefs, oscore_contexts[i].master_secret, FALSE);
        hex_str_to_bytes(oscore_contexts[i].master_salt_prefs, oscore_contexts[i].master_salt, FALSE);

        /* Algorithm-dependent key and IV length */
        key_len = oscore_alg_get_key_len(oscore_contexts[i].algorithm);
        iv_len = oscore_alg_get_iv_len(oscore_contexts[i].algorithm);

        /* Allocate memory for derived parameters */
        oscore_contexts[i].request_decryption_key = g_byte_array_sized_new(key_len);
        oscore_contexts[i].response_decryption_key = g_byte_array_sized_new(key_len);
        oscore_contexts[i].common_iv = g_byte_array_sized_new(iv_len);

        oscore_context_derive_params(&oscore_contexts[i]);
    }
}

/* Check user input, do not allocate any memory */
static gboolean oscore_context_update_cb(void *r, char **err) {
    oscore_context_t *rec = (oscore_context_t *) r;
    GByteArray *bytes; /* temp array to verify each parameter */

    bytes = g_byte_array_new();

    if (hex_str_to_bytes(rec->sender_id_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Sender ID is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (bytes->len == 0) {
        *err = g_strdup("Sender ID is mandatory.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->recipient_id_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Recipient ID is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (bytes->len == 0) {
        *err = g_strdup("Recipient ID is mandatory.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->master_secret_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Master Secret is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (bytes->len == 0) {
        *err = g_strdup("Master Secret is mandatory.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->master_salt_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Master Salt is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    /* no len check on Master Salt as it is optional */

     g_byte_array_free(bytes, TRUE);
     return TRUE;
}

static void* oscore_context_copy_cb(void *n, const void *o, size_t siz _U_) {
    oscore_context_t *new_record = (oscore_context_t *) n;
    const oscore_context_t *old_record = (const oscore_context_t *) o;

    new_record->master_secret_prefs = g_strdup(old_record->master_secret_prefs);
    new_record->master_salt_prefs = g_strdup(old_record->master_salt_prefs);
    new_record->sender_id_prefs = g_strdup(old_record->sender_id_prefs);
    new_record->recipient_id_prefs = g_strdup(old_record->recipient_id_prefs);
    new_record->algorithm = old_record->algorithm;

    /* FIXME don't forget to allocate new byte array and copy derived params */

    return new_record;
}

static void oscore_context_free_cb(void *r) {
    oscore_context_t *rec = (oscore_context_t *) r;

    g_free(rec->master_secret_prefs);
    g_free(rec->master_salt_prefs);
    g_free(rec->sender_id_prefs);
    g_free(rec->recipient_id_prefs);

    if (rec->master_secret) {
        g_byte_array_free(rec->master_secret, TRUE);
    }

    if (rec->master_salt) {
        g_byte_array_free(rec->master_salt, TRUE);
    }

    if (rec->sender_id) {
        g_byte_array_free(rec->sender_id, TRUE);
    }

    if (rec->recipient_id) {
        g_byte_array_free(rec->recipient_id, TRUE);
    }

    if (rec->request_decryption_key) {
        g_byte_array_free(rec->request_decryption_key, TRUE);
    }

    if (rec->response_decryption_key) {
        g_byte_array_free(rec->response_decryption_key, TRUE);
    }

    if (rec->common_iv) {
        g_byte_array_free(rec->common_iv, TRUE);
    }
}

/* 1 byte for code plus 8 bytes for shortest authentication tag.
 * See Section 5.3 of draft-ietf-core-object-security-07.
 * */
#define OSCORE_MIN_LENGTH 9

#define OSCORE_MAX_INFO_LENGTH 48

#define OSCORE_VERSION 1
/* GByteArrays within the oscore_context_t object should be initialized before calling this function */
static gboolean oscore_context_derive_params(oscore_context_t *context) {
    char *digest_name = "SHA256";
    char *iv_label = "IV";
    char *key_label = "Key";
    int md;
    guint8 prk[32]; /* Pseudo-random key from HKDF-Extract step. 32 for SHA256. */
    guint key_len;
    guint iv_len;
    guint8 info_buf[OSCORE_MAX_INFO_LENGTH];
    guint info_len;
    GByteArray *info;

    md = gcry_md_map_name(digest_name);

    key_len = oscore_alg_get_key_len(context->algorithm);
    iv_len = oscore_alg_get_iv_len(context->algorithm);

    info = g_byte_array_new();

    /* Common HKDF-Extract step on master salt */
    hkdf_extract(md, context->master_salt->data, context->master_salt->len, context->master_secret->data, context->master_secret->len, prk);

    /* Request Decryption Key */
    info_len = 0;
    info_len += cborencoder_put_array(&info_buf[info_len], 4);
    info_len += cborencoder_put_bytes(&info_buf[info_len], context->sender_id->len, context->sender_id->data);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], context->algorithm);
    info_len += cborencoder_put_text(&info_buf[info_len], key_label, 3);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], key_len);
    g_byte_array_append(info, info_buf, info_len);
    g_byte_array_set_size(context->request_decryption_key, key_len);
    hkdf_expand(md, prk, 32, info->data, info->len, context->request_decryption_key->data, key_len); /* 32 for SHA256 */

    /* Response Decryption Key */
    info_len = 0;
    g_byte_array_set_size(info, 0);
    info_len += cborencoder_put_array(&info_buf[info_len], 4);
    info_len += cborencoder_put_bytes(&info_buf[info_len], context->recipient_id->len, context->recipient_id->data);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], context->algorithm);
    info_len += cborencoder_put_text(&info_buf[info_len], key_label, 3);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], key_len);
    g_byte_array_append(info, info_buf, info_len);
    g_byte_array_set_size(context->response_decryption_key, key_len);
    hkdf_expand(md, prk, 32, info->data, info->len, context->response_decryption_key->data, key_len); /* 32 for SHA256 */

    /* Common IV */
    info_len = 0;
    g_byte_array_set_size(info, 0);
    info_len += cborencoder_put_array(&info_buf[info_len], 4);
    info_len += cborencoder_put_null(&info_buf[info_len]);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], context->algorithm);
    info_len += cborencoder_put_text(&info_buf[info_len], iv_label, 2);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], iv_len);
    g_byte_array_append(info, info_buf, info_len);
    g_byte_array_set_size(context->common_iv, iv_len);
    hkdf_expand(md, prk, 32, info->data, info->len, context->common_iv->data, iv_len); /* 32 for SHA256 */

    g_byte_array_free(info, TRUE);
    return TRUE;
}

static guint oscore_alg_get_key_len(cose_aead_alg_t algorithm) {
    switch(algorithm) {
        case COSE_AES_CCM_16_64_128:
            return 16; /* RFC8152 */
        /* unsupported */
        default:
            return 0;
    }
    return 0;
}

static guint oscore_alg_get_tag_len(cose_aead_alg_t algorithm) {
    switch(algorithm) {
        case COSE_AES_CCM_16_64_128:
            return 8; /* RFC8152 */
        /* unsupported */
        default:
            return 0;
    }
    return 0;
}

static guint oscore_alg_get_iv_len(cose_aead_alg_t algorithm) {
    switch(algorithm) {
        case COSE_AES_CCM_16_64_128:
            return 13; /* RFC8152 */
        /* unsupported */
        default:
            return 0;
    }
    return 0;
}

static oscore_context_t * oscore_find_context(oscore_info_t *info) {
    guint i;

    for (i = 0; i < num_oscore_contexts; i++) {
        if (oscore_contexts[i].sender_id_prefs && info->kid) {
            if (memcmp(oscore_contexts[i].sender_id->data, info->kid, oscore_contexts[i].sender_id->len) == 0) {
                return &oscore_contexts[i];
            }
        }
    }
    return NULL;
}

/**
CBOR encoding functions needed to construct HKDF info and aad.
Author Martin Gunnarsson <martin.gunnarsson@ri.se>
Modified by Malisa Vucinic <malishav@gmail.com>

*/
static guint8
cborencoder_put_text(guint8 *buffer, char *text, guint8 text_len) {
    guint8 ret = 0;

    if(text_len > 23 ){
        buffer[ret++] = 0x78;
        buffer[ret++] = text_len;
    } else {
        buffer[ret++] = (0x60 | text_len);
    }

    memcpy(&buffer[ret], text, text_len);
    ret += text_len;
    return ret;
}

static guint8
cborencoder_put_array(guint8 *buffer, guint8 elements) {
    guint8 ret = 0;

    if(elements > 15){
        return 0;
    }

    buffer[ret++] = (0x80 | elements);
    return ret;
}

static guint8
cborencoder_put_bytes(guint8 *buffer, guint8 bytes_len, guint8 *bytes) {
    guint8 ret = 0;

    if(bytes_len > 23){
        buffer[ret++] = 0x58;
        buffer[ret++] = bytes_len;
    } else {
        buffer[ret++] = (0x40 | bytes_len);
    }
    memcpy(&buffer[ret], bytes, bytes_len);
    ret += bytes_len;
    return ret;
}

static guint8
cborencoder_put_unsigned(guint8 *buffer, guint8 value) {
    guint8 ret = 0;

    if(value > 0x17 ){
        buffer[ret++] = 0x18;
        buffer[ret++] = value;
        return ret;
    }

    buffer[ret++] = value;
    return ret;
}

static guint8
cborencoder_put_null(guint8 *buffer) {
    guint8 ret = 0;

    buffer[ret++] = 0xf6;
    return ret;
}

/* out should hold 13 bytes at most */
static void
oscore_create_nonce(guint8 *out,
        oscore_context_t *context,
        oscore_info_t *info) {

    guint i = 0;
    gchar piv_extended[13]; /* longest nonce in RFC8152 is 13 bytes */
    guint iv_len;
    guint pad_len;

    DISSECTOR_ASSERT(out != NULL);
    DISSECTOR_ASSERT(context != NULL);
    DISSECTOR_ASSERT(info != NULL);

    /* Section 5.2 of draft-ietf-core-object-security-07 */
    iv_len = oscore_alg_get_iv_len(context->algorithm);
    pad_len = iv_len - 6 - context->sender_id->len;

    piv_extended[i++] = context->sender_id->len;

    memset(&piv_extended[i], 0x00, pad_len);
    i += pad_len;

    memcpy(&piv_extended[i], context->sender_id->data, context->sender_id->len);
    i += context->sender_id->len;

    pad_len = 5 - info->piv_len;

    memset(&piv_extended[i], 0x00, pad_len);
    i += pad_len;

    memcpy(&piv_extended[i], info->piv, info->piv_len);
    i += info->piv_len;

    DISSECTOR_ASSERT(i == iv_len);

    for (i = 0; i < iv_len; i++) {
        out[i] = piv_extended[i] ^ context->common_iv->data[i];
    }

}

static oscore_decryption_status_t
oscore_decrypt_and_verify(tvbuff_t *tvb_ciphertext,
        packet_info *pinfo,
        guint *offset,
        proto_tree *tree,
        oscore_context_t *context,
        oscore_info_t *info,
        tvbuff_t **tvb_plaintext) {

    gboolean have_tag = FALSE;
    guint8 nonce[13];
    guint8 tmp[16];
    guint8 *text;
    guint8 rx_tag[16];
    guint tag_len = 0;
    guint8 gen_tag[16];
    guint8 external_aad[100]; /* FIXME dirty length */
    guint8 external_aad_len = 0;
    guint8 aad[100]; /* FIXME dirty length */
    guint8 aad_len = 0;
    gint ciphertext_captured_len;
    gint ciphertext_reported_len;
    gchar *encrypt0 = "Encrypt0";
    proto_item *tag_item = NULL;

    tag_len = oscore_alg_get_tag_len(context->algorithm);

    ciphertext_reported_len = tvb_reported_length(tvb_ciphertext) - tag_len;

    if (ciphertext_reported_len < 0) {
        return STATUS_ERROR_MESSAGE_TOO_SMALL;
    }

    /* Check if the payload is truncated.  */
    if (tvb_bytes_exist(tvb_ciphertext, *offset, ciphertext_reported_len)) {
        ciphertext_captured_len = ciphertext_reported_len;
    }
    else {
        ciphertext_captured_len = tvb_captured_length_remaining(tvb_ciphertext, *offset);
    }

    /* Check if the tag is present in the captured data. */
    have_tag = tvb_bytes_exist(tvb_ciphertext, *offset + ciphertext_reported_len, tag_len);
    if (have_tag) {
        tvb_memcpy(tvb_ciphertext, rx_tag, *offset + ciphertext_reported_len, tag_len);
    }

    /* Create nonce to use for decryption and authenticity check */
    oscore_create_nonce(nonce, context, info);

    /*
     * Create the CCM* initial block for decryption (Adata=0, M=0, counter=0).
     * FIXME: This only handles AES-CCM-16-64-128, add generic algorithm handling
     * */
    ccm_init_block(tmp, FALSE, 0, 0, 0, 0, 0, nonce);

    /*
    * Make a copy of the ciphertext in heap memory.
    *
    * We will decrypt the message in-place and then use the buffer as the
    * real data for the new tvb.
    */
    text = (guint8 *)tvb_memdup(pinfo->pool, tvb_ciphertext, *offset, ciphertext_captured_len);

    /*
     * Perform CTR-mode transformation and decrypt the tag.
     * FIXME: This only handles AES-CCM-16-64-128, add generic algorithm handling
     * */
    if(ccm_ctr_encrypt(context->request_decryption_key->data, tmp, rx_tag, text, ciphertext_captured_len) == FALSE) {
        return STATUS_ERROR_DECRYPT_FAILED;
    }

    /* Create a tvbuff for the plaintext. */
    *tvb_plaintext = tvb_new_real_data((const guint8 *)text, ciphertext_captured_len, ciphertext_reported_len);
    tvb_set_child_real_data_tvbuff(tvb_ciphertext, *tvb_plaintext);
    add_new_data_source(pinfo, *tvb_plaintext, "Decrypted OSCORE");

    /* Construct external_aad to be able to verify the tag */
    external_aad_len += cborencoder_put_array(&external_aad[external_aad_len], 5); /* 5 elements in the array */
    external_aad_len += cborencoder_put_unsigned(&external_aad[external_aad_len], OSCORE_VERSION);
    external_aad_len += cborencoder_put_unsigned(&external_aad[external_aad_len], context->algorithm);
    external_aad_len += cborencoder_put_bytes(&external_aad[external_aad_len], info->kid_len, info->kid);
    external_aad_len += cborencoder_put_bytes(&external_aad[external_aad_len], info->piv_len, info->piv);
    external_aad_len += cborencoder_put_bytes(&external_aad[external_aad_len], 0, NULL); // Class I options not implemented/standardized yet

    DISSECTOR_ASSERT(external_aad_len < 100); /* FIXME dirty */

    aad_len += cborencoder_put_array(&aad[aad_len], 3); // COSE Encrypt0 structure with 3 elements
    aad_len += cborencoder_put_text(&aad[aad_len], encrypt0, 8); /* Text string "Encrypt0" */
    aad_len += cborencoder_put_bytes(&aad[aad_len], 0, NULL);  /* Empty byte string */
    aad_len += cborencoder_put_bytes(&aad[aad_len], external_aad_len, external_aad); /* OSCORE external_aad */

    DISSECTOR_ASSERT(aad_len < 100); /* FIXME dirty */

    /*
     * Create the CCM* initial block for authentication (Adata!=0, M!=0, counter=l(m)).
     * FIXME: This only handles AES-CCM-16-64-128, add generic algorithm handling
     * */
    ccm_init_block(tmp, TRUE, tag_len, 0, 0, 0, ciphertext_captured_len, nonce);

    /* Compute CBC-MAC authentication tag. */
    /*
    * FIXME And yes, despite the warning in tvbuff.h, I think tvb_get_ptr is the
    * right function here since either A) the payload wasn't encrypted, in
    * which case l_m is zero, or B) the payload was encrypted, and the tvb
    * already points to contiguous memory, since we just allocated it in
    * decryption phase.
    */
    if (!ccm_cbc_mac(context->request_decryption_key->data, tmp, aad, aad_len, tvb_get_ptr(*tvb_plaintext, 0, ciphertext_captured_len), ciphertext_captured_len, gen_tag)) {
        return STATUS_ERROR_CBCMAC_FAILED;
    }
    /* Compare the received tag with the one we generated. */
    else if (memcmp(gen_tag, rx_tag, tag_len) != 0) {
        return STATUS_ERROR_TAG_CHECK_FAILED;
    }

    /* Display the tag. */
    if (tag_len) {
        tag_item = proto_tree_add_bytes(tree, hf_oscore_tag, tvb_ciphertext, ciphertext_captured_len, tag_len, rx_tag);
        PROTO_ITEM_SET_GENERATED(tag_item);
    }

    return STATUS_SUCCESS_DECRYPTION_TAG_CHECK;
}

/* Code to actually dissect the packets */
static int
oscore_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *oscore_tree;
    /* Other misc. local variables. */
    guint offset = 0;
    oscore_info_t *info = data;
    oscore_context_t *context = NULL;
    oscore_decryption_status_t status;
    tvbuff_t *tvb_decrypted = NULL;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < OSCORE_MIN_LENGTH) {
        return 0;
    }

    /* Set the Protocol column to the constant string of oscore */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSCORE");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_oscore, tvb, 0, -1, ENC_NA);

    oscore_tree = proto_item_add_subtree(ti, ett_oscore);

    if (info->kid == NULL) {
        expert_add_info(pinfo, oscore_tree, &ei_oscore_key_id_not_found);
        return tvb_reported_length(tvb);
    }

    if (info->piv == NULL) {
        expert_add_info(pinfo, oscore_tree, &ei_oscore_partial_iv_not_found);
        return tvb_reported_length(tvb);
    }

    if ((context = oscore_find_context(info)) == NULL) {
        expert_add_info(pinfo, oscore_tree, &ei_oscore_context_not_set);
        return tvb_reported_length(tvb);
    }

    status = oscore_decrypt_and_verify(tvb, pinfo, &offset, oscore_tree, context, info, &tvb_decrypted);

    switch (status) {
        case STATUS_ERROR_DECRYPT_FAILED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_decrypt_error);
            return tvb_reported_length(tvb);
        case STATUS_ERROR_CBCMAC_FAILED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_cbc_mac_failed);
            return tvb_reported_length(tvb);
        case STATUS_ERROR_TAG_CHECK_FAILED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_tag_check_failed);
            return tvb_reported_length(tvb);
        case STATUS_ERROR_MESSAGE_TOO_SMALL:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_message_too_small);
            return tvb_reported_length(tvb);
        case STATUS_SUCCESS_DECRYPTION_TAG_CHECK:
            break;
    }

    DISSECTOR_ASSERT(tvb_decrypted != NULL);

    proto_tree_add_item(oscore_tree, hf_oscore_coap_data, tvb_decrypted, 0, tvb_reported_length(tvb_decrypted), ENC_NA);

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_oscore(void)
{
    module_t        *oscore_module;
    expert_module_t *expert_oscore;
    dissector_handle_t oscore_handle;

    static hf_register_info hf[] = {
        { &hf_oscore_coap_data,
          { "Decrypted CoAP Data", "oscore.coap_data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_oscore_tag,
          { "Decrypted Authentication Tag", "oscore.tag", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Decrypted Authentication Tag", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_oscore
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_oscore_key_id_not_found,
          { "oscore.key_id_not_found", PI_UNDECODED, PI_WARN,
            "Key ID not found - can't decrypt", EXPFILL }
        },
        { &ei_oscore_partial_iv_not_found,
          { "oscore.partial_iv_not_found", PI_UNDECODED, PI_WARN,
            "Partial IV not found - can't decrypt", EXPFILL }
        },
        { &ei_oscore_context_not_set,
          { "oscore.context_not_set", PI_UNDECODED, PI_WARN,
            "Security context not set - can't decrypt", EXPFILL }
        },
        { &ei_oscore_message_too_small,
          { "oscore.message_too_small", PI_UNDECODED, PI_WARN,
            "Message too small", EXPFILL }
        },
        { &ei_oscore_cbc_mac_failed,
          { "oscore.cbc_mac_failed", PI_UNDECODED, PI_WARN,
            "Call to CBC-MAC failed", EXPFILL }
        },
        { &ei_oscore_tag_check_failed,
          { "oscore.tag_check_failed", PI_UNDECODED, PI_WARN,
            "Authentication tag check failed", EXPFILL }
        },
        { &ei_oscore_decrypt_error,
          { "oscore.decrypt_error", PI_UNDECODED, PI_WARN,
            "Decryption error", EXPFILL }
        }
    };

    static uat_field_t oscore_context_uat_flds[] = {
        UAT_FLD_CSTRING(oscore_context_uat,sender_id_prefs,"Sender ID",
                "Sender ID as HEX string. Should be 0 to 8 bytes. Mandatory."),
        UAT_FLD_CSTRING(oscore_context_uat,recipient_id_prefs,"Recipient ID",
                "Recipient ID as HEX string. Should be 0 to 8 bytes. Mandatory."),
        UAT_FLD_CSTRING(oscore_context_uat,master_secret_prefs,"Master Secret",
                "Master Secret as HEX string. Should be 0 to 32 bytes. Mandatory."),
        UAT_FLD_CSTRING(oscore_context_uat,master_salt_prefs,"Master Salt",
                "Master Salt as HEX string. Should be 0 to 32 bytes. Optional."),
        UAT_FLD_VS(oscore_context_uat, algorithm, "Algorithm", oscore_context_alg_vals, "Decryption algorithm."),
        UAT_END_FIELDS
    };

    /* Register the protocol name and description */
    proto_oscore = proto_register_protocol("Object Security for Constrained RESTful Environments",
            "OSCORE", "oscore");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_oscore, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_oscore = expert_register_protocol(proto_oscore);
    expert_register_field_array(expert_oscore, ei, array_length(ei));

    oscore_module = prefs_register_protocol(proto_oscore, NULL);

    /* Create a UAT for security context management. */
    oscore_context_uat = uat_new("Security Contexts",
            sizeof(oscore_context_t),       /* record size */
            "oscore_contexts",              /* filename */
            TRUE,                           /* from_profile */
            &oscore_contexts,               /* data_ptr */
            &num_oscore_contexts,           /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* help */
            oscore_context_copy_cb,         /* copy callback */
            oscore_context_update_cb,       /* update callback */
            oscore_context_free_cb,         /* free callback */
            oscore_context_post_update_cb,  /* post update callback */
            NULL,                           /* reset callback */
            oscore_context_uat_flds);       /* UAT field definitions */

    prefs_register_uat_preference(oscore_module, "contexts",
                "Security Contexts",
                "Security context configuration data",
                oscore_context_uat);

    oscore_handle = register_dissector("oscore", oscore_dissect, proto_oscore);
}

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
