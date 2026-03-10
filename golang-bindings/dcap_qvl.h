#ifndef DCAP_QVL_H
#define DCAP_QVL_H

#include <stdint.h>
#include <stddef.h>

/*
 * Output callback for C FFI.
 * The callback is invoked synchronously exactly once per API call.
 *
 * - data/len: UTF-8 bytes (JSON on success, error message on failure)
 * - user_data: opaque pointer passed through by the caller
 *
 * Callback return:
 * - 0: consumed successfully
 * - non-zero: callback failed, FFI returns callback error
 */
typedef int (*dcap_output_cb)(uint8_t *data, size_t len, void *user_data);

/* Parse quote binary → JSON with full structure */
int dcap_parse_quote_cb(const uint8_t *quote, size_t quote_len,
                        dcap_output_cb cb, void *user_data);

/* Verify quote with collateral (uses Intel production root CA) */
int dcap_verify_cb(const uint8_t *quote, size_t quote_len,
                   const uint8_t *collateral_json, size_t coll_len,
                   uint64_t now_secs,
                   dcap_output_cb cb, void *user_data);

/* Verify quote with custom root CA */
int dcap_verify_with_root_ca_cb(const uint8_t *quote, size_t quote_len,
                                const uint8_t *collateral_json, size_t coll_len,
                                const uint8_t *root_ca_der, size_t root_ca_len,
                                uint64_t now_secs,
                                dcap_output_cb cb, void *user_data);

/* Parse PCK extension from PEM certificate chain */
int dcap_parse_pck_extension_from_pem_cb(const uint8_t *pem, size_t pem_len,
                                         dcap_output_cb cb, void *user_data);

#endif /* DCAP_QVL_H */
