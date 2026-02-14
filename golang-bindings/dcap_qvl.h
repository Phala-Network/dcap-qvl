#ifndef DCAP_QVL_H
#define DCAP_QVL_H

#include <stdint.h>
#include <stddef.h>

/*
 * Return convention: 0 = success, non-zero = error.
 * On success, *out_json points to a JSON string allocated by Rust.
 * On error, *out_json points to an error message string allocated by Rust.
 * In both cases, call dcap_free(out_json, out_len) to release the memory.
 */

/* Parse quote binary → JSON with full structure */
int dcap_parse_quote(const uint8_t *quote, size_t quote_len,
                     char **out_json, size_t *out_len);

/* Verify quote with collateral (uses Intel production root CA) */
int dcap_verify(const uint8_t *quote, size_t quote_len,
                const char *collateral_json, size_t coll_len,
                uint64_t now_secs,
                char **out_json, size_t *out_len);

/* Verify quote with custom root CA */
int dcap_verify_with_root_ca(const uint8_t *quote, size_t quote_len,
                             const char *collateral_json, size_t coll_len,
                             const uint8_t *root_ca_der, size_t root_ca_len,
                             uint64_t now_secs,
                             char **out_json, size_t *out_len);

/* Parse PCK extension from PEM certificate chain */
int dcap_parse_pck_extension_from_pem(const uint8_t *pem, size_t pem_len,
                                      char **out_json, size_t *out_len);

/* Free memory allocated by Rust */
void dcap_free(char *ptr, size_t len);

#endif /* DCAP_QVL_H */
