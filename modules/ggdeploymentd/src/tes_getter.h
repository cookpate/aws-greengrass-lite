#ifndef GGL_TES_GETTER_H
#define GGL_TES_GETTER_H

#define TES_CREDENTIAL_RETRY_BASE_MS 1000
#define TES_CREDENTIAL_RETRY_MAX_MS 60000

#include <gg/attr.h>
#include <gg/error.h>
#include <gg/types.h>
#include <stdint.h>

typedef struct TesCredentials {
    GgBuffer aws_region;
    GgBuffer access_key_id;
    GgBuffer secret_access_key;
    GgBuffer session_token;
} TesCredentials;

NONNULL(1)
typedef GgError (*TesCredentialsGetter)(TesCredentials *tes_creds);

ACCESS(write_only, 1) NONNULL(1)
GgError get_tes_credentials(TesCredentials *tes_creds);

ACCESS(write_only, 1) NONNULL(1) NONNULL(2)
GgError get_tes_credentials_with_retry(
    TesCredentials *tes_creds,
    TesCredentialsGetter get_credentials,
    uint32_t base_ms,
    uint32_t max_ms
);

#endif
