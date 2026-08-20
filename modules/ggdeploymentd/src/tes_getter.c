#include "tes_getter.h"
#include <gg/arena.h>
#include <gg/backoff.h>
#include <gg/buffer.h>
#include <gg/flags.h>
#include <gg/log.h>
#include <gg/map.h>
#include <gg/object.h>
#include <ggl/core_bus/client.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    TesCredentials *tes_creds;
    TesCredentialsGetter get_credentials;
    GgError result;
} TesCredentialsRetryCtx;

static GgError retry_get_tes_credentials(void *ctx);
static bool is_tes_credentials_error_retryable(GgError error);

static bool is_tes_credentials_error_retryable(GgError error) {
    return (error == GG_ERR_NOCONN) || (error == GG_ERR_TIMEOUT)
        || (error == GG_ERR_RETRY);
}

static GgError retry_get_tes_credentials(void *ctx) {
    TesCredentialsRetryCtx *retry_ctx = ctx;
    retry_ctx->result = retry_ctx->get_credentials(retry_ctx->tes_creds);
    if (is_tes_credentials_error_retryable(retry_ctx->result)) {
        GG_LOGW(
            "TES credential retrieval failed due to a transient error (%s); retrying with backoff.",
            gg_strerror(retry_ctx->result)
        );
        return retry_ctx->result;
    }
    return GG_ERR_OK;
}

GgError get_tes_credentials_with_retry(
    TesCredentials *tes_creds,
    TesCredentialsGetter get_credentials,
    uint32_t base_ms,
    uint32_t max_ms
) {
    TesCredentialsRetryCtx ctx = { .tes_creds = tes_creds,
                                   .get_credentials = get_credentials,
                                   .result = GG_ERR_OK };
    GgError ret
        = gg_backoff(base_ms, max_ms, 0, retry_get_tes_credentials, &ctx);
    if (ret != GG_ERR_OK) {
        return ret;
    }
    return ctx.result;
}

GgError get_tes_credentials(TesCredentials *tes_creds) {
    GgObject *aws_access_key_id = NULL;
    GgObject *aws_secret_access_key = NULL;
    GgObject *aws_session_token = NULL;

    static uint8_t credentials_alloc[1500];
    static GgBuffer tesd = GG_STR("aws_iot_tes");
    GgObject result;
    GgMap params = { 0 };
    GgArena credential_alloc = gg_arena_init(GG_BUF(credentials_alloc));
    GgError service_error = GG_ERR_OK;

    GgError ret = ggl_call(
        tesd,
        GG_STR("request_credentials"),
        params,
        &service_error,
        &credential_alloc,
        &result
    );
    if (ret != GG_ERR_OK) {
        if (ret == GG_ERR_REMOTE) {
            ret = service_error;
        }
        GG_LOGE("Failed to get TES credentials: %s.", gg_strerror(ret));
        return ret;
    }

    ret = gg_map_validate(
        gg_obj_into_map(result),
        GG_MAP_SCHEMA(
            { GG_STR("accessKeyId"),
              GG_REQUIRED,
              GG_TYPE_BUF,
              &aws_access_key_id },
            { GG_STR("secretAccessKey"),
              GG_REQUIRED,
              GG_TYPE_BUF,
              &aws_secret_access_key },
            { GG_STR("sessionToken"),
              GG_REQUIRED,
              GG_TYPE_BUF,
              &aws_session_token },
        )
    );
    if (ret != GG_ERR_OK) {
        GG_LOGE("Failed to validate TES credentials.");
        return GG_ERR_FAILURE;
    }
    tes_creds->access_key_id = gg_obj_into_buf(*aws_access_key_id);
    tes_creds->secret_access_key = gg_obj_into_buf(*aws_secret_access_key);
    tes_creds->session_token = gg_obj_into_buf(*aws_session_token);
    return GG_ERR_OK;
}

#ifdef GG_SDK_TESTING

#include <assert.h>
#include <gg/test.h>
#include <string.h>
#include <unity.h>

static GgError tes_credentials_test_results[4];
static size_t tes_credentials_test_result_count;
static size_t tes_credentials_test_attempts;

static GgError get_test_tes_credentials(TesCredentials *tes_creds) {
    (void) tes_creds;
    size_t result_index = tes_credentials_test_attempts;
    tes_credentials_test_attempts += 1;
    if (result_index >= tes_credentials_test_result_count) {
        return GG_ERR_FATAL;
    }
    return tes_credentials_test_results[result_index];
}

static void set_tes_credentials_test_results(
    const GgError *results, size_t result_count
) {
    assert(
        result_count
        <= (sizeof(tes_credentials_test_results)
            / sizeof(tes_credentials_test_results[0]))
    );
    memcpy(
        tes_credentials_test_results,
        results,
        result_count * sizeof(tes_credentials_test_results[0])
    );
    tes_credentials_test_result_count = result_count;
    tes_credentials_test_attempts = 0;
}

GG_TEST_DEFINE(tes_credentials_cloud_retries_transient_errors) {
    const GgError RESULTS[]
        = { GG_ERR_NOCONN, GG_ERR_TIMEOUT, GG_ERR_RETRY, GG_ERR_OK };
    set_tes_credentials_test_results(
        RESULTS, (sizeof(RESULTS) / sizeof(RESULTS[0]))
    );

    TesCredentials credentials = { 0 };
    TEST_ASSERT_EQUAL(
        GG_ERR_OK,
        get_tes_credentials_with_retry(
            &credentials, get_test_tes_credentials, 1, 1
        )
    );
    TEST_ASSERT_EQUAL_UINT32(4, tes_credentials_test_attempts);
}

GG_TEST_DEFINE(tes_credentials_cloud_does_not_retry_permanent_error) {
    const GgError RESULTS[] = { GG_ERR_INVALID, GG_ERR_OK };
    set_tes_credentials_test_results(
        RESULTS, (sizeof(RESULTS) / sizeof(RESULTS[0]))
    );

    TesCredentials credentials = { 0 };
    TEST_ASSERT_EQUAL(
        GG_ERR_INVALID,
        get_tes_credentials_with_retry(
            &credentials, get_test_tes_credentials, 1, 1
        )
    );
    TEST_ASSERT_EQUAL_UINT32(1, tes_credentials_test_attempts);
}

#endif
