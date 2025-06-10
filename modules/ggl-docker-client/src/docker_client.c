/* aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ggl/docker_client.h"
#include "ggl/cleanup.h"
#include "ggl/file.h"
#include <ggl/base64.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/exec.h>
#include <ggl/http.h>
#include <ggl/io.h>
#include <ggl/json_encode.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

static GglError head_buf_write(void *context, GglBuffer buf) {
    GglByteVec *output = (GglByteVec *) context;
    GglBuffer remaining = ggl_byte_vec_remaining_capacity(*output);
    buf = ggl_buffer_substr(buf, 0, remaining.len);
    (void) ggl_byte_vec_append(output, buf);
    return GGL_ERR_OK;
}

// Captures the first N bytes of a payload. The rest are silently discarded.
static GglWriter head_buf_writer(GglByteVec *vec) {
    return (GglWriter) { .ctx = vec, .write = head_buf_write };
}

/// The max length of a docker image name including its repository and digest
#define DOCKER_MAX_IMAGE_LEN (4096U)

GglError ggl_docker_check_server(void) {
    const char *args[] = { "docker", "-v", NULL };
    uint8_t output_bytes[512U] = { 0 };
    GglByteVec output = GGL_BYTE_VEC(output_bytes);
    GglError err = ggl_exec_command_with_output(args, head_buf_writer(&output));
    if (err != GGL_ERR_OK) {
        if (output.buf.len == 0) {
            GGL_LOGE("Docker does not appear to be installed.");
        } else {
            GGL_LOGE(
                "docker -v failed with '%.*s'",
                (int) output.buf.len,
                output.buf.data
            );
        }
    }

    return err;
}

GglError ggl_docker_pull(GglBuffer image_name) {
    char image_null_term[DOCKER_MAX_IMAGE_LEN + 1U] = { 0 };
    if (image_name.len > DOCKER_MAX_IMAGE_LEN) {
        GGL_LOGE("Docker image name too long.");
        return GGL_ERR_INVALID;
    }
    memcpy(image_null_term, image_name.data, image_name.len);

    GGL_LOGD("Pulling %.*s", (int) image_name.len, image_name.data);
    const char *args[] = { "docker", "pull", "-q", image_null_term, NULL };
    GglError err = ggl_exec_command(args);
    if (err != GGL_ERR_OK) {
        GGL_LOGE("docker image pull failed.");
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggl_docker_remove(GglBuffer image_name) {
    char image_null_term[DOCKER_MAX_IMAGE_LEN + 1U] = { 0 };
    if (image_name.len > DOCKER_MAX_IMAGE_LEN) {
        GGL_LOGE("Docker image name too long.");
        return GGL_ERR_INVALID;
    }
    GGL_LOGD("Removing docker image '%s'", image_null_term);

    memcpy(image_null_term, image_name.data, image_name.len);
    const char *args[] = { "docker", "rmi", image_null_term, NULL };

    uint8_t output_bytes[512U] = { 0 };
    GglByteVec output = GGL_BYTE_VEC(output_bytes);
    GglError err = ggl_exec_command_with_output(args, head_buf_writer(&output));
    if (err != GGL_ERR_OK) {
        size_t start = 0;
        if (ggl_buffer_contains(output.buf, GGL_STR("No such image"), &start)) {
            GGL_LOGD("Image was not found to delete.");
            return GGL_ERR_OK;
        }
        GGL_LOGE(
            "docker rmi failed: '%.*s'", (int) output.buf.len, output.buf.data
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggl_docker_check_image(GglBuffer image_name) {
    char image_null_term[DOCKER_MAX_IMAGE_LEN + 1U] = { 0 };
    if (image_name.len > DOCKER_MAX_IMAGE_LEN) {
        GGL_LOGE("Docker image name too long.");
        return GGL_ERR_INVALID;
    }
    memcpy(image_null_term, image_name.data, image_name.len);

    GGL_LOGD("Finding docker image '%s'", image_null_term);

    const char *args[]
        = { "docker", "image", "ls", "-q", image_null_term, NULL };

    uint8_t output_bytes[256] = { 0 };
    GglByteVec output = GGL_BYTE_VEC(output_bytes);
    GglError err = ggl_exec_command_with_output(args, head_buf_writer(&output));
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "docker image ls -q failed: '%.*s'",
            (int) output.buf.len,
            output.buf.data
        );
        return GGL_ERR_FAILURE;
    }
    if (output.buf.len == 0) {
        return GGL_ERR_NOENTRY;
    }
    return GGL_ERR_OK;
}

GglError ggl_docker_credentials_store(
    GglBuffer registry, GglBuffer username, GglBuffer secret
) {
    GglObject payload_obj = ggl_obj_map(GGL_MAP(
        ggl_kv(GGL_STR("SeverURL"), ggl_obj_buf(registry)),
        ggl_kv(GGL_STR("Username"), ggl_obj_buf(username)),
        ggl_kv(GGL_STR("Secret"), ggl_obj_buf(secret))
    ));

    const char *const ARGS[]
        = { "docker-credential-secretservice", "store", NULL };
    return ggl_exec_command_with_input(ARGS, payload_obj);
}

GglError ggl_docker_credentials_ecr_retrieve(
    GglBuffer ecr_registry, SigV4Details sigv4_details
) {
    int fd = -1;
    uint16_t http_response = 400;
    GglError err = GGL_ERR_OK;
    {
        // ecr.<region>.amazonaws.com
        uint8_t url_buf[512];
        GglByteVec url = GGL_BYTE_VEC(url_buf);
        err = ggl_byte_vec_append(&url, GGL_STR("https://"));
        ggl_byte_vec_chain_append(&err, &url, GGL_STR("ecr."));
        ggl_byte_vec_chain_append(&err, &url, sigv4_details.aws_region);
        ggl_byte_vec_chain_append(
            &err, &url, GGL_STR(".amazonaws.com/GetAuthorizationToken\0")
        );

        if (err != GGL_ERR_OK) {
            GGL_LOGE("Failed to create GetAuthorizationToken URL");
            return err;
        }
        uint8_t host_buf[256];
        GglByteVec host = GGL_BYTE_VEC(host_buf);
        ggl_byte_vec_chain_append(&err, &host, GGL_STR("ecr."));
        ggl_byte_vec_chain_append(&err, &host, sigv4_details.aws_region);
        ggl_byte_vec_chain_append(&err, &host, GGL_STR(".amazonaws.com\0"));

        if (err != GGL_ERR_OK) {
            GGL_LOGE("Failed to create GetAuthorizationToken host");
            return err;
        }

        char template[] = "/tmp/ecr_credentials_XXXXXX";
        fd = mkstemp(template);
        if (fd < 0) {
            return GGL_ERR_FAILURE;
        }
        unlink(template);

        err = sigv4_download(
            (const char *) url_buf,
            host.buf,
            GGL_STR("GetAuthorizationToken"),
            fd,
            sigv4_details,
            &http_response
        );
    }

    GGL_CLEANUP_ID(cleanup_fd, cleanup_close, fd);

    uint8_t secret_buf[4096];
    off_t bytes_written = lseek(fd, 0, SEEK_CUR);
    if (((uintmax_t) bytes_written > SIZE_MAX)
        || ((size_t) bytes_written > sizeof(secret_buf))) {
        return GGL_ERR_NOMEM;
    }
    lseek(fd, 0, SEEK_SET);
    GglBuffer response = GGL_BUF(secret_buf);
    GglError read_err = ggl_file_read(fd, &response);
    if (read_err != GGL_ERR_OK) {
        return GGL_ERR_FAILURE;
    }
    (void) ggl_close(fd);
    cleanup_fd = -1;

    if ((err != GGL_ERR_OK) || (http_response != 200U)) {
        GGL_LOGE(
            "GetAuthorizationToken failed (HTTP=%" PRIu16 "): %.*s",
            http_response,
            (int) response.len,
            response.data
        );
        return GGL_ERR_FAILURE;
    }

    err = ggl_base64_decode_in_place(&response);
    if (err != GGL_ERR_OK) {
        return GGL_ERR_PARSE;
    }
    size_t split;
    if (!ggl_buffer_contains(response, GGL_STR(":"), &split)) {
        return GGL_ERR_PARSE;
    }
    GglBuffer username = ggl_buffer_substr(response, 0, split);
    GglBuffer secret = ggl_buffer_substr(response, split + 1U, SIZE_MAX);
    return ggl_docker_credentials_store(ecr_registry, username, secret);
}
