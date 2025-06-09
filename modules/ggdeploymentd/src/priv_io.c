// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "priv_io.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/io.h>
#include <ggl/vector.h>
#include <stddef.h>

static GglError byte_vec_write(void *ctx, GglBuffer buf) {
    if (buf.len == 0) {
        return GGL_ERR_OK;
    }
    if (ctx == NULL) {
        return GGL_ERR_NOMEM;
    }
    GglByteVec *byte_vec = (GglByteVec *) ctx;
    return ggl_byte_vec_append(byte_vec, buf);
}

GglWriter priv_byte_vec_writer(GglByteVec *byte_vec) {
    return (GglWriter) { .write = byte_vec_write, .ctx = byte_vec };
}
