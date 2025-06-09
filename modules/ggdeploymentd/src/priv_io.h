// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef GGDEPLOYMENTD_PRIV_IO_H
#define GGDEPLOYMENTD_PRIV_IO_H

// TODO: move into ggl-sdk io.h

#include <ggl/io.h>
#include <ggl/vector.h>

// Appends content onto the back of a byte vector
// Writer function returns GGL_ERR_NOMEM if append fails or if writer was
// created with NULL vec.
GglWriter priv_byte_vec_writer(GglByteVec *byte_vec);

#endif
