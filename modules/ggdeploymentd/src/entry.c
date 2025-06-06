// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "bus_server.h"
#include "deployment_handler.h"
#include "ggdeploymentd.h"
#include "iot_jobs_listener.h"
#include "sys/stat.h"
#include "unistd.h"
#include <errno.h>
#include <fcntl.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/core_bus/gg_config.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/proxy/environment.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

GglError run_ggdeploymentd(const char *bin_path) {
    GGL_LOGI("Started ggdeploymentd process.");

    GglError ret = ggl_proxy_set_environment();
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    umask(0002);

    static uint8_t root_path_mem[PATH_MAX] = { 0 };
    GglArena alloc = ggl_arena_init(
        ggl_buffer_substr(GGL_BUF(root_path_mem), 0, sizeof(root_path_mem) - 1)
    );
    GglBuffer root_path;
    ret = ggl_gg_config_read_str(
        GGL_BUF_LIST(GGL_STR("system"), GGL_STR("rootPath")), &alloc, &root_path
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGW("Failed to get root path from config.");
        return ret;
    }

    int root_path_fd;
    ret = ggl_dir_open(root_path, O_PATH, false, &root_path_fd);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to open rootPath.");
        return ret;
    }

    int sys_ret = fchdir(root_path_fd);
    if (sys_ret != 0) {
        GGL_LOGE("Failed to enter rootPath: %d.", errno);
        (void) ggl_close(root_path_fd);
        return GGL_ERR_FAILURE;
    }

    GglDeploymentHandlerThreadArgs args = { .root_path_fd = root_path_fd,
                                            .root_path = root_path,
                                            .bin_path = bin_path };

    pthread_t ptid_jobs;
    pthread_create(&ptid_jobs, NULL, &job_listener_thread, &args);
    pthread_detach(ptid_jobs);

    pthread_t ptid_handler;
    pthread_create(&ptid_handler, NULL, &ggl_deployment_handler_thread, &args);
    pthread_detach(ptid_handler);

    ggdeploymentd_start_server();

    return GGL_ERR_OK;
}
