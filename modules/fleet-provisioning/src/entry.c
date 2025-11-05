// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "cloud_request.h"
#include "config_operations.h"
#include "fleet-provisioning.h"
#include "pki_ops.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/cleanup.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <ggl/process.h>
#include <ggl/proxy/environment.h>
#include <ggl/socket_server.h>
#include <ggl/utils.h>
#include <ggl/vector.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TEMPLATE_LEN 128
#define MAX_ENDPOINT_LENGTH 128
#define MAX_TEMPLATE_PARAM_LEN 4096
#define MAX_CSR_LENGTH 4096

#define USER_GROUP (GGL_SYSTEMD_SYSTEM_USER ":" GGL_SYSTEMD_SYSTEM_GROUP)

static GglError cleanup_actions(
    GglBuffer output_dir_path,
    GglBuffer tmp_cert_path,
    GglBuffer thing_name,
    FleetProvArgs *args
) {
    // Create destination directory
    const char *mkdir_dest_args[]
        = { "mkdir", "-p", (char *) output_dir_path.data, NULL };
    GglError ret = ggl_process_call(mkdir_dest_args);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to create destination directory");
        return ret;
    }
    GGL_LOGI("Successfully created destination directory");

    // Copy certificates from output_dir contents to destination_dir (overwrite
    // existing)
    static uint8_t cmd_mem[PATH_MAX * 2];
    GglByteVec cmd = GGL_BYTE_VEC(cmd_mem);
    ret = ggl_byte_vec_append(&cmd, GGL_STR("cp -rf "));
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    ret = ggl_byte_vec_append(&cmd, tmp_cert_path);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    ret = ggl_byte_vec_append(&cmd, GGL_STR("* "));
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    ret = ggl_byte_vec_append(&cmd, output_dir_path);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    ret = ggl_byte_vec_push(&cmd, '\0');
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    const char *sh_args[] = { "sh", "-c", (char *) cmd.buf.data, NULL };
    ret = ggl_process_call(sh_args);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to copy certificates to destination directory");
        return ret;
    }
    GGL_LOGI("Successfully copied certificates to destination directory");

    ret = ggl_update_system_cert_paths(output_dir_path, args, thing_name);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    ret = ggl_update_iot_endpoints(args);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    const char *chown_args[]
        = { "chown", "-R", USER_GROUP, (char *) output_dir_path.data, NULL };

    ret = ggl_process_call(chown_args);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to change ownership of certificates");
        return ret;
    }
    GGL_LOGI(
        "Successfully changed ownership of certificates to %s", USER_GROUP
    );

    return GGL_ERR_OK;
}

static GglError setup_iotcored_for_socket_activation(
    int pid, char ***argv, char ***envp, void *ctx
) {
    assert(ctx != NULL);
    assert(envp != NULL);
    (void) argv;

    int *socket_fd = ctx;

    // search envp for LISTEN_PID
    GglBuffer pid_str = { 0 };
    char **envs = *envp;
    while (envs != NULL) {
        GglBuffer found = ggl_buffer_from_null_term(*envs);
        if (ggl_buffer_remove_prefix(&found, GGL_STR("LISTEN_PID="))) {
            pid_str = found;
            break;
        }
        ++envs;
    }

    if ((pid_str.data == NULL) || (pid_str.len <= 0U)) {
        GGL_LOGE("Failed to find child env");
        return GGL_ERR_FAILURE;
    }
    int format_ret
        = snprintf((char *) pid_str.data, pid_str.len - 1U, "%d", pid);
    if (format_ret < 0) {
        GGL_LOGE("Failed to modify child env");
        return GGL_ERR_FAILURE;
    }
    pid_str.data[format_ret] = '\0';

    // reopen socket_fd where iotcored expects it
    dup2(*socket_fd, 3);
    (void) ggl_close(*socket_fd);

    return GGL_ERR_OK;
}

static GglError start_iotcored(
    FleetProvArgs *args, int *iotcored_pid, int socket_fd
) {
    static uint8_t uuid_mem[37];
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unparse(binuuid, (char *) uuid_mem);
    uuid_mem[36] = '\0';

    const char *iotcore_d_args[]
        = { args->iotcored_path, "-n", "iotcoredfleet",   "-e",
            args->endpoint,      "-i", (char *) uuid_mem, "-r",
            args->root_ca_path,  "-c", args->claim_cert,  "-k",
            args->claim_key,     NULL };

    GglError ret = ggl_process_spawn(
        iotcore_d_args,
        iotcored_pid,
        setup_iotcored_for_socket_activation,
        &socket_fd,
        10U
    );

    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to start iotcored.");
        return ret;
    }

    GGL_LOGD("PID for new iotcored: %d", *iotcored_pid);
    return GGL_ERR_OK;
}

static void cleanup_kill_process(const int *pid) {
    if (*pid >= 0) {
        (void) ggl_process_kill(*pid, 30U);
    }
}

static GglError set_iotcored_environment(void) {
    // No other threads call setenv
    // NOLINTBEGIN(concurrency-mt-unsafe)
    GglError proxy_ret = ggl_proxy_set_environment();
    if (proxy_ret != GGL_ERR_OK) {
        GGL_LOGW("Failed to set proxy environment variables.");
    }
    int setenv_ret = setenv("LISTEN_FDNAMES", "aws_iot_mqtt", true);
    if (setenv_ret == -1) {
        return GGL_ERR_FAILURE;
    }
    setenv_ret = setenv("LISTEN_FDS", "1", true);
    if (setenv_ret == -1) {
        return GGL_ERR_FAILURE;
    }
    setenv_ret = setenv("LISTEN_PID", "..........", true);
    if (setenv_ret == -1) {
        return GGL_ERR_FAILURE;
    }
    // NOLINTEND(concurrency-mt-unsafe)
    return GGL_ERR_OK;
}

GglError run_fleet_prov(FleetProvArgs *args) {
    uint8_t config_resp_mem[PATH_MAX] = { 0 };
    GglArena alloc = ggl_arena_init(GGL_BUF(config_resp_mem));

    static uint8_t template_params_mem[MAX_TEMPLATE_PARAM_LEN] = { 0 };
    GglArena template_alloc = ggl_arena_init(GGL_BUF(template_params_mem));
    GglMap template_params = { 0 };

    bool enabled = false;
    GglError ret = ggl_has_provisioning_config(alloc, &enabled);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    if (!enabled) {
        return GGL_ERR_OK;
    }

    // Skip if already provisioned
    bool provisioned = false;
    ret = ggl_is_already_provisioned(alloc, &provisioned);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    if (provisioned) {
        GGL_LOGI("Skipping provisioning.");
        return GGL_ERR_OK;
    }

    GglBuffer tmp_cert_path = GGL_STR("/tmp/provisioning/");

    ret = ggl_get_configuration(args);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    ret = ggl_load_template_params(args, &template_alloc, &template_params);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    int output_dir;
    ret = ggl_dir_open(tmp_cert_path, O_PATH, true, &output_dir);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE(
            "Error opening output directory %.*s.",
            (int) tmp_cert_path.len,
            tmp_cert_path.data
        );
        return ret;
    }
    GGL_CLEANUP(cleanup_close, output_dir);

    ret = set_iotcored_environment();
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to set socket environment variables (%d).", errno);
        return ret;
    }

    int socket_fd = -1;
    ret = ggl_socket_open(
        GGL_STR("/run/greengrass/iotcoredfleet"), 0660, &socket_fd
    );
    GGL_CLEANUP_ID(cleanup_socket_fd, cleanup_close, socket_fd);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error opening core bus socket.");
        return ret;
    }

    int iotcored_pid = -1;
    ret = start_iotcored(args, &iotcored_pid, socket_fd);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    (void) ggl_close(socket_fd);
    cleanup_socket_fd = -1;
    GGL_CLEANUP(cleanup_kill_process, iotcored_pid);

    int priv_key;
    ret = ggl_file_openat(
        output_dir, GGL_STR("priv_key"), O_RDWR | O_CREAT, 0600, &priv_key
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error opening private key file for writing.");
        return ret;
    }
    GGL_CLEANUP(cleanup_close, priv_key);

    int pub_key;
    ret = ggl_file_openat(
        output_dir, GGL_STR("pub_key.pub"), O_RDWR | O_CREAT, 0600, &pub_key
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error opening public key file for writing.");
        return ret;
    }
    GGL_CLEANUP(cleanup_close, pub_key);

    int cert_req;
    ret = ggl_file_openat(
        output_dir, GGL_STR("cert_req.pem"), O_RDWR | O_CREAT, 0600, &cert_req
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error opening CSR file for writing.");
        return ret;
    }
    GGL_CLEANUP(cleanup_close, cert_req);

    ret = ggl_pki_generate_keypair(
        priv_key, pub_key, cert_req, args->csr_common_name
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    (void) lseek(priv_key, 0, SEEK_SET);
    (void) lseek(pub_key, 0, SEEK_SET);
    (void) lseek(cert_req, 0, SEEK_SET);

    // Read CSR from file descriptor
    uint8_t csr_mem[MAX_CSR_LENGTH] = { 0 };
    ssize_t csr_len = read(cert_req, csr_mem, sizeof(csr_mem) - 1);
    if (csr_len <= 0) {
        GGL_LOGE("Failed to read CSR from file.");
        return GGL_ERR_FAILURE;
    }
    GglBuffer csr_buf = { .data = csr_mem, .len = (size_t) csr_len };

    // Create certificate output file
    int certificate_fd;
    ret = ggl_file_openat(
        output_dir,
        GGL_STR("certificate.pem"),
        O_RDWR | O_CREAT,
        0600,
        &certificate_fd
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error opening certificate file for writing.");
        return ret;
    }
    GGL_CLEANUP(cleanup_close, certificate_fd);

    // Wait for MQTT(iotcored) connection to establish
    (void) ggl_sleep(5);

    static uint8_t thing_name_mem[128];
    GglBuffer thing_name = GGL_BUF(thing_name_mem);

    ret = ggl_get_certificate_from_aws(
        csr_buf,
        ggl_buffer_from_null_term(args->template_name),
        template_params,
        &thing_name,
        certificate_fd
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    GglBuffer output_dir_path = GGL_STR("/var/lib/greengrass/credentials/");
    if (args->output_dir != NULL) {
        output_dir_path = ggl_buffer_from_null_term(args->output_dir);
    }

    ret = cleanup_actions(output_dir_path, tmp_cert_path, thing_name, args);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    GGL_LOGI("Process Complete, Your device is now provisioned");
    return GGL_ERR_OK;
}
