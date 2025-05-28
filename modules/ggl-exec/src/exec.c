/* aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ggl/exec.h"
#include "fcntl.h"
#include "ggl/cleanup.h"
#include "ggl/file.h"
#include "ggl/socket_epoll.h"
#include "ggl/vector.h"
#include "stdlib.h"
#include <errno.h>
#include <ggl/attr.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static GglError wait_for_process(pid_t pid) {
    int child_status;
    if (waitpid(pid, &child_status, 0) == -1) {
        GGL_LOGE("Error, waitpid got hit");
        return GGL_ERR_FAILURE;
    }
    if (!WIFEXITED(child_status)) {
        GGL_LOGD("Script did not exit normally");
        return GGL_ERR_FAILURE;
    }
    GGL_LOGI("Script exited with child status %d\n", WEXITSTATUS(child_status));
    if (WEXITSTATUS(child_status) != 0) {
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggl_exec_command(const char *const args[]) {
    int pid = -1;
    GglError err = ggl_exec_command_async(args, &pid);
    if (err != GGL_ERR_OK) {
        return err;
    }

    return wait_for_process(pid);
}

GglError ggl_exec_command_async(const char *const args[], pid_t *child_pid) {
    pid_t pid = -1;
    int ret = posix_spawnp(
        &pid, args[0], NULL, NULL, (char *const *) args, environ
    );
    if (ret != 0) {
        GGL_LOGE("Error, unable to spawn (%d)", ret);
        return GGL_ERR_FAILURE;
    }
    *child_pid = pid;
    return GGL_ERR_OK;
}

GglError ggl_exec_kill_process(pid_t process_id) {
    // Send the SIGTERM signal to the process

    // NOLINTBEGIN(concurrency-mt-unsafe, readability-else-after-return)
    if (kill(process_id, SIGTERM) == -1) {
        GGL_LOGE(
            "Failed to kill the process id %d : %s errno:%d.",
            process_id,
            strerror(errno),
            errno
        );
        return GGL_ERR_FAILURE;
    }

    int status;
    pid_t wait_pid;

    // Wait for the process to terminate
    do {
        wait_pid = waitpid(process_id, &status, 0);
        if (wait_pid == -1) {
            if (errno == ECHILD) {
                GGL_LOGE("Process %d has already terminated.\n", process_id);
                break;
            } else {
                GGL_LOGE(
                    "Error waiting for process %d: %s (errno: %d)\n",
                    process_id,
                    strerror(errno),
                    errno
                );
                break;
            }
        }

        if (WIFEXITED(status)) {
            GGL_LOGE(
                "Process %d exited with status %d.\n",
                process_id,
                WEXITSTATUS(status)
            );
        } else if (WIFSIGNALED(status)) {
            GGL_LOGE(
                "Process %d was killed by signal %d.\n",
                process_id,
                WTERMSIG(status)
            );
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    GGL_LOGI("Process %d has terminated.\n", process_id);

    // NOLINTEND(concurrency-mt-unsafe, readability-else-after-return)
    return GGL_ERR_OK;
}

static GglError read_pipe(int fd, GglBuffer *buf) NONNULL(2);
static GglError exec_output_ready(void *ctx, uint64_t data) NONNULL(1);

static GglError read_pipe(int fd, GglBuffer *buf) {
    ssize_t ret = read(fd, buf->data, buf->len);
    if (ret < 0) {
        if (errno == EINTR) {
            return GGL_ERR_RETRY;
        }
        if (errno == EWOULDBLOCK) {
            return GGL_ERR_NODATA;
        }
        GGL_LOGE("Failed to read fd %d: %d.", fd, errno);
        return GGL_ERR_FAILURE;
    }
    if (ret == 0) {
        return GGL_ERR_NODATA;
    }

    *buf = ggl_buffer_substr(*buf, (size_t) ret, SIZE_MAX);
    return GGL_ERR_OK;
}

typedef struct OutputContext {
    GglByteVec vec;
    int out;
    int err;
    int pidfd;
} OutputContext;

static GglError exec_output_ready(void *ctx, uint64_t data) {
    OutputContext *context = (OutputContext *) ctx;
    uint8_t buffer_bytes[1024];
    GglBuffer buffer = GGL_BUF(buffer_bytes);

    switch (data) {
        // stdout readable
    case 1: {
        GglError err = GGL_ERR_FAILURE;
        while ((err = read_pipe(context->out, &buffer)) != GGL_ERR_FAILURE) {
            if (err == GGL_ERR_NODATA) {
                return GGL_ERR_OK;
            }
            if (err == GGL_ERR_OK) {
                (void) ggl_byte_vec_append(&context->vec, buffer);
            }
        }
        return GGL_ERR_FAILURE;
    }

    // stderr readable
    case 2: {
        GglError err = GGL_ERR_FAILURE;
        while ((err = read_pipe(context->err, &buffer)) != GGL_ERR_FAILURE) {
            if (err == GGL_ERR_NODATA) {
                return GGL_ERR_OK;
            }
            if (err == GGL_ERR_OK) {
                (void) ggl_byte_vec_append(&context->vec, buffer);
            }
        }
        return GGL_ERR_FAILURE;
    }

    // Process finished
    case 4: {
        siginfo_t info = { 0 };
        int ret = -1;

        while (((ret = waitid(
                     P_PIDFD, (id_t) context->pidfd, &info, WEXITED | WNOHANG
                 ))
                != 0)
               && (errno == EINTR)) { }

        if (ret != 0) {
            GGL_LOGE("Couldn't wait for process (%d).", context->pidfd);
            return GGL_ERR_FAILURE;
        }
        if ((info.si_code != CLD_EXITED) || (info.si_status != 0)) {
            GGL_LOGE(
                "Process exited uncleanly (%d:%d).",
                info.si_code,
                info.si_status
            );
            return GGL_ERR_FAILURE;
        }
        GGL_LOGD("Process finished.");
        return GGL_ERR_EXPECTED;
    }

    default:
        return GGL_ERR_INVALID;
    }
}

GglError ggl_exec_command_with_output(
    const char *const args[], GglBuffer *output
) {
    GglByteVec vector = ggl_byte_vec_init(*output);
    output->len = 0;

    int cout_pipe[2] = { -1, -1 };
    int cerr_pipe[2] = { -1, -1 };
    posix_spawn_file_actions_t action = { 0 };

    int ret = pipe(cout_pipe);
    if (ret != 0) {
        GGL_LOGE("Failed to create pipe (%d)", errno);
        return GGL_ERR_FAILURE;
    };
    GGL_CLEANUP(cleanup_close, cout_pipe[0]);
    GGL_CLEANUP(cleanup_close, cout_pipe[1]);

    ret = pipe(cerr_pipe);
    if (ret != 0) {
        GGL_LOGE("Failed to create pipe (%d)", errno);
        return GGL_ERR_FAILURE;
    }
    GGL_CLEANUP(cleanup_close, cerr_pipe[0]);
    GGL_CLEANUP(cleanup_close, cerr_pipe[1]);

    posix_spawn_file_actions_init(&action);
    posix_spawn_file_actions_addclose(&action, cout_pipe[0]);
    posix_spawn_file_actions_addclose(&action, cerr_pipe[0]);
    posix_spawn_file_actions_adddup2(&action, cout_pipe[1], 1);
    posix_spawn_file_actions_adddup2(&action, cerr_pipe[1], 2);

    posix_spawn_file_actions_addclose(&action, cout_pipe[1]);
    posix_spawn_file_actions_addclose(&action, cerr_pipe[1]);
    int pidfd = -1;
    ret = pidfd_spawnp(
        &pidfd, args[0], &action, NULL, (char *const *) args, environ
    );

    if (ret != 0) {
        GGL_LOGE("Error, unable to spawn (%d)", ret);
        return GGL_ERR_FAILURE;
    }
    GGL_CLEANUP(cleanup_close, pidfd);

    int epoll = -1;
    GglError err = ggl_socket_epoll_create(&epoll);
    if (err != GGL_ERR_OK) {
        return err;
    }

    ret = fcntl(cout_pipe[0], O_NONBLOCK);
    if (ret != 0) {
        return GGL_ERR_FAILURE;
    }

    err = ggl_socket_epoll_add(epoll, cout_pipe[0], 1);
    if (err != GGL_ERR_OK) {
        return err;
    }

    ret = fcntl(cerr_pipe[0], O_NONBLOCK);
    if (ret != 0) {
        return GGL_ERR_FAILURE;
    }
    err = ggl_socket_epoll_add(epoll, cerr_pipe[0], 2);
    if (err != GGL_ERR_OK) {
        return err;
    }

    err = ggl_socket_epoll_add(epoll, pidfd, 4);
    OutputContext context = {
        .vec = vector, .out = cout_pipe[0], .err = cout_pipe[1], .pidfd = pidfd
    };
    err = ggl_socket_epoll_run(epoll, exec_output_ready, (void *) output);
    *output = context.vec.buf;
    return err;
}
