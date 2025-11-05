// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ggl/cleanup.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/process.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef _GNU_SOURCE
extern char **environ;
#endif

#ifdef SYS_close_range
#include <linux/close_range.h>
#endif

// Prevent multiple threads from unblocking SIGALRM
static pthread_mutex_t sigalrm_mtx = PTHREAD_MUTEX_INITIALIZER;

static void sigalrm_handler(int s) {
    (void) s;
}

// Lowest allowed priority in order to run before threads are created.
__attribute__((constructor(101))) static void setup_sigalrm(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    int sys_ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (sys_ret != 0) {
        GGL_LOGE("pthread_sigmask failed: %d", sys_ret);
        _Exit(1);
    }

    struct sigaction act = { .sa_handler = sigalrm_handler };
    sigaction(SIGALRM, &act, NULL);
}

#ifdef SYS_close_range
static int sys_close_range(unsigned first, unsigned last, unsigned flags) {
    return (int) syscall(SYS_close_range, first, last, flags);
}
#else
static int sys_close_range(unsigned first, unsigned last, unsigned flags) {
    (void) flags;
    int max_fd = (int) sysconf(_SC_OPEN_MAX);
    int range_last = (last < (unsigned) max_fd) ? (int) last : max_fd;
    for (int i = (int) first; i < range_last; i++) {
        close(i);
    }
    return 0;
}

#define CLOSE_RANGE_UNSHARE 2
#endif

static GglError close_parent_files(
    int handle, char ***argv, char ***envp, void *ctx
) {
    (void) handle;
    (void) argv;
    (void) envp;
    (void) ctx;
    int *pipe_fd = ctx;

    if (*pipe_fd < 3) {
        sys_close_range(3, UINT_MAX, CLOSE_RANGE_UNSHARE);
        return GGL_ERR_OK;
    }

    if (*pipe_fd > 3) {
        sys_close_range(3, (unsigned int) *pipe_fd - 1U, CLOSE_RANGE_UNSHARE);
    }
    sys_close_range(
        (unsigned int) *pipe_fd + 1U, UINT_MAX, CLOSE_RANGE_UNSHARE
    );
    return GGL_ERR_OK;
}

static GglError set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        GGL_LOGE("Failed to get flags on fd (errno=%d)", errno);
        return GGL_ERR_FAILURE;
    }
    if ((flags & FD_CLOEXEC) == FD_CLOEXEC) {
        return GGL_ERR_OK;
    }

    flags |= FD_CLOEXEC;
    int ret = fcntl(fd, F_SETFD, flags);
    if (ret == -1) {
        GGL_LOGE("Failed to set CLOEXEC on fd (errno=%d)", errno);
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggl_process_spawn(
    const char *const argv[],
    int *handle,
    GglProcessSpawnCallback callback,
    void *ctx,
    uint32_t exec_timeout
) {
    assert(argv[0] != NULL);
    assert(handle != NULL);

    if (exec_timeout > (uint32_t) (INT_MAX / 1000)) {
        exec_timeout = (uint32_t) (INT_MAX / 1000);
    }

    int pipe_fds[2] = { -1, -1 };
    int pipe_ret = pipe(pipe_fds);
    if (pipe_ret == -1) {
        return GGL_ERR_FAILURE;
    }
    int read_pipe = pipe_fds[0];
    int write_pipe = pipe_fds[1];
    GGL_CLEANUP(cleanup_close, read_pipe);
    GGL_CLEANUP(cleanup_close, write_pipe);
    GglError ret = set_cloexec(read_pipe);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    ret = set_cloexec(write_pipe);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    if (callback == NULL) {
        callback = close_parent_files;
        ctx = &write_pipe;
    }

    pid_t pid = fork();

    if (pid == 0) {
        ret = callback(pid, (char ***) &argv, &environ, ctx);

        int exec_ret;
        if (ret == GGL_ERR_OK) {
            execvp(argv[0], (char **) argv);
            exec_ret = errno;
            GGL_LOGE("Failed to exec (%d)", exec_ret);
        } else {
            GGL_LOGE("Callback failed (%d)", ret);
            exec_ret = (int) ret;
        }
        (void) ggl_file_write(
            write_pipe,
            (GglBuffer) { .data = (uint8_t *) &exec_ret,
                          .len = sizeof(exec_ret) }
        );

        _Exit(1);
    }

    if (pid < 0) {
        GGL_LOGE("Err %d when calling fork.", errno);
        return GGL_ERR_FAILURE;
    }

    int child_exit_status;
    ret = GGL_ERR_TIMEOUT;

    if (exec_timeout > 0) {
        sigset_t set;
        sigfillset(&set);
        sigdelset(&set, SIGALRM);
        sigset_t old_set;

        GGL_MTX_SCOPE_GUARD(&sigalrm_mtx);

        pthread_sigmask(SIG_SETMASK, &set, &old_set);

        alarm(exec_timeout);

        ssize_t bytes_read
            = read(read_pipe, &child_exit_status, sizeof(child_exit_status));

        alarm(0);

        if (bytes_read == sizeof(child_exit_status)) {
            ret = GGL_ERR_OK;
        } else if (bytes_read == 0) {
            ret = GGL_ERR_NODATA;
        } else {
            ret = GGL_ERR_TIMEOUT;
        }

        pthread_sigmask(SIG_SETMASK, &old_set, NULL);

    } else {
        ret = ggl_file_read_exact(
            read_pipe,
            (GglBuffer) { .data = (uint8_t *) &child_exit_status,
                          .len = sizeof(child_exit_status) }
        );
    }

    // Expected error code: GGL_ERR_NODATA (pipe was closed)

    if (ret == GGL_ERR_NODATA) {
        *handle = pid;
        return GGL_ERR_OK;
    }

    // OK means a return code was written and child exited
    if (ret == GGL_ERR_OK) {
        GGL_LOGE("Child failed to exec (%d)", child_exit_status);
        ret = GGL_ERR_FAILURE;
    }
    // Timeout means we alarmed.
    else if (ret == GGL_ERR_TIMEOUT) {
        GGL_LOGE("Child timed out waiting to exec.");
    }

    // in any error case, reap the child.
    (void) ggl_process_kill(pid, 0);
    return ret;
}

GglError ggl_process_wait(int handle, bool *exit_status) {
    while (true) {
        siginfo_t info = { 0 };
        int ret = waitid(P_PID, (id_t) handle, &info, WEXITED);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            GGL_LOGE("Err %d when calling waitid.", errno);
            return GGL_ERR_FAILURE;
        }

        switch (info.si_code) {
        case CLD_EXITED:
            if (exit_status != NULL) {
                *exit_status = info.si_status == 0;
            }
            return GGL_ERR_OK;
        case CLD_KILLED:
        case CLD_DUMPED:
            if (exit_status != NULL) {
                *exit_status = false;
            }
            return GGL_ERR_OK;
        default:;
        }
    }
}

GglError ggl_process_kill(int handle, uint32_t term_timeout) {
    if (term_timeout == 0) {
        kill(handle, SIGKILL);
        return ggl_process_wait(handle, NULL);
    }

    sigset_t set;
    sigfillset(&set);
    sigdelset(&set, SIGALRM);

    sigset_t old_set;

    kill(handle, SIGTERM);

    int waitid_ret;
    int waitid_err;

    {
        GGL_MTX_SCOPE_GUARD(&sigalrm_mtx);

        pthread_sigmask(SIG_SETMASK, &set, &old_set);

        alarm(term_timeout);

        siginfo_t info = { 0 };
        waitid_ret = waitid(P_PID, (id_t) handle, &info, WEXITED);
        waitid_err = errno;

        alarm(0);

        pthread_sigmask(SIG_SETMASK, &old_set, NULL);
    }

    if (waitid_ret == 0) {
        return GGL_ERR_OK;
    }

    if (waitid_err != EINTR) {
        GGL_LOGE("Err %d when calling waitid.", waitid_err);
        return GGL_ERR_FAILURE;
    }

    kill(handle, SIGKILL);

    return ggl_process_wait(handle, NULL);
}

GglError ggl_process_call(const char *const argv[]) {
    int handle;
    GglError ret = ggl_process_spawn(argv, &handle, NULL, NULL, 0);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    bool exit_status = false;
    ret = ggl_process_wait(handle, &exit_status);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    return exit_status ? GGL_ERR_OK : GGL_ERR_FAILURE;
}
