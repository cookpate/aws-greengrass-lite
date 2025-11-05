// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef GGL_PROCESS_H
#define GGL_PROCESS_H

//! Process management functionality

#include <ggl/error.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

/// This callback is registered to be called betweek fork() and exec()
/// The callback is allowed to modify argv and environ and perform syscalls
/// which are safe post-fork().
typedef GglError (*GglProcessSpawnCallback)(
    int handle, char ***argv, char ***environ, void *ctx
);

/// Spawn a child process with given arguments
/// Exactly one of wait or kill must eventually be called to clean up resources
/// and reap zombie.
/// argv must be null-terminated.
/// GglProcessSpawnCallback if set is invoked between fork() and execvp(), at
/// which point any pre-exec actions may be taken.
GglError ggl_process_spawn(
    const char *const argv[],
    int *handle,
    GglProcessSpawnCallback callback,
    void *ctx,
    uint32_t exec_timeout
);

/// Wait until child process exits
/// Cleans up handle and child zombie.
/// Will return OK if cleanup is successful, regardless of exit status.
GglError ggl_process_wait(int handle, bool *exit_status);

/// Kill a child process
/// If term_timeout > 0, first sends SIGTERM and waits up to timeout.
/// If term_timeout == 0, or timeout elapses, sends SIGKILL.
/// Cleans up handle and child zombie.
GglError ggl_process_kill(int handle, uint32_t term_timeout);

/// Run a process with given arguments, and return if successful.
/// argv must be null-terminated.
GglError ggl_process_call(const char *const argv[]);

#endif
