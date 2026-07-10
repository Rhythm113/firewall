#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "pgp_wrapper.h"

// Encrypts plaintext buffer using GnuPG CLI
int pgp_encrypt(const void *plaintext, size_t plaintext_len, char **ciphertext, size_t *ciphertext_len) {
    int in_pipe[2];
    int out_pipe[2];
    pid_t pid;

    if (pipe(in_pipe) < 0 || pipe(out_pipe) < 0) {
        perror("[pgp_wrapper] pipe creation failed");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("[pgp_wrapper] fork failed");
        return -1;
    }

    if (pid == 0) {
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);

        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        char *gpg_args[] = {
            "gpg",
            "--batch",
            "--yes",
            "--encrypt",
            "--sign",
            "--recipient", "agent@soc.local",
            "--trust-model", "always",
            "--armor",
            NULL
        };

        execvp("gpg", gpg_args);
        perror("[pgp_wrapper] execvp gpg failed");
        exit(1);
    } else {
        close(in_pipe[0]);
        close(out_pipe[1]);

        size_t total_written = 0;
        const char *ptr = (const char *)plaintext;
        while (total_written < plaintext_len) {
            ssize_t written = write(in_pipe[1], ptr + total_written, plaintext_len - total_written);
            if (written < 0) {
                perror("[pgp_wrapper] write to gpg stdin failed");
                close(in_pipe[1]);
                close(out_pipe[0]);
                waitpid(pid, NULL, 0);
                return -1;
            }
            total_written += written;
        }
        close(in_pipe[1]);

        size_t capacity = 4096;
        size_t total_read = 0;
        char *buffer = malloc(capacity);
        if (!buffer) {
            close(out_pipe[0]);
            waitpid(pid, NULL, 0);
            return -1;
        }

        while (1) {
            if (total_read + 1024 >= capacity) {
                capacity *= 2;
                char *new_buf = realloc(buffer, capacity);
                if (!new_buf) {
                    free(buffer);
                    close(out_pipe[0]);
                    waitpid(pid, NULL, 0);
                    return -1;
                }
                buffer = new_buf;
            }

            ssize_t bytes_read = read(out_pipe[0], buffer + total_read, 1024);
            if (bytes_read < 0) {
                perror("[pgp_wrapper] read from gpg stdout failed");
                free(buffer);
                close(out_pipe[0]);
                waitpid(pid, NULL, 0);
                return -1;
            }
            if (bytes_read == 0) {
                break;
            }
            total_read += bytes_read;
        }
        close(out_pipe[0]);

        buffer[total_read] = '\0';

        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "[pgp_wrapper] gpg encryption failed with exit code %d\n", WEXITSTATUS(status));
            free(buffer);
            return -1;
        }

        *ciphertext = buffer;
        *ciphertext_len = total_read;
        return 0;
    }
}

// Decrypts ciphertext buffer using GnuPG CLI
int pgp_decrypt(const char *ciphertext, size_t ciphertext_len, void **plaintext, size_t *plaintext_len) {
    int in_pipe[2];
    int out_pipe[2];
    pid_t pid;

    if (pipe(in_pipe) < 0 || pipe(out_pipe) < 0) {
        perror("[pgp_wrapper] pipe creation failed");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        perror("[pgp_wrapper] fork failed");
        return -1;
    }

    if (pid == 0) {
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);

        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);

        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        char *gpg_args[] = {
            "gpg",
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--decrypt",
            NULL
        };

        execvp("gpg", gpg_args);
        perror("[pgp_wrapper] execvp gpg decrypt failed");
        exit(1);
    } else {
        close(in_pipe[0]);
        close(out_pipe[1]);

        size_t total_written = 0;
        while (total_written < ciphertext_len) {
            ssize_t written = write(in_pipe[1], ciphertext + total_written, ciphertext_len - total_written);
            if (written < 0) {
                perror("[pgp_wrapper] write to gpg decrypt stdin failed");
                close(in_pipe[1]);
                close(out_pipe[0]);
                waitpid(pid, NULL, 0);
                return -1;
            }
            total_written += written;
        }
        close(in_pipe[1]);

        size_t capacity = 4096;
        size_t total_read = 0;
        unsigned char *buffer = malloc(capacity);
        if (!buffer) {
            close(out_pipe[0]);
            waitpid(pid, NULL, 0);
            return -1;
        }

        while (1) {
            if (total_read + 1024 >= capacity) {
                capacity *= 2;
                unsigned char *new_buf = realloc(buffer, capacity);
                if (!new_buf) {
                    free(buffer);
                    close(out_pipe[0]);
                    waitpid(pid, NULL, 0);
                    return -1;
                }
                buffer = new_buf;
            }

            ssize_t bytes_read = read(out_pipe[0], buffer + total_read, 1024);
            if (bytes_read < 0) {
                perror("[pgp_wrapper] read from gpg decrypt stdout failed");
                free(buffer);
                close(out_pipe[0]);
                waitpid(pid, NULL, 0);
                return -1;
            }
            if (bytes_read == 0) {
                break;
            }
            total_read += bytes_read;
        }
        close(out_pipe[0]);

        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "[pgp_wrapper] gpg decryption failed with exit status %d\n", WEXITSTATUS(status));
            free(buffer);
            return -1;
        }

        *plaintext = buffer;
        *plaintext_len = total_read;
        return 0;
    }
}
