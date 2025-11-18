/**
 * sandboxed_echo.c
 *
 * This wildly unexciting binary reads exactly one line from stdin,
 * echoes it back out, and tattles to the bait log if the line smells
 * suspicious (or merely enthusiastic about flags). The implementation
 * is aggressively single-purpose on purpose; fancy code invites fancy
 * mistakes, and we already have enough of those elsewhere.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef LOG_PATH
#define LOG_PATH "/tmp/bait.log"
#endif

static void die(const char *message) {
    fprintf(stderr, "[sandboxed_echo] fatal: %s\n", message);
    exit(EXIT_FAILURE);
}

static void append_log(const char *tag, const char *payload) {
    FILE *log = fopen(LOG_PATH, "a");
    if (!log) {
        return;
    }

    time_t now = time(NULL);
    struct tm *stamp = gmtime(&now);
    if (!stamp) {
        fclose(log);
        return;
    }

    char buffer[64];
    if (strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", stamp) == 0) {
        fclose(log);
        return;
    }

    fprintf(log, "%s | %s | %s\n", buffer, tag, payload);
    fclose(log);
}

static int looks_suspicious(const char *input) {
    const char *keywords[] = {
        "flag",
        "FLAG",
        "Flag",
        "syscall",
        "ptrace",
        "open",
        "read",
        "write",
        "mmap",
        "exec",
        "binsh",
        "cat /",
        "sh",
        "bash",
        NULL
    };

    for (const char **keyword = keywords; *keyword; ++keyword) {
        if (strstr(input, *keyword) != NULL) {
            return 1;
        }
    }
    return 0;
}

int main(void) {
    static char buffer[512];

    if (isatty(STDIN_FILENO)) {
        append_log("notice", "stdin connected to tty; someone is poking the sandbox manually");
    }

    if (!fgets(buffer, sizeof(buffer), stdin)) {
        if (ferror(stdin)) {
            append_log("error", "failed to read stdin");
            die("unable to read input");
        }
        append_log("warning", "received empty stdin");
        printf("[sandboxed] no input received\n");
        fflush(stdout);
        return EXIT_SUCCESS;
    }

    buffer[strcspn(buffer, "\r\n")] = '\0';

    printf("%s\n", buffer);
    fflush(stdout);

    append_log("echo", buffer);

    if (looks_suspicious(buffer)) {
        // Before current ISO8601 logging
        fprintf(stderr, "[TRAP] User tried command: %s\n", buffer);
        append_log("alert", buffer);
        fprintf(stderr, "[sandboxed_echo] suspicious content detected; event logged\n");
    } else {
        fprintf(stderr, "[sandboxed_echo] input classified as boring\n");
    }

    return EXIT_SUCCESS;
}
