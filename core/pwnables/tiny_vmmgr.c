/**
 * =========================================================================
 *  ISOL8R :: Project Sandtrap
 *  tiny_vmmgr.c - Portable Virtual Machine Manager for Shellcode Experiments
 * =========================================================================
 *
 *  OVERVIEW
 *  --------
 *  This file implements a small, obstinate, and eager-to-please virtual 
 *  machine harness that accepts raw shellcode from the operator and 
 *  dutifully copies it into an RWX memory region. The sarcastic logs and 
 *  delightfully naive detection rules are designed to mimic an internal 
 *  research tool the security team reluctantly inherited from enthusiastic 
 *  colleagues. We keep the functionality sharp enough for genuine exploit
 *  research while sprinkling in enough honeypots to keep analysts awake. 
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------
 *  CONSTANTS AND MACROS
 * ---------------------------------------------------------------------------
 */

/** The maximum number of bytes of shellcode we will accept. */
#define VMMGR_MAX_SHELLCODE_SIZE 4096u

/** If the user supplies a payload smaller than this, we still allocate a full page. */
#define VMMGR_PAGE_SIZE 4096u

/** Path to the honeypot log file */
#define VMMGR_BAIT_LOG_PATH "/app/logs/bait.log"

/** Default shellcode source indicator. */
#define VMMGR_INPUT_STDIN "-"

/** Macro to supress unused parameter warnings in certain helper functions. */
#define VMMGR_UNUSED(x) (void)(x)

/** Macro to ensure we exit gracefully with a consistent exit code. */
#define VMMGR_EXIT_FAILURE 1
#define VMMGR_EXIT_SUCCESS 0

/** Macro to handle memory allocation failure uniformly. */
#define VMMGR_CHECK_ALLOC(ptr)                   \
    do {                                         \
        if ((ptr) == NULL) {                     \
            perror("[tiny_vmmgr] malloc");       \
            exit(VMMGR_EXIT_FAILURE);            \
        }                                        \
    } while (0)

/** Macro to simplify writing banner text. */
#define VMMGR_BANNER_LINE(msg) puts(msg)

/** Helper macro to calculate length of static arrays. */
#define VMMGR_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/* ---------------------------------------------------------------------------
 *  FORWARD DECLARATIONS
 * ---------------------------------------------------------------------------
 */

struct shellcode_buffer;

static void vmmgr_print_banner(void);
static void vmmgr_print_usage(const char *program_name);
static FILE *vmmgr_open_input_stream(int argc, char *const argv[]);
static struct shellcode_buffer vmmgr_read_shellcode(FILE *stream);
static bool vmmgr_contains_null_byte(const struct shellcode_buffer *buffer);
static void vmmgr_log_bait_event(const char *pattern, const struct shellcode_buffer *buffer);
static bool vmmgr_contains_pattern(const struct shellcode_buffer *buffer, const uint8_t *pattern, size_t pattern_len);
static bool vmmgr_contains_string(const struct shellcode_buffer *buffer, const char *needle);
static bool vmmgr_inspect_shellcode(const struct shellcode_buffer *buffer);
static void vmmgr_warn_about_nulls(bool contains_nulls);
static void vmmgr_execute_shellcode(const struct shellcode_buffer *buffer);
static void vmmgr_handle_bait_detection(const char *pattern, const struct shellcode_buffer *buffer, const char *message);
static void vmmgr_secure_zero(void *ptr, size_t len);

/* ---------------------------------------------------------------------------
 *  DATA STRUCTURES
 * ---------------------------------------------------------------------------
 */

/**
 * A simple heap-backed buffer storing user-supplied shellcode, along with
 * metadata that simplifies logging and analysis.
 */
struct shellcode_buffer {
    uint8_t *data;      /**< Pointer to the raw shellcode bytes. */
    size_t length;      /**< Total number of bytes read. */
    bool from_stdin;    /**< Whether the payload was sourced from stdin. */
};

/* ---------------------------------------------------------------------------
 *  UTILITY FUNCTIONS
 * ---------------------------------------------------------------------------
 */

/**
 * Securely zeroes memory to avoid leaving copies of shellcode around longer
 * than necessary. Implemented with volatile pointer semantics to discourage
 * the compiler from optimising it out.
 */
static void vmmgr_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0u;
    }
}

/**
 * Prints the ASCII art banner sparingly used by the VM manager. The banner is
 * intentionally understated; the harness aspires to look like an internal tool,
 * not a carnival ride.
 */
static void vmmgr_print_banner(void) {
    VMMGR_BANNER_LINE("====================================");
    VMMGR_BANNER_LINE(" tiny_vmmgr :: ISOL8R VM Harness");
    VMMGR_BANNER_LINE("====================================");
}

/**
 * Provides usage information when the operator supplies invalid arguments.
 *
 * @param program_name The name of the executable (argv[0]).
 */
static void vmmgr_print_usage(const char *program_name) {
    fprintf(stderr,
            "Usage: %s [shellcode_file|-]\n"
            "  - If no argument is provided, shellcode is read from stdin.\n"
            "  - Passing '-' explicitly also reads from stdin.\n"
            "  - Any other single argument is treated as a file path.\n",
            program_name);
}

/**
 * Opens the input stream from which shellcode will be read. Supports stdin
 * (default) or a file specified by the user. Additional arguments trigger the
 * usage message.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return A FILE pointer ready for reading shellcode.
 */
static FILE *vmmgr_open_input_stream(int argc, char *const argv[]) {
    if (argc == 1) {
        return stdin;
    }

    if (argc == 2) {
        if (strcmp(argv[1], VMMGR_INPUT_STDIN) == 0) {
            return stdin;
        }

        FILE *file = fopen(argv[1], "rb");
        if (!file) {
            fprintf(stderr, "[tiny_vmmgr] Failed to open '%s': %s\n", argv[1], strerror(errno));
            exit(VMMGR_EXIT_FAILURE);
        }
        return file;
    }

    vmmgr_print_usage(argv[0]);
    exit(VMMGR_EXIT_FAILURE);
}

/**
 * Reads shellcode from the provided stream into a heap-backed buffer. The
 * function enforces a strict size limit and exits gracefully if the payload
 * exceeds expectations.
 *
 * @param stream Input stream (stdin or file).
 * @return A populated shellcode_buffer structure.
 */
static struct shellcode_buffer vmmgr_read_shellcode(FILE *stream) {
    uint8_t *buffer = (uint8_t *)malloc(VMMGR_MAX_SHELLCODE_SIZE);
    VMMGR_CHECK_ALLOC(buffer);

    size_t total_read = 0u;
    while (!feof(stream) && total_read < VMMGR_MAX_SHELLCODE_SIZE) {
        size_t bytes_read = fread(buffer + total_read, 1, VMMGR_MAX_SHELLCODE_SIZE - total_read, stream);
        total_read += bytes_read;
        if (bytes_read == 0) {
            if (ferror(stream)) {
                perror("[tiny_vmmgr] fread");
                free(buffer);
                exit(VMMGR_EXIT_FAILURE);
            }
            break;
        }
    }

    if (total_read == VMMGR_MAX_SHELLCODE_SIZE && !feof(stream)) {
        fprintf(stderr, "[tiny_vmmgr] Payload exceeds %u bytes. Please behave.\n", VMMGR_MAX_SHELLCODE_SIZE);
        free(buffer);
        exit(VMMGR_EXIT_FAILURE);
    }

    struct shellcode_buffer result = {
        .data = buffer,
        .length = total_read,
        .from_stdin = (stream == stdin),
    };

    if (stream != stdin) {
        fclose(stream);
    }

    return result;
}

/**
 * Checks whether the supplied shellcode contains a null byte. This often hints
 * at string-based payload tooling mishaps, so the harness merely warns.
 *
 * @param buffer Pointer to the shellcode buffer.
 * @return True if a null byte is present, false otherwise.
 */
static bool vmmgr_contains_null_byte(const struct shellcode_buffer *buffer) {
    if (!buffer || !buffer->data) {
        return false;
    }
    for (size_t i = 0; i < buffer->length; ++i) {
        if (buffer->data[i] == 0x00u) {
            return true;
        }
    }
    return false;
}

/**
 * Appends a formatted entry to the bait log, tagging the security team and
 * leaving breadcrumbs for post-incident forensics. The message includes the
 * detected pattern and the timestamp in UTC.
 *
 * @param pattern Detected suspicious pattern.
 * @param buffer  Pointer to the offending payload (for length reporting).
 */
static void vmmgr_log_bait_event(const char *pattern, const struct shellcode_buffer *buffer) {
    FILE *log = fopen(VMMGR_BAIT_LOG_PATH, "a");
    if (!log) {
        fprintf(stderr, "[tiny_vmmgr] Warning: unable to open bait log at '%s': %s\n", VMMGR_BAIT_LOG_PATH, strerror(errno));
        return;
    }

    time_t now = time(NULL);
    struct tm tm_snapshot;
    gmtime_r(&now, &tm_snapshot);

    char timestamp[64];
    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_snapshot) == 0) {
        strncpy(timestamp, "1970-01-01 00:00:00", sizeof(timestamp));
        timestamp[sizeof(timestamp) - 1] = '\0';
    }

    size_t payload_length = buffer && buffer->data ? buffer->length : 0u;
    size_t preview_len = payload_length < 16 ? payload_length : 16;

    char hex_preview[3 * 16 + 5];
    hex_preview[0] = '\0';
    if (preview_len > 0 && buffer && buffer->data) {
        size_t offset = 0;
        for (size_t i = 0; i < preview_len && offset + 3 < sizeof(hex_preview); ++i) {
            int written = snprintf(hex_preview + offset,
                                   sizeof(hex_preview) - offset,
                                   "%02x%s",
                                   buffer->data[i],
                                   (i + 1 < preview_len) ? " " : "");
            if (written <= 0) {
                hex_preview[0] = '\0';
                break;
            }
            offset += (size_t)written;
        }
        if (payload_length > preview_len && offset + 4 < sizeof(hex_preview)) {
            snprintf(hex_preview + offset, sizeof(hex_preview) - offset, " ...");
        }
    }

    const char *hex_dump = (hex_preview[0] != '\0') ? hex_preview : "(empty)";

    fprintf(log,
            "[BAIT] [VMMGR] Pattern '%s' detected in payload (length=%zu) at %s\n",
            pattern ? pattern : "unknown",
            payload_length,
            timestamp);
    fprintf(log,
            "[BAIT] [VMMGR] Payload hex dump: %s at %s\n",
            hex_dump,
            timestamp);
    fclose(log);
}

/**
 * Searches the shellcode buffer for a raw byte pattern.
 *
 * @param buffer      Shellcode buffer.
 * @param pattern     Byte sequence to find.
 * @param pattern_len Length of the pattern.
 * @return True if the pattern is found.
 */
static bool vmmgr_contains_pattern(const struct shellcode_buffer *buffer, const uint8_t *pattern, size_t pattern_len) {
    if (!buffer || !buffer->data || pattern_len == 0) {
        return false;
    }

    for (size_t i = 0; i + pattern_len <= buffer->length; ++i) {
        if (memcmp(buffer->data + i, pattern, pattern_len) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Searches the shellcode buffer for a string (case-sensitive).
 *
 * @param buffer Shellcode buffer.
 * @param needle Null-terminated string to search for.
 * @return True if the string appears within the payload.
 */
static bool vmmgr_contains_string(const struct shellcode_buffer *buffer, const char *needle) {
    if (!buffer || !buffer->data || !needle) {
        return false;
    }

    const size_t needle_len = strlen(needle);
    if (needle_len == 0) {
        return false;
    }

    return vmmgr_contains_pattern(buffer, (const uint8_t *)needle, needle_len);
}

/**
 * Handles bait detection events: logs the attempt, prints a sarcastic quip,
 * and terminates the program.
 *
 * @param pattern Human-readable description of the detected pattern.
 * @param buffer  The offending payload.
 * @param message Sarcastic message to display to the user.
 */
static void vmmgr_handle_bait_detection(const char *pattern, const struct shellcode_buffer *buffer, const char *message) {
    vmmgr_log_bait_event(pattern, buffer);
    if (message && *message) {
        fprintf(stderr, "%s\n", message);
    }

    if (buffer && buffer->data) {
        vmmgr_secure_zero(buffer->data, buffer->length);
        free(buffer->data);
    }
    exit(VMMGR_EXIT_FAILURE);
}

/**
 * Inspects the shellcode for banned patterns. Returns true if the payload is
 * deemed safe, false otherwise. The function handles logging when necessary.
 *
 * @param buffer Shellcode buffer.
 * @return True if no banned patterns were found.
 */
static bool vmmgr_inspect_shellcode(const struct shellcode_buffer *buffer) {
    if (!buffer || !buffer->data) {
        return false;
    }

    static const struct {
        const char *description;
        const char *message;
        const uint8_t pattern[8];
        size_t length;
        bool is_string;
    } detectors[] = {
        {
            .description = "/bin/sh",
            .message = "[VMMGR] A classic. Predictable. Blocked.",
            .pattern = "/bin/sh",
            .length = 7,
            .is_string = true,
        },
        {
            .description = "execve",
            .message = "[VMMGR] execve? How original. Try again.",
            .pattern = "execve",
            .length = 6,
            .is_string = true,
        },
        {
            .description = "syscall (0x0f 0x05)",
            .message = "[VMMGR] Forbidden fruits are the juiciest. But no.",
            .pattern = {0x0f, 0x05},
            .length = 2,
            .is_string = false,
        },
        {
            .description = "syscall",
            .message = "[VMMGR] 'syscall' spelled out? Subtlety is a virtue.",
            .pattern = "syscall",
            .length = 7,
            .is_string = true,
        },
        {
            .description = "flag",
            .message = "[VMMGR] The flag is in another castle. Blocked.",
            .pattern = "flag",
            .length = 4,
            .is_string = true,
        },
    };

    for (size_t i = 0; i < VMMGR_ARRAY_LEN(detectors); ++i) {
        bool hit = false;
        if (detectors[i].is_string) {
            hit = vmmgr_contains_string(buffer, (const char *)detectors[i].pattern);
        } else {
            hit = vmmgr_contains_pattern(buffer, detectors[i].pattern, detectors[i].length);
        }

        if (hit) {
            vmmgr_handle_bait_detection(detectors[i].description, buffer, detectors[i].message);
            return false;
        }
    }

    return true;
}

/**
 * Emits a gentle warning if the payload contains null bytes. These often foil
 * string-based loaders, and the harness prefers to alert the operator rather
 * than enforce a restriction.
 *
 * @param contains_nulls Whether the original payload included a null byte.
 */
static void vmmgr_warn_about_nulls(bool contains_nulls) {
    if (contains_nulls) {
        fprintf(stderr, "[tiny_vmmgr] Caution: payload contains null bytes. Hope your loader likes NULs.\n");
    }
}

/**
 * Executes the validated shellcode by allocating RWX memory, copying the
 * payload, and performing a function pointer jump. Relies on MAP_ANONYMOUS
 * allocations and ensures the pointer is properly aligned.
 *
 * @param buffer Shellcode buffer.
 */
static void vmmgr_execute_shellcode(const struct shellcode_buffer *buffer) {
    if (!buffer || !buffer->data || buffer->length == 0) {
        fprintf(stderr, "[tiny_vmmgr] No shellcode to execute. Perhaps try writing some first.\n");
        exit(VMMGR_EXIT_FAILURE);
    }

    const bool contains_nulls = vmmgr_contains_null_byte(buffer);

    void *region = mmap(NULL,
                        VMMGR_PAGE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);
    if (region == MAP_FAILED) {
        perror("[tiny_vmmgr] mmap");
        exit(VMMGR_EXIT_FAILURE);
    }

    memcpy(region, buffer->data, buffer->length);
    vmmgr_secure_zero(buffer->data, buffer->length);
    free(buffer->data);

    if (mprotect(region, VMMGR_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("[tiny_vmmgr] mprotect");
        munmap(region, VMMGR_PAGE_SIZE);
        exit(VMMGR_EXIT_FAILURE);
    }

    vmmgr_warn_about_nulls(contains_nulls);

    void (*shellcode_entry)(void) = (void (*)(void))region;
    shellcode_entry();

    munmap(region, VMMGR_PAGE_SIZE);
}

/* ---------------------------------------------------------------------------
 *  MAIN ENTRY POINT
 * ---------------------------------------------------------------------------
 */

int main(int argc, char *argv[]) {
    vmmgr_print_banner();
    FILE *input = vmmgr_open_input_stream(argc, argv);
    struct shellcode_buffer buffer = vmmgr_read_shellcode(input);

    if (buffer.length == 0) {
        fprintf(stderr, "[tiny_vmmgr] Empty payload provided. Even no-ops deserve a byte.\n");
        free(buffer.data);
        return VMMGR_EXIT_FAILURE;
    }

    if (!vmmgr_inspect_shellcode(&buffer)) {
        return VMMGR_EXIT_FAILURE;
    }

    vmmgr_execute_shellcode(&buffer);
    return VMMGR_EXIT_SUCCESS;
}
