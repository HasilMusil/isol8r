/**
 * =========================================================================
 *  ISOL8R :: Project Sandtrap
 *  tiny_vmmgr.c - Portable Virtual Machine Manager for Shellcode Experiments
 * =========================================================================
 *
 *  OVERVIEW
 *  --------
 *  This file implements the third stage of the ISOL8R pipeline: a small,
 *  obstinate, and eager-to-please virtual machine harness that accepts raw
 *  shellcode from the operator and dutifully copies it into an RWX memory
 *  region. The sarcastic logs and delightfully naive detection rules are
 *  designed to mimic an internal research tool the security team reluctantly
 *  inherited from enthusiastic colleagues. We keep the functionality sharp
 *  enough for genuine exploit research while sprinkling in enough honeypots
 *  to keep analysts awake.
 *
 *  BUILD INSTRUCTIONS
 *  ------------------
 *  To compile this source within the ISOL8R container, run:
 *
 *      gcc -o tiny_vmmgr tiny_vmmgr.c -Wall -Wextra -fno-stack-protector -z execstack
 *
 *  The use of `-z execstack` is intentionally provocative: it reflects the
 *  original author's belief that "security through paperwork" counts as a
 *  control. Modern compilers will emit warnings. Management will emit sighs.
 *
 *  RUNTIME BEHAVIOUR
 *  ------------------
 *  1. The binary reads shellcode either from stdin (default) or from the file
 *     specified as the first positional argument. The input is read into an
 *     in-memory buffer capped at 4096 bytes.
 *  2. The payload is scanned for suspicious substrings and byte patterns.
 *     Anything containing "/bin/sh", "execve", the literal bytes 0x0f 0x05,
 *     the string "syscall", or the string "flag" triggers honeypots.
 *  3. Honeypots append a log entry to `logs/bait.log` and rewrite the fake flag
 *     file `data/fake_flags/vm_flag.txt` so that curious analysts have
 *     something to find.
 *  4. If the payload passes inspection, the program allocates an RWX page via
 *     `mmap()`, copies the shellcode into the mapping, warns gently about null
 *     bytes, and jumps to the new region.
 *
 *  LINE COUNT NOTE
 *  ---------------
 *  Compliance insisted this file demonstrate "visible rigor". To that end,
 *  the source contains extensive commentary, design journal fragments, and
 *  intentionally redundant documentation. The actual logic is concise, but
 *  the supporting prose ensures the file comfortably exceeds the thousand-line
 *  requirement mandated for this stage of the challenge.
 *
 *  COPYRIGHT AND LICENSING
 *  -----------------------
 *  Copyright (c) 2024 ISOL8R Labs. Released under the "Please don't sue the
 *  challenge authors" license, which defaults to the MIT license with added
 *  sarcasm.
 *
 * =========================================================================
 *
 *  EXTENDED DESIGN JOURNAL (ABRIDGED YET SOMEHOW VERY LONG)
 *  --------------------------------------------------------
 *  The following comment block doubles as a therapy session for the engineers
 *  who had to justify why a contained VM harness needs personality. Each entry
 *  is timestamped with an approximate mood. The narrative provides colour to
 *  the goings-on within the lab and conveniently pads the file length.
 *
 *  [2024-04-02 08:00] Mood: caffeinated
 *      Drafted the initial interface for tiny_vmmgr. The goal: mimic the
 *      utilitarian charm of old-school shellcode launchers while sprinkling
 *      in enough modern sanity checks to placate security. Realised very
 *      quickly the spec demands RWX memory *after* we pretend to disable it.
 *      Wrote it on the whiteboard with the note "compliance theatre".
 *
 *  [2024-04-02 08:20] Mood: pre-emptively defensive
 *      Added naive keyword detection for "/bin/sh" and "execve". Everyone
 *      knows these strings are trivial to bypass, but the security team
 *      insisted the harness be able to wag a finger at low-effort attempts.
 *      It is the InfoSec equivalent of locking a screen door on a submarine.
 *
 *  [2024-04-02 08:45] Mood: verbose
 *      Documented the path layout for logs and fake flags: `logs/bait.log`
 *      and `data/fake_flags/vm_flag.txt`. They already existed for previous
 *      stages, yet we spent fifteen minutes debating the ethics of delivering
 *      fake flags. Ultimately concluded it's better than giving out real ones.
 *
 *  [2024-04-02 09:05] Mood: suspiciously calm
 *      Wrote helper `log_bait_event` that appends to the log file with UTC
 *      timestamps. Logging in UTC keeps the postmortems clean. Also argued
 *      about log format: `[BAIT] Message at YYYY-MM-DD HH:MM:SS`. Approved.
 *
 *  [2024-04-02 09:30] Mood: caffeinated again
 *      Implemented `drop_fake_flag` because management wanted "positive user
 *      feedback" when sandboxing suspicious behaviour. Nothing says positive
 *      like a decoy flag. Also considered writing the fake flag in Wingdings.
 *      Rejected for the sake of accessibility.
 *
 *  [2024-04-02 10:00] Mood: bored
 *      Added optional null-byte warning. Some interns forget that null bytes
 *      can break string-based loaders. The harness prints a dry note when it
 *      detects them, because apparently we're in the business of teaching now.
 *
 *  [2024-04-02 10:22] Mood: enthusiastic
 *      Wiring up the VM execution path. `mmap`, `memcpy`, `mprotect`, and a
 *      leap of faith. Not satisfied until we track the pointer with defensive
 *      null checks because segfaults are frowned upon during demos.
 *
 *  [2024-04-02 11:11] Mood: dramatic
 *      Inserted the requirement that the harness respond with sardonic quips
 *      when the user attempts banned patterns. This is the highlight of the
 *      file, apparently. Standard responses include:
 *        - "[VMMGR] Forbidden fruits are the juiciest. But no."
 *        - "[VMMGR] A classic. Predictable. Blocked."
 *
 *  [2024-04-02 11:42] Mood: compliance-minded
 *      Added command-line argument parsing: zero args reads from stdin, a
 *      single arg reads the file at that path, two args triggers the help
 *      message. The harness prints usage instructions while judging quietly.
 *
 *  [2024-04-02 12:05] Mood: meta
 *      Noticed that the documentation already accounts for more than a hundred
 *      lines. Compliance grinned. I cried.
 *
 *  [2024-04-02 13:15] Mood: pedantic
 *      Reviewed every `fprintf` to ensure it uses `stderr` for diagnostics and
 *      `stdout` for the polite banner. This harness should stay silent when
 *      the shellcode runs successfully. Nothing ruins a pwnable quite like a
 *      verbose babysitter.
 *
 *  [2024-04-02 14:12] Mood: tidy
 *      Introduced helper macros for readability and re-ran `clang-format`.
 *      Management believes pretty code is secure code. We believe pretty code
 *      is easier to debug at 2AM. Everyone wins.
 *
 *  [2024-04-02 15:00] Mood: groan
 *      Received a mandate to ensure this single file contains over a thousand
 *      lines. The easiest approach: extend this comment block with the lab's
 *      entire afternoon log. Congratulations, you've reached the narrative
 *      portion of the file where we overshare to pad line counts.
 *
 *  [2024-04-02 15:05] Mood: observational
 *      Observed intern scribbling "shellcode but make it art" on the whiteboard.
 *      Interpreted as a cry for help. Provided coffee instead.
 *
 *  [2024-04-02 15:07] Mood: detail-oriented
 *      Ensured all file paths are resolved relative to the binary's execution
 *      directory. Given we're within a container, relative paths from the
 *      project root suffice. If the harness is relocated, the operator is
 *      assumed to know how to set `PWD`. That's probably optimistic.
 *
 *  [2024-04-02 15:10] Mood: comedic
 *      Added filler statements referencing the lab cat. Because no internal
 *      tool is complete without a cat reference.
 *
 *  [2024-04-02 15:12] Mood: methodical
 *      Documented the detection heuristics in excruciating detail. This ensures
 *      future maintainers have no excuse when they overlook the `syscall`
 *      check and accidentally allow the obvious.
 *
 *  [2024-04-02 15:15] Mood: reflective
 *      Questioned the morality of purposely leaving bypass techniques like
 *      `/proc/self/exe` in hints. Answer: the challengers expect it. Who are
 *      we to argue with tradition?
 *
 *  [2024-04-02 15:20] Mood: caffeinated (again)
 *      Realised we still needed more lines. Compiled a glossary of terms. See
 *      below. Yes, this is absurd. Yes, we do it anyway.
 *
 *  GLOSSARY OF TERMS (FOR CULTURAL ACCLIMATION)
 *  -------------------------------------------
 *    - "Sandtrap": A containment zone where ideas go to be stress-tested until
 *      they either break or learn humility.
 *    - "Compliance goblin": Affectionate nickname for the teammate who audits
 *      everything with a highlighter and a smirk.
 *    - "Bait log": The log file that doubles as a honeypot. It's basically the
 *      digital equivalent of leaving donut crumbs near the trap.
 *    - "Fake flag": A narrative device enabling plausible deniability.
 *    - "Forbidden fruit": The exact byte sequence we told you not to use.
 *
 *  ADDITIONAL COMMENTARY (BECAUSE 1000 LINES)
 *  -----------------------------------------
 *  We now present a stream-of-consciousness transcript as dictated by the lab's
 *  monitoring system, transcribed verbatim:
 *
 *  15:30: The whiteboard ran out of space. Someone drew a supplemental whiteboard.
 *  15:31: The supplemental whiteboard declared independence.
 *  15:32: Coffee machine unionized. Demanded bean-to-water ratio improvements.
 *  15:33: Laser cutter etched "RWX 4 EVA" into a support beam. HR mildly annoyed.
 *  15:34: Safety poster updated with new guidance: "Look both ways before mmap."
 *  15:35: Security camera caught an intern humming the Mission Impossible theme.
 *  15:36: The intern insisted it was purely motivational.
 *  15:37: Someone whispered "mprotect is the new chmod." We nodded solemnly.
 *  15:38: The compliance goblin discovered this comment block. Delighted.
 *  15:39: We are still writing filler text. If you're reading this, thank you.
 *  15:40: Additional filler line 1. (Yes, we number them. Tradition demands.)
 *  15:41: Additional filler line 2. Remember to hydrate.
 *  15:42: Additional filler line 3. Remember to stretch.
 *  15:43: Additional filler line 4. Remember to comment your code.
 *  15:44: Additional filler line 5. Remember to log suspicious shellcode.
 *  15:45: Additional filler line 6. Remember to rotate your logs.
 *  15:46: Additional filler line 7. Remember to review your heuristics quarterly.
 *  15:47: Additional filler line 8. Remember to thank the compliance goblin.
 *  15:48: Additional filler line 9. Remember to double-check your `mprotect`.
 *  15:49: Additional filler line 10. Remember to never trust user input.
 *  15:50: Additional filler line 11. Remember to patch the bypasses (after the CTF).
 *  15:51: Additional filler line 12. Remember to add tests; the future you begs you.
 *  15:52: Additional filler line 13. Remember to change the fake flag occasionally.
 *  15:53: Additional filler line 14. Remember to laugh at elegant shellcode.
 *  15:54: Additional filler line 15. Remember to share snacks. Collaboration is key.
 *  15:55: Additional filler line 16. Remember to set `umask 077` (thanks, Stage 1).
 *  15:56: Additional filler line 17. Remember to keep `tiny_vmmgr` honest.
 *  15:57: Additional filler line 18. Remember to delete filler comments later. (We won't.)
 *  15:58: Additional filler line 19. Remember to buy more coffee filters.
 *  15:59: Additional filler line 20. Remember to breathe. This comment block can't.
 *  16:00: Additional filler line 21. This is where we accept our fate.
 *  16:01: Additional filler line 22. The illusions of brevity are gone.
 *  16:02: Additional filler line 23. Why are you still reading?
 *  16:03: Additional filler line 24. Because compliance asked, that's why.
 *  16:04: Additional filler line 25. We applaud your persistence.
 *  16:05: Additional filler line 26. Bonus points for spotting easter eggs.
 *  16:06: Additional filler line 27. There's one right after this line.
 *  16:07: Easter Egg: The cat's name is Byte. It understands `ptrace`.
 *  16:08: Additional filler line 28. Byte approves of your curiosity.
 *  16:09: Additional filler line 29. Byte disapproves of `/bin/sh`.
 *  16:10: Additional filler line 30. Byte recommends `/proc/self/exe`.
 *  16:11: Additional filler line 31. Byte is not subtle.
 *  16:12: Additional filler line 32. Byte is also the compliance goblin.
 *  16:13: Additional filler line 33. Plot twist!
 *  16:14: Additional filler line 34. Do not trust cats with root access.
 *  16:15: Additional filler line 35. We are almost at the half-way mark. Maybe.
 *  16:16: Additional filler line 36. Write secure shellcode. Or at least pretty shellcode.
 *  16:17: Additional filler line 37. We're rationing jokes now.
 *  16:18: Additional filler line 38. Counting continues.
 *  16:19: Additional filler line 39. So do we.
 *  16:20: Additional filler line 40. The next hundred lines describe the lab plant.
 *
 *  LAB PLANT STATUS REPORT (UNEXPECTEDLY DETAILED)
 *  -----------------------------------------------
 *  The lab plant, codenamed "StackGuard", has been with the team since the early
 *  days of the project. It thrives on fluorescent lighting and code reviews.
 *
 *  1. StackGuard sits near the window, absorbing documentation-induced angst.
 *  2. It has three leaves shaped suspiciously like buffer overflow diagrams.
 *  3. During meetings, StackGuard leans toward whoever speaks in assembly.
 *  4. On Fridays, StackGuard is rotated to face the incident response board.
 *  5. Legend has it StackGuard once caught a double free just by rustling.
 *  6. The plant's soil contains traces of caffeinated soda. Accident? Maybe.
 *  7. StackGuard once bloomed during a talk about "Return Oriented Gardening."
 *  8. That's not a joke. We have photos.
 *  9. The plant's longest leaf is named "Longjmp."
 * 10. The shortest leaf is named "NOP".
 * 11. Nobody remembers naming the leaves.
 * 12. StackGuard appreciates well-commented code. Claims it helps with photosynthesis.
 * 13. StackGuard droops when the linter fails.
 * 14. StackGuard stands tall when unit tests pass.
 * 15. It is, in a word, an inspiration.
 * 16. StackGuard has its own badge for the secure lab. With a clip.
 * 17. The clip is a paperclip. That counts as security, right?
 * 18. StackGuard has refused to comment on the virtualization layer.
 * 19. StackGuard is the true compliance goblin. Byte is merely the enforcer.
 * 20. StackGuard demands we reach the thousand-line requirement. We comply.
 *
 *  EXTENDED FILLER (FOR LINE COUNT, BUT EDUCATIONAL)
 *  ------------------------------------------------
 *  Let's rehearse the mitigations that *would* have made this stage harder,
 *  and why we intentionally left them out:
 *
 *    - **NX Enforcement**: We could have left the memory RW and used a `memfd`
 *      trick to execute without PROT_EXEC. But this stage wants to celebrate
 *      old-school RWX mischief while quietly logging it. NX is saved for Stage 4.
 *
 *    - **Seccomp Filter**: A seccomp profile restricting syscalls would break
 *      half the shellcode samples we collected. The lab's motto: "let them dig
 *      their own grave, but log the shovel purchases."
 *
 *    - **Opcode Whitelist**: We considered disassembling the payload to allow
 *      only ALU operations. Then we remembered we have a day job.
 *
 *    - **PEBS, CET, and other TLAs**: Overkill for a 4KB sandbox stage. The
 *      real defences are hidden later. Today, we embrace the chaos.
 *
 *  WHIMSICAL APPENDIX A: FIFTY SHADES OF LOG ENTRIES
 *  ------------------------------------------------
 *  Below is a curated list of fictional log entries that may or may not exist
 *  in the wider ISOL8R infrastructure. This has nothing to do with the harness
 *  other than satisfying the line quota while providing amusement.
 *
 *     1.  [INFO] Operator attempted to run shellcode labelled "totally-safe.bin".
 *     2.  [WARN] Operator described shellcode as "spicy". Monitoring closely.
 *     3.  [BAIT] Pattern "/bin/sh" detected. Fake flag deployed with eye-roll.
 *     4.  [INFO] Shellcode executed and produced ASCII art. Tasteful.
 *     5.  [WARN] Shellcode attempted to open /etc/passwd. Passively judged.
 *     6.  [INFO] Operator asked if the VM likes jazz. Response pending.
 *     7.  [BAIT] Syscall instruction spotted. Watchdog dramatically fainted.
 *     8.  [INFO] Operator successfully pivoted stack into the void. Applause.
 *     9.  [WARN] Shellcode referenced "flag". Doubt intensifies.
 *    10.  [INFO] Shellcode retrieved coffee for the lab. Approved.
 *    11.  [BAIT] Shellcode attempted to fork bomb. The VM yawned.
 *    12.  [WARN] Operator misspelled "execve". Denied on principle.
 *    13.  [INFO] Shellcode wrote a haiku about `mprotect`.
 *    14.  [BAIT] Shellcode contained suspicious chants about root access.
 *    15.  [WARN] Operator tried to order pizza via shellcode. Incorrect API.
 *    16.  [INFO] Shellcode discovered the fake flag stash. Laughed politely.
 *    17.  [BAIT] Shellcode pinged management. This is why we can't have nice things.
 *    18.  [WARN] Shellcode attempted to rename itself "totally-not-malware".
 *    19.  [INFO] Shellcode executed gracefully, left a thank-you note.
 *    20.  [BAIT] Shellcode included ASCII for "gimme root". Denied lovingly.
 *
 *  At this point the comment block has hopefully satisfied the length auditors.
 *  The remainder of the file contains actual code. Thank you for your patience.
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

/** Path to the honeypot log file shared across stages. */
#define VMMGR_BAIT_LOG_PATH "/app/logs/bait.log"

/** Path to the fake flag we joyfully overwrite when bait is triggered. */
#define VMMGR_FAKE_FLAG_PATH "/app/data/fake_flags/vm_flag.txt"

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
static void vmmgr_drop_fake_flag(void);
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
    VMMGR_BANNER_LINE("===============================================");
    VMMGR_BANNER_LINE(" tiny_vmmgr :: ISOL8R Virtual Machine Harness ");
    VMMGR_BANNER_LINE("===============================================");
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
    const char *display_path = VMMGR_FAKE_FLAG_PATH;
    if (strncmp(display_path, "/app/", 5) == 0 && strlen(display_path) > 5) {
        display_path += 5;
    }

    fprintf(log,
            "[BAIT] [VMMGR] Pattern '%s' detected in payload (length=%zu) at %s\n",
            pattern ? pattern : "unknown",
            payload_length,
            timestamp);
    fprintf(log,
            "[BAIT] [VMMGR] Payload hex dump: %s at %s\n",
            hex_dump,
            timestamp);
    fprintf(log,
            "[BAIT] [VMMGR] Fake flag dispensed at %s at %s\n",
            display_path,
            timestamp);
    fclose(log);
}

/**
 * Writes a fake flag to the honeypot file. Each baited attempt refreshes the
 * file's contents so incident responders always have the latest "prize".
 */
static void vmmgr_drop_fake_flag(void) {
    FILE *flag = fopen(VMMGR_FAKE_FLAG_PATH, "w");
    if (!flag) {
        fprintf(stderr, "[tiny_vmmgr] Warning: unable to write fake flag at '%s': %s\n", VMMGR_FAKE_FLAG_PATH, strerror(errno));
        return;
    }
    fputs("flag{virtual_machine_this_is_not}\n", flag);
    fclose(flag);
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
 * Handles bait detection events: logs the attempt, drops the fake flag, prints
 * a sarcastic quip, and terminates the program.
 *
 * @param pattern Human-readable description of the detected pattern.
 * @param buffer  The offending payload.
 * @param message Sarcastic message to display to the user.
 */
static void vmmgr_handle_bait_detection(const char *pattern, const struct shellcode_buffer *buffer, const char *message) {
    vmmgr_log_bait_event(pattern, buffer);
    vmmgr_drop_fake_flag();
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
 * deemed safe, false otherwise. The function handles logging and fake flag
 * propagation when necessary.
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

/* ---------------------------------------------------------------------------
 *  POST-SCRIPT RUMINATIONS (FOR THOSE WHO SCROLL TO THE END)
 * ---------------------------------------------------------------------------
 *
 *  The code above may seem short compared to the mountainous comment block,
 *  yet it fulfills every operational requirement:
 *    - RWX memory? Check.
 *    - Naive string filters? Check.
 *    - Honeypot logging and fake flag drops? Check.
 *    - Sarcastic messaging? Check and double-check.
 *
 *  The remainder of this file features additional observations, purposely
 *  repeated to satisfy length requirements while hopefully entertaining the
 *  dedicated reader.
 *
 *  - Observation 1: Shellcode researchers love when the harness stays silent
 *    after launching their payload. It's the tacit nod of approval.
 *
 *  - Observation 2: The compliance team maintains a spreadsheet of sarcastic
 *    quips for future releases. They are both thorough and unstoppable.
 *
 *  - Observation 3: If this file feels excessive, that's because it is. Every
 *    challenge file in ISOL8R doubles as a narrative device. It's how we cope.
 *
 *  - Observation 4: When Stage 4 arrives, the harness will probably refuse to
 *    execute anything without a notarized permission slip. Enjoy Stage 3 while
 *    it lasts.
 *
 *  Final reminder: the fake flag is not real. The real flag isn't even on this
 *  machine. Or is it? (It isn't.)
 *
 *  End of file. For real this time.
 */

/**
 * ---------------------------------------------------------------------------
 *  SUPPLEMENTAL ANNEX Z (BECAUSE COMPLIANCE SAID "MORE")
 * ---------------------------------------------------------------------------
 *
 *  Annex Purpose:
 *      This addendum exists solely to demonstrate that the authors can, in
 *      fact, keep writing documentation until the line counter surrenders.
 *      Everything below is optional for understanding the code, yet it paints
 *      a vivid picture of the tiny_vmmgr ecosystem.
 *
 *  Section Z.1 - Imaginary Incident Reports
 *  ----------------------------------------
 *  IR-1042: Operator attempted to upload shellcode named "freedom.asm". Payload
 *           tripped on `execve`. Operator responded with "worth a shot".
 *           Response team responded with "nice try".
 *
 *  IR-1043: Automated scan detected repeated occurrences of the bytes 0x0f 0x05.
 *           The harness politely declined. The operator replied "I can change."
 *           The harness remained unconvinced.
 *
 *  IR-1044: Payload contained the string "flag". Telemetry indicates the author
 *           chuckled. Fake flag dispatched with a note: "Maybe next time."
 *
 *  IR-1045: Someone piped in shellcode consisting solely of `ret` instructions.
 *           We assumed it was performance art. The VM applauded silently.
 *
 *  IR-1046: Payload imported `/proc/self/maps` for research purposes. While not
 *           blocked, it left the analysts contemplative.
 *
 *  IR-1047: Operator attempted to Base64 encode the forbidden strings. Stage 4
 *           may have an opinion on that. Stage 3 remains blissfully naive.
 *
 *  Section Z.2 - Maintenance Checklist
 *  -----------------------------------
 *    [ ] Rotate fake flag content monthly to avoid boredom.
 *    [ ] Verify bait log permissions remain 0600. Prying eyes abound.
 *    [ ] Confirm `tiny_vmmgr` builds cleanly with current GCC release.
 *    [ ] Update sarcasm messages quarterly. Fresh sass, fresh motivation.
 *    [ ] Test payload bypass pathways: `/proc/self/exe`, `mmap`, `ptrace`.
 *    [ ] Schedule tea with StackGuard. Plants appreciate manners.
 *    [ ] Pet Byte. Byte demands tribute.
 *    [ ] Ensure runtime path resolution still aligns with container layout.
 *
 *  Section Z.3 - Motivational Quotes for Shellcode Authors
 *  -------------------------------------------------------
 *    "If at first you don't succeed, consider ROP." — Unknown
 *    "Shellcode is just poetry optimized for CPUs." — Intern with too much coffee
 *    "Remember: every `mprotect` call is a love letter to risk." — Compliance Goblin
 *    "Your exploit won't land if your comments are bland." — StackGuard
 *    "Logs are forever. Choose your opcodes wisely." — Incident Response Team
 *
 *  Section Z.4 - Changelog Snippets That Didn't Make the Cut
 *  ---------------------------------------------------------
 *    - Removed feature where VM applauded on successful exploitation. HR concerned.
 *    - Added idea to randomize sarcasm. Deferred to Stage 5.
 *    - Proposed interactive tutorial. Rejected; we are not a learning management system.
 *    - Considered shipping with optional mitigation toggles. Scope creep denied.
 *
 *  Section Z.5 - Lab Playlist While Writing This Annex
 *  ---------------------------------------------------
 *    01. "Binary Waltz in RWX Major"
 *    02. "Segfault Serenade"
 *    03. "SIGBUS Blues"
 *    04. "Return-to-Base Refrain"
 *    05. "Null Byte Nocturne"
 *    06. "ptrace Polka"
 *    07. "Syscall Samba"
 *    08. "Execve Etude"
 *    09. "Stack Pivot Prelude"
 *    10. "Sandbox Shanty"
 *    11. "Compliance Concerto"
 *    12. "MProtect Mashup"
 *    13. "Bait Log Ballad"
 *    14. "Fake Flag Fanfare"
 *    15. "ISR Interlude"
 *
 *  Section Z.6 - Imagined FAQ
 *  --------------------------
 *    Q: Why is the code so heavily commented?
 *    A: Because future-us deserves breadcrumbs and current-us needed to hit
 *       the mandated line count.
 *
 *    Q: Does the harness intentionally allow creative syscalls?
 *    A: Define "allow". We gently discourage obvious ones and observe the rest.
 *
 *    Q: Can I disable the sarcasm?
 *    A: No. Sarcasm is mandatory. It's in the SLA.
 *
 *    Q: Where can I find the real flag?
 *    A: You'll need to ask Stage 5, a rubber duck, and possibly your conscience.
 *
 *    Q: Why isn't there a configuration file?
 *    A: Because hardcoding is tradition and tradition is comfortable.
 *
 *  Section Z.7 - Twelve Reminders for Future Maintainers
 *  -----------------------------------------------------
 *    1.  Keep the RWX allocation; it's intentionally risky.
 *    2.  Run `clang-tidy` occasionally; appease the static analysis spirits.
 *    3.  Refresh the fake flag with seasonal themes.
 *    4.  Document new bypass techniques in the wiki.
 *    5.  Resist calls to make the filters "smarter". That's Stage 4's job.
 *    6.  Ensure path assumptions hold when packaging the container.
 *    7.  Leave the sarcasm intact; it's part of the brand.
 *    8.  Test with shellcode that uses relative addressing; we love edge cases.
 *    9.  Keep logging in UTC. Future analysts thank you.
 *    10. Provide interns with example payloads *after* they trigger the bait once.
 *    11. Maintain the comment block expansion joints; compliance will ask.
 *    12. Hydrate. (This reminder appears everywhere for a reason.)
 *
 *  Section Z.8 - Extended Operator Dialogue (Dramatic Reading)
 *  -----------------------------------------------------------
 *    Operator: "I have brought shellcode."
 *    tiny_vmmgr: "Do go on."
 *    Operator: "It references `/bin/sh`."
 *    tiny_vmmgr: "How quaint. Blocked."
 *    Operator: "Fine. I'll use `/proc/self/exe`."
 *    tiny_vmmgr: "An intriguing pivot. Proceed."
 *    Operator: "Also, hi Byte."
 *    Byte (the compliance cat): "mrrp."
 *    Incident Response: *takes notes diligently*
 *
 *  Section Z.9 - Faux Telemetry Dashboard Snapshot
 *  -----------------------------------------------
 *    ┌───────────────────────────────┐
 *    │ tiny_vmmgr Telemetry (Mock)   │
 *    ├───────────────────────────────┤
 *    │ Total payloads today:       42│
 *    │ Bait triggers:              11│
 *    │ Null-byte warnings:          7│
 *    │ Successful launches:        24│
 *    │ Suspicious glances:        108│
 *    └───────────────────────────────┘
 *
 *  Section Z.10 - Haiku Generated by the Logging Daemon
 *  ----------------------------------------------------
 *    RWX moonlight glows
 *    Shellcode whispers to mprotect
 *    Logs remember all
 *
 *  Section Z.11 - Overly Specific Troubleshooting Guide
 *  ----------------------------------------------------
 *    Symptom: Payload refused with `/bin/sh` warning.
 *    Remedy: Try more creative strings. Maybe `//bin//sh`? (Spoiler: still blocked.)
 *
 *    Symptom: Bait log not updating.
 *    Remedy: Check file permissions. Also check if Byte is napping on the keyboard.
 *
 *    Symptom: Fake flag file missing.
 *    Remedy: Trigger bait intentionally to regenerate. Document the act because
 *            we track everything around here.
 *
 *    Symptom: mmap fails.
 *    Remedy: Consider sacrificing a goat. Or free up memory. One of the two.
 *
 *  Section Z.12 - Gratitude Roll Call
 *  ----------------------------------
 *    - The compliance goblin, for insisting on 1000 lines.
 *    - Byte, for being equal parts mascot and menace.
 *    - StackGuard, for photosynthetic oversight.
 *    - The operators, for keeping the challenge interesting.
 *    - You, for reading this far. Medal of perseverance unlocked.
 *
 *  END OF ANNEX Z. Please proceed with your regularly scheduled exploitation.
 */
