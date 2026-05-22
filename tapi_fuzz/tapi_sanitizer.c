/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Sanitizer report parser
 *
 * Reading what a crashing process printed, and reducing it to an
 * identity that is the same every time the same defect happens.
 */

#define TE_LGR_USER "TAPI SANITIZER"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_sanitizer.h"

/** How many frames go into a signature. */
#define SAN_SIGNATURE_FRAMES    3

/** Frames that belong to the runtime rather than to the defect. */
static const char *const san_noise_prefixes[] = {
    "__asan",
    "__msan",
    "__tsan",
    "__ubsan",
    "__lsan",
    "__sanitizer",
    "__interceptor",
    "asan_",
    NULL,
};

/** Allocator frames, which every memory report has and none identifies. */
static const char *const san_noise_names[] = {
    "malloc",
    "calloc",
    "realloc",
    "free",
    "operator new",
    "operator new[]",
    "operator delete",
    "operator delete[]",
    NULL,
};

/** Is this frame the runtime talking about itself? */
static bool
san_frame_is_noise(const char *function)
{
    size_t i;

    if (function == NULL)
        return true;

    for (i = 0; san_noise_prefixes[i] != NULL; i++)
    {
        if (strncmp(function, san_noise_prefixes[i],
                    strlen(san_noise_prefixes[i])) == 0)
            return true;
    }

    for (i = 0; san_noise_names[i] != NULL; i++)
    {
        if (strcmp(function, san_noise_names[i]) == 0)
            return true;
    }

    return false;
}

/** Cut the trailing spaces off a string in place. */
static void
san_strip_trailing_space(char *text)
{
    size_t len = strlen(text);

    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                       text[len - 1] == '\r'))
        text[--len] = '\0';
}

/** Skip the spaces at the start of a line. */
static const char *
san_skip_spaces(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;

    return p;
}

/** Copy a run of characters, stopping at @p stop or at the end. */
static char *
san_dup_until(const char *start, const char *stop_chars)
{
    size_t len = strcspn(start, stop_chars);
    char *result = TE_ALLOC(len + 1);

    memcpy(result, start, len);
    result[len] = '\0';

    return result;
}

/** Drop the trailing "::h0123456789abcdef" a Rust symbol carries. */
static void
san_strip_rust_hash(char *function)
{
    size_t len = strlen(function);
    size_t i;

    if (len < 19 || strncmp(function + len - 19, "::h", 3) != 0)
        return;

    for (i = len - 16; i < len; i++)
    {
        if (!((function[i] >= '0' && function[i] <= '9') ||
              (function[i] >= 'a' && function[i] <= 'f')))
            return;
    }

    function[len - 19] = '\0';
}

/** Add a frame to the report being built. */
static void
san_add_frame(te_vec *frames, char *function, char *location)
{
    tapi_sanitizer_frame frame = { .function = function,
                                   .location = location };

    if (function != NULL)
        san_strip_rust_hash(function);

    TE_VEC_APPEND(frames, frame);
}

/**
 * Read a sanitizer stack frame.
 *
 * They look like @c "    #0 0x55e4 in parse_header /src/a.c:12:5" and,
 * when there are no symbols, like
 * @c "    #1 0x7f2a (/lib/libc.so.6+0x29d90)".
 */
static bool
san_parse_sanitizer_frame(const char *line, te_vec *frames)
{
    const char *p = san_skip_spaces(line);
    const char *in;

    if (*p != '#')
        return false;

    p++;
    if (*p < '0' || *p > '9')
        return false;

    while (*p >= '0' && *p <= '9')
        p++;

    p = san_skip_spaces(p);
    if (strncmp(p, "0x", 2) != 0)
        return false;

    in = strstr(p, " in ");
    if (in == NULL)
    {
        /* No symbols: keep the module, there is nothing else. */
        san_add_frame(frames, NULL, TE_STRDUP(san_skip_spaces(p)));
        return true;
    }

    p = san_skip_spaces(in + 4);
    san_add_frame(frames, san_dup_until(p, " "),
                  TE_STRDUP(san_skip_spaces(p + strcspn(p, " "))));

    return true;
}

/**
 * Read a Rust backtrace frame, which is a numbered line with the
 * symbol and, on the line after it, the source location.
 */
static bool
san_parse_rust_frame(const char *line, te_vec *frames)
{
    const char *p = san_skip_spaces(line);
    const char *colon;

    if (*p < '0' || *p > '9')
        return false;

    colon = strchr(p, ':');
    if (colon == NULL || colon[1] != ' ')
        return false;

    for (const char *d = p; d < colon; d++)
    {
        if (*d < '0' || *d > '9')
            return false;
    }

    san_add_frame(frames, TE_STRDUP(san_skip_spaces(colon + 1)), NULL);

    return true;
}

/** Attach a source location to the frame that was read last. */
static void
san_attach_location(te_vec *frames, const char *location)
{
    tapi_sanitizer_frame *frame;

    if (te_vec_size(frames) == 0)
        return;

    frame = te_vec_get(frames, te_vec_size(frames) - 1);
    if (frame->location == NULL)
        frame->location = TE_STRDUP(location);
}

/** Recognise the header line of a sanitizer report. */
static bool
san_parse_header(const char *line, tapi_sanitizer_report *report)
{
    static const struct {
        const char *marker;
        tapi_sanitizer_kind kind;
    } markers[] = {
        { "AddressSanitizer: ",          TAPI_SANITIZER_ASAN },
        { "LeakSanitizer: ",             TAPI_SANITIZER_LSAN },
        { "MemorySanitizer: ",           TAPI_SANITIZER_MSAN },
        { "ThreadSanitizer: ",           TAPI_SANITIZER_TSAN },
        { "UndefinedBehaviorSanitizer: ", TAPI_SANITIZER_UBSAN },
    };
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(markers); i++)
    {
        const char *found = strstr(line, markers[i].marker);

        if (found == NULL)
            continue;

        /* SUMMARY comes after the real header; do not overwrite it. */
        if (report->kind != TAPI_SANITIZER_NONE)
            return true;

        found += strlen(markers[i].marker);
        report->kind = markers[i].kind;
        report->error = san_dup_until(found, "(\n");

        /* "heap-use-after-free on address 0x..." - the address varies. */
        {
            char *on = strstr(report->error, " on ");

            if (on != NULL)
                *on = '\0';
        }
        san_strip_trailing_space(report->error);

        return true;
    }

    return false;
}

/** Recognise an UndefinedBehaviorSanitizer line, which has no banner. */
static bool
san_parse_ubsan(const char *line, tapi_sanitizer_report *report)
{
    const char *marker = strstr(line, ": runtime error: ");

    if (marker == NULL || report->kind != TAPI_SANITIZER_NONE)
        return false;

    report->kind = TAPI_SANITIZER_UBSAN;
    report->error = san_dup_until(marker + strlen(": runtime error: "), ":\n");
    san_strip_trailing_space(report->error);

    return true;
}

/** Recognise a Rust panic, old format and new. */
static bool
san_parse_rust_panic(const char *line, tapi_sanitizer_report *report)
{
    const char *marker = strstr(line, "panicked at ");

    if (marker == NULL || report->kind != TAPI_SANITIZER_NONE)
        return false;

    marker += strlen("panicked at ");
    report->kind = TAPI_SANITIZER_RUST_PANIC;

    if (*marker == '\'')
        report->error = san_dup_until(marker + 1, "'");
    else
        report->error = san_dup_until(marker, "\n");

    san_strip_trailing_space(report->error);

    return true;
}

/** Build the identity of a defect from what was parsed. */
static void
san_build_signature(tapi_sanitizer_report *report)
{
    te_string signature = TE_STRING_INIT;
    unsigned int used = 0;
    size_t i;

    te_string_append(&signature, "%s",
                     tapi_sanitizer_kind2str(report->kind));
    if (report->error != NULL)
        te_string_append(&signature, ":%s", report->error);

    for (i = 0; i < report->n_frames && used < SAN_SIGNATURE_FRAMES; i++)
    {
        if (san_frame_is_noise(report->frames[i].function))
            continue;

        te_string_append(&signature, ":%s", report->frames[i].function);
        used++;
    }

    report->signature = signature.ptr;
}

/* See description in tapi_sanitizer.h */
bool
tapi_sanitizer_parse(const char *text, tapi_sanitizer_report *report)
{
    te_vec frames = TE_VEC_INIT(tapi_sanitizer_frame);
    char *copy;
    char *line;
    char *saveptr = NULL;

    memset(report, 0, sizeof(*report));

    if (text == NULL)
    {
        san_build_signature(report);
        return false;
    }

    copy = TE_STRDUP(text);

    for (line = strtok_r(copy, "\n", &saveptr);
         line != NULL;
         line = strtok_r(NULL, "\n", &saveptr))
    {
        const char *stripped = san_skip_spaces(line);

        if (san_parse_header(line, report))
            continue;
        if (san_parse_ubsan(line, report))
            continue;
        if (san_parse_rust_panic(line, report))
            continue;

        if (san_parse_sanitizer_frame(line, &frames))
            continue;
        if (san_parse_rust_frame(line, &frames))
            continue;

        if (strncmp(stripped, "at ", 3) == 0)
            san_attach_location(&frames, san_skip_spaces(stripped + 3));
    }

    free(copy);

    report->n_frames = te_vec_size(&frames);
    if (report->n_frames != 0)
    {
        report->frames = TE_ALLOC(report->n_frames * sizeof(*report->frames));
        memcpy(report->frames, frames.data.ptr,
               report->n_frames * sizeof(*report->frames));
    }
    te_vec_free(&frames);

    san_build_signature(report);

    return report->kind != TAPI_SANITIZER_NONE;
}

/* See description in tapi_sanitizer.h */
void
tapi_sanitizer_signature_fallback(tapi_sanitizer_report *report,
                                  const char *fallback)
{
    te_string signature = TE_STRING_INIT;

    if (report->kind != TAPI_SANITIZER_NONE)
        return;

    te_string_append(&signature, "unknown:%s", fallback);
    free(report->signature);
    report->signature = signature.ptr;
}

/* See description in tapi_sanitizer.h */
void
tapi_sanitizer_report_log(const tapi_sanitizer_report *report)
{
    size_t i;

    RING("%s: %s", tapi_sanitizer_kind2str(report->kind),
         report->error != NULL ? report->error : "no error text");
    RING("  signature: %s", report->signature);

    for (i = 0; i < report->n_frames; i++)
    {
        RING("  #%zu %s %s", i,
             report->frames[i].function != NULL ?
                 report->frames[i].function : "?",
             report->frames[i].location != NULL ?
                 report->frames[i].location : "");
    }
}

/* See description in tapi_sanitizer.h */
void
tapi_sanitizer_report_free(tapi_sanitizer_report *report)
{
    size_t i;

    for (i = 0; i < report->n_frames; i++)
    {
        free(report->frames[i].function);
        free(report->frames[i].location);
    }

    free(report->frames);
    free(report->error);
    free(report->signature);

    memset(report, 0, sizeof(*report));
}

/* See description in tapi_sanitizer.h */
const char *
tapi_sanitizer_kind2str(tapi_sanitizer_kind kind)
{
    switch (kind)
    {
        case TAPI_SANITIZER_ASAN:
            return "asan";
        case TAPI_SANITIZER_UBSAN:
            return "ubsan";
        case TAPI_SANITIZER_TSAN:
            return "tsan";
        case TAPI_SANITIZER_LSAN:
            return "lsan";
        case TAPI_SANITIZER_MSAN:
            return "msan";
        case TAPI_SANITIZER_RUST_PANIC:
            return "panic";
        case TAPI_SANITIZER_SIGNAL:
            return "signal";
        default:
            return "unknown";
    }
}

/* See description in tapi_sanitizer.h */
tapi_cybersec_severity
tapi_sanitizer_severity(tapi_sanitizer_kind kind, const char *error)
{
    switch (kind)
    {
        case TAPI_SANITIZER_ASAN:
            /* Corruption an attacker can steer is worse than the rest. */
            if (error != NULL &&
                (strstr(error, "use-after-free") != NULL ||
                 strstr(error, "buffer-overflow") != NULL ||
                 strstr(error, "double-free") != NULL))
                return TAPI_CYBERSEC_SEV_CRITICAL;
            return TAPI_CYBERSEC_SEV_HIGH;

        case TAPI_SANITIZER_MSAN:
        case TAPI_SANITIZER_TSAN:
        case TAPI_SANITIZER_SIGNAL:
            return TAPI_CYBERSEC_SEV_HIGH;

        case TAPI_SANITIZER_UBSAN:
        case TAPI_SANITIZER_RUST_PANIC:
            /* Reachable from input, it is at least a denial of service. */
            return TAPI_CYBERSEC_SEV_MEDIUM;

        case TAPI_SANITIZER_LSAN:
            return TAPI_CYBERSEC_SEV_LOW;

        default:
            return TAPI_CYBERSEC_SEV_INFO;
    }
}
