/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Sanitizer report parser
 *
 * @defgroup tapi_sanitizer Sanitizer reports (tapi_sanitizer)
 * @ingroup tapi_fuzz
 * @{
 *
 * Turning what a sanitizer printed into something a test can act on.
 *
 * The part that matters is the **signature**: the kind of error and the
 * names of the top frames, with addresses, offsets and the sanitizer's
 * own frames left out. Two runs of the same defect produce the same
 * signature, and a different defect produces a different one. That is
 * what makes it usable as the subject of a finding and as an entry in
 * @c conf/trc.xml - a crash that is known stays known while it is being
 * fixed, and a new one stands out on the run that introduces it.
 *
 * A Rust panic is parsed too. It is the same kind of evidence, it comes
 * out of the same fuzzing run, and a test should not have to care which
 * language produced the crash it is looking at.
 */

#ifndef __TSF_TAPI_SANITIZER_H__
#define __TSF_TAPI_SANITIZER_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Who reported the error. */
typedef enum tapi_sanitizer_kind {
    /** Nothing was recognised. */
    TAPI_SANITIZER_NONE = 0,
    /** AddressSanitizer: memory errors. */
    TAPI_SANITIZER_ASAN,
    /** UndefinedBehaviorSanitizer. */
    TAPI_SANITIZER_UBSAN,
    /** ThreadSanitizer: data races. */
    TAPI_SANITIZER_TSAN,
    /** LeakSanitizer. */
    TAPI_SANITIZER_LSAN,
    /** MemorySanitizer: uninitialized memory. */
    TAPI_SANITIZER_MSAN,
    /** A Rust panic. */
    TAPI_SANITIZER_RUST_PANIC,
    /** The process died on a signal and said nothing. */
    TAPI_SANITIZER_SIGNAL,
} tapi_sanitizer_kind;

/** One frame of a reported stack. */
typedef struct tapi_sanitizer_frame {
    /** Function name, or @c NULL when the frame had none. */
    char *function;
    /** Source location or module, or @c NULL. */
    char *location;
} tapi_sanitizer_frame;

/** What a sanitizer said. */
typedef struct tapi_sanitizer_report {
    /** Who reported it. */
    tapi_sanitizer_kind kind;
    /** The error itself, e.g. @c "heap-use-after-free". */
    char *error;
    /** Number of frames. */
    size_t n_frames;
    /** Frames, innermost first, without the sanitizer's own. */
    tapi_sanitizer_frame *frames;
    /**
     * Stable identity of the defect: the kind, the error and the names
     * of the top frames. Free of addresses and offsets, so it is the
     * same on every run and on every machine.
     */
    char *signature;
} tapi_sanitizer_report;

/**
 * Read a sanitizer report out of whatever a crashing process printed.
 *
 * @param[in]  text     Output of the process, usually its stderr.
 * @param[out] report   What was found; release it with
 *                      tapi_sanitizer_report_free().
 *
 * @return @c true if anything was recognised. When nothing was,
 *         @p report is still initialized, with kind
 *         @ref TAPI_SANITIZER_NONE.
 */
extern bool tapi_sanitizer_parse(const char *text,
                                 tapi_sanitizer_report *report);

/**
 * Build the signature of a report that has none, from a fallback name.
 *
 * Used when a crash could not be reproduced and there is nothing to
 * parse: the name of the artifact a fuzzer wrote is derived from its
 * contents, so it identifies the input even though it says nothing
 * about the defect.
 *
 * @param[in,out] report    Report.
 * @param[in]     fallback  Name to build the signature from.
 */
extern void tapi_sanitizer_signature_fallback(tapi_sanitizer_report *report,
                                              const char *fallback);

/**
 * Write a report into the log.
 *
 * @param report        Report.
 */
extern void tapi_sanitizer_report_log(const tapi_sanitizer_report *report);

/**
 * Release a report.
 *
 * @param report        Report.
 */
extern void tapi_sanitizer_report_free(tapi_sanitizer_report *report);

/**
 * Spell out who reported an error.
 *
 * @param kind          Kind.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_sanitizer_kind2str(tapi_sanitizer_kind kind);

/**
 * How much a defect of this kind matters.
 *
 * Memory corruption is worse than a leak, and a leak is worse than a
 * panic that the program was entitled to.
 *
 * @param kind          Kind.
 * @param error         The error text (may be @c NULL).
 *
 * @return A severity.
 */
extern tapi_cybersec_severity tapi_sanitizer_severity(
                                tapi_sanitizer_kind kind, const char *error);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SANITIZER_H__ */

/**@} <!-- END tapi_sanitizer --> */
