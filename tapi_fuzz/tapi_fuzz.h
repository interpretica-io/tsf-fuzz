/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Fuzzing campaign TAPI
 *
 * @defgroup tapi_fuzz Fuzzing (tapi_fuzz)
 * @{
 *
 * Running a fuzzer from a test, and turning what it finds into results.
 *
 * Every other security check in these repositories looks for a weakness
 * whose shape somebody wrote down first. A fuzzer does not: it is the
 * one thing here that finds defects nobody had thought of. What it
 * needs in exchange is somewhere to put the answer, and that is what
 * this is - a campaign with a beginning and an end, statistics that say
 * whether it did anything, crashes reduced to stable identities, and
 * reproducers saved next to the suite.
 *
 * The parts:
 *
 * - @ref tapi_fuzz - the campaign: run a fuzzer, read its statistics,
 *   and check that it actually fuzzed;
 * - @ref tapi_sanitizer - what a crashing process printed, reduced to
 *   an identity that is the same every time;
 * - @ref tapi_fuzz_crash - the artifacts a campaign left behind:
 *   reproduce, deduplicate, report, and keep as regression seeds.
 *
 * Four fuzzers are driven through one interface, because the shape of a
 * campaign is the same for all of them:
 *
 * | Kind | Runs | Needs |
 * |---|---|---|
 * | @ref TAPI_FUZZ_LIBFUZZER | the target itself | a target built with @c -fsanitize=fuzzer |
 * | @ref TAPI_FUZZ_CARGO | @c cargo @c fuzz @c run | a Rust @c fuzz_target, which is libFuzzer underneath |
 * | @ref TAPI_FUZZ_AFLPP | @c afl-fuzz | a target built with an @c afl-cc, or QEMU mode |
 * | @ref TAPI_FUZZ_HONGGFUZZ | @c honggfuzz | a target, instrumented or not |
 *
 * A campaign in a test:
 *
 * @code
 * tapi_fuzz_opt opt = tapi_fuzz_default_opt;
 * tapi_fuzz_app *app = NULL;
 * tapi_fuzz_stats stats;
 * te_vec crashes;
 *
 * opt.kind = TAPI_FUZZ_LIBFUZZER;
 * opt.target = "/opt/dut/fuzz_parser";
 * opt.corpus_dir = corpus;
 * opt.output_dir = artifacts;
 * opt.max_total_time = 300;
 *
 * CHECK_RC(tapi_fuzz_do(factory, &opt, 400000, &app));
 * CHECK_RC(tapi_fuzz_get_stats(app, &stats));
 * tapi_fuzz_stats_log(&stats);
 * CHECK_RC(tapi_fuzz_check_progress(&stats, 10000, 1, &report));
 *
 * CHECK_RC(tapi_fuzz_crashes_collect(factory, &opt, seeds_dir, 30000,
 *                                    &crashes));
 * CHECK_RC(tapi_fuzz_crashes_check(&crashes, &report));
 * @endcode
 *
 * @note The check that matters most is tapi_fuzz_check_progress(). A
 *       harness that dies on startup, or rejects every input it is
 *       given, produces no crashes - and a test that only looks for
 *       crashes calls that a pass. Assert that the campaign executed
 *       something and that coverage moved, or the whole thing is
 *       theatre.
 *
 * @note A campaign is not a unit test: it takes as long as it is told
 *       to. Give the group its own requirement so an ordinary run does
 *       not sit through it, and keep the corpus in the suite so that
 *       every run starts where the last one got to.
 */

#ifndef __TSF_TAPI_FUZZ_H__
#define __TSF_TAPI_FUZZ_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_devtool.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Which fuzzer to run. */
typedef enum tapi_fuzz_kind {
    /** The target is a libFuzzer binary and runs itself. */
    TAPI_FUZZ_LIBFUZZER = 0,
    /** @c cargo @c fuzz @c run against a Rust fuzz target. */
    TAPI_FUZZ_CARGO,
    /** @c afl-fuzz driving the target. */
    TAPI_FUZZ_AFLPP,
    /** @c honggfuzz driving the target. */
    TAPI_FUZZ_HONGGFUZZ,
} tapi_fuzz_kind;

/** How to run a campaign. */
typedef struct tapi_fuzz_opt {
    /** Which fuzzer. */
    tapi_fuzz_kind kind;
    /** The program that does the fuzzing; @c NULL for the kind's default. */
    const char *runner;
    /**
     * What is fuzzed: the path of the target binary, or, for
     * @ref TAPI_FUZZ_CARGO, the name of the fuzz target. Mandatory.
     */
    const char *target;
    /** Directory with the input corpus on the agent. Mandatory. */
    const char *corpus_dir;
    /**
     * Where the fuzzer writes. For libFuzzer and cargo-fuzz it is the
     * artifact directory; for AFL++ it is @c -o, with the crashes in a
     * subdirectory of it; for honggfuzz it is the workspace.
     * tapi_fuzz_crash_dir() knows the difference. Mandatory.
     */
    const char *output_dir;
    /** Dictionary file on the agent, or @c NULL. */
    const char *dict;

    /** Stop after this many seconds; @c 0 to run until stopped. */
    unsigned int max_total_time;
    /** Stop after this many inputs; @c 0 for no limit. */
    unsigned int runs;
    /** Largest input to generate, bytes; @c 0 for the fuzzer's default. */
    unsigned int max_len;
    /** Give up on one input after this many seconds; @c 0 for the default. */
    unsigned int timeout_s;
    /** Memory limit for one run, MiB; @c 0 for the fuzzer's default. */
    unsigned int rss_limit_mb;
    /** Parallel workers; @c 0 for one. */
    unsigned int workers;
    /** Random seed; @c 0 to let the fuzzer choose. */
    unsigned int seed;
    /** Look for leaks as well as crashes (libFuzzer and cargo-fuzz). */
    bool detect_leaks;

    /** Number of extra arguments. */
    size_t n_extra_args;
    /** Extra arguments, passed to the fuzzer as they are. */
    const char **extra_args;

    /** Working directory on the agent (@c NULL to keep the default one). */
    const char *workdir;
} tapi_fuzz_opt;

/** Default options: libFuzzer, leak detection on, no limits. */
extern const tapi_fuzz_opt tapi_fuzz_default_opt;

/** A running or finished campaign. */
typedef struct tapi_fuzz_app tapi_fuzz_app;

/** What a campaign did. */
typedef struct tapi_fuzz_stats {
    /** @c true if anything could be read at all. */
    bool valid;
    /** Inputs executed. */
    uint64_t execs;
    /** Inputs per second. */
    uint64_t execs_per_sec;
    /** Inputs kept in the corpus. */
    uint64_t corpus_size;
    /**
     * How much of the target the campaign reached. It is the fuzzer's
     * own number and the fuzzers do not agree on the unit - libFuzzer
     * counts covered edges, AFL++ reports the share of its bitmap in
     * per mille - so compare it with itself across runs, not with
     * another fuzzer.
     */
    uint64_t coverage;
    /** libFuzzer features, @c 0 for the others. */
    uint64_t features;
    /** Crashing inputs saved. */
    uint64_t crashes;
    /** Inputs that timed out or hung. */
    uint64_t timeouts;
} tapi_fuzz_stats;

/**
 * Create a campaign.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Options.
 * @param[out] app          Handle.
 *
 * @return Status code.
 * @retval TE_EINVAL        A mandatory option is missing.
 */
extern te_errno tapi_fuzz_create(tapi_job_factory_t *factory,
                                 const tapi_fuzz_opt *opt,
                                 tapi_fuzz_app **app);

/**
 * Start the campaign.
 *
 * @param app           Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_start(tapi_fuzz_app *app);

/**
 * Wait for the campaign to end on its own.
 *
 * A fuzzer that was given a time or a run limit ends by itself; one
 * that was not runs until tapi_fuzz_stop(). Its exit status is not
 * treated as the result: libFuzzer exits non-zero precisely when it
 * found something, which is a success for the test that asked for it.
 *
 * @param app           Handle.
 * @param timeout_ms    How long to wait, ms.
 *
 * @return Status code.
 * @retval TE_EINPROGRESS   It is still running.
 */
extern te_errno tapi_fuzz_wait(tapi_fuzz_app *app, int timeout_ms);

/**
 * Stop the campaign.
 *
 * @param app           Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_stop(tapi_fuzz_app *app);

/**
 * Get what the fuzzer printed.
 *
 * @param[in]  app      Handle.
 * @param[out] output   Output description; the strings belong to @p app.
 */
extern void tapi_fuzz_get_output(const tapi_fuzz_app *app,
                                 tapi_devtool_output *output);

/**
 * Destroy a handle. It must not be used afterwards.
 *
 * @param app           Handle (may be @c NULL).
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_destroy(tapi_fuzz_app *app);

/**
 * Create, start and wait for a campaign.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Options.
 * @param[in]  timeout_ms   How long to wait, ms. It must be longer than
 *                          tapi_fuzz_opt::max_total_time.
 * @param[out] app          Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_do(tapi_job_factory_t *factory,
                             const tapi_fuzz_opt *opt, int timeout_ms,
                             tapi_fuzz_app **app);

/**
 * Read the statistics of a campaign.
 *
 * libFuzzer and honggfuzz are read from what they printed; AFL++ keeps
 * a @c fuzzer_stats file, which is read from the agent.
 *
 * @param[in]  app      Handle, after the campaign has finished.
 * @param[out] stats    Statistics; tapi_fuzz_stats::valid says whether
 *                      anything could be read.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_get_stats(tapi_fuzz_app *app,
                                    tapi_fuzz_stats *stats);

/**
 * Write statistics into the log.
 *
 * @param stats         Statistics.
 */
extern void tapi_fuzz_stats_log(const tapi_fuzz_stats *stats);

/**
 * Check that the campaign did something.
 *
 * This is the check that keeps a fuzzing test honest. A harness that
 * fails to start, or that rejects every input before it reaches the
 * code, finds nothing - and looks exactly like a clean run.
 *
 * @param[in]     stats         Statistics.
 * @param[in]     min_execs     Fewest inputs a real campaign would have
 *                              executed; @c 0 to skip the check.
 * @param[in]     min_coverage  Lowest coverage a real campaign would
 *                              have reached; @c 0 to skip the check.
 * @param[in,out] report        Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_check_progress(const tapi_fuzz_stats *stats,
                                         uint64_t min_execs,
                                         uint64_t min_coverage,
                                         tapi_cybersec_report *report);

/**
 * Get the directory a fuzzer of this kind puts crashing inputs in.
 *
 * @param[in]  opt      Options of the campaign.
 * @param[out] dest     String to append the path to.
 */
extern void tapi_fuzz_crash_dir(const tapi_fuzz_opt *opt, te_string *dest);

/**
 * Spell out a fuzzer kind.
 *
 * @param kind          Kind.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_fuzz_kind2str(tapi_fuzz_kind kind);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_FUZZ_H__ */

/**@} <!-- END tapi_fuzz --> */
