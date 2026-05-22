/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Crash triage
 *
 * @defgroup tapi_fuzz_crash Crash triage (tapi_fuzz_crash)
 * @ingroup tapi_fuzz
 * @{
 *
 * What a campaign left behind, turned into results.
 *
 * A directory of crashing inputs is not a test result. Half of them are
 * the same defect reached by different paths, none of them says what
 * went wrong, and a week later nobody can tell which of them are fixed.
 * So each artifact is replayed against the target, the sanitizer report
 * is reduced to a signature, artifacts that share a signature are
 * counted as one, and the survivors are saved next to the suite.
 *
 * That last part is what makes fuzzing pay for itself twice:
 *
 * 1. the campaign finds a crash;
 * 2. tapi_fuzz_crashes_check() reports it with a verdict built from the
 *    signature, and it goes into @c conf/trc.xml as a known issue;
 * 3. the saved reproducer is committed into the suite's corpus with
 *    tapi_fuzz_seed_add(), so every later campaign starts by replaying
 *    it;
 * 4. when it is fixed, the TRC entry flips to @c PASSED and the seed
 *    guards the fix from then on.
 *
 * @note Listing a directory on an agent is done by running @c find,
 *       because RCF transfers files but does not enumerate them.
 */

#ifndef __TSF_TAPI_FUZZ_CRASH_H__
#define __TSF_TAPI_FUZZ_CRASH_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_fuzz.h"
#include "tapi_sanitizer.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One distinct defect a campaign found. */
typedef struct tapi_fuzz_crash {
    /** Path of the artifact on the agent. */
    char *artifact;
    /** Where the reproducer was saved on the engine, or @c NULL. */
    char *saved;
    /** How many artifacts turned out to be this same defect. */
    unsigned int count;
    /** What the target said when the artifact was replayed. */
    tapi_sanitizer_report report;
} tapi_fuzz_crash;

/**
 * Collect, replay and deduplicate what a campaign left behind.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Options of the campaign that produced them.
 * @param[in]  save_dir     Directory on the engine to save one
 *                          reproducer per distinct defect in, or
 *                          @c NULL to save none.
 * @param[in]  timeout_ms   How long one replay may take, ms.
 * @param[out] crashes      Vector of #tapi_fuzz_crash, initialized by
 *                          the call; release it with
 *                          tapi_fuzz_crashes_free().
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_crashes_collect(tapi_job_factory_t *factory,
                                          const tapi_fuzz_opt *opt,
                                          const char *save_dir,
                                          int timeout_ms,
                                          te_vec *crashes);

/**
 * Report every distinct defect as a finding.
 *
 * The subject of a finding is the signature, so the verdict a test
 * emits is the same on every run that reproduces the same defect.
 *
 * @param[in]     crashes  Vector filled by tapi_fuzz_crashes_collect().
 * @param[in,out] report   Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_crashes_check(const te_vec *crashes,
                                        tapi_cybersec_report *report);

/**
 * Write what was found into the log.
 *
 * @param crashes       Vector filled by tapi_fuzz_crashes_collect().
 */
extern void tapi_fuzz_crashes_log(const te_vec *crashes);

/**
 * Release collected crashes.
 *
 * @param crashes       Vector filled by tapi_fuzz_crashes_collect().
 */
extern void tapi_fuzz_crashes_free(te_vec *crashes);

/**
 * Put a reproducer into the corpus of an agent, as a seed.
 *
 * A crash that is kept as a seed is replayed at the start of every
 * later campaign, which is what stops it coming back.
 *
 * @param ta            Agent name.
 * @param corpus_dir    Corpus directory on the agent.
 * @param local_file    File on the engine, e.g. a saved reproducer.
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_seed_add(const char *ta, const char *corpus_dir,
                                   const char *local_file);

/**
 * List the regular files of a directory on an agent.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  dir          Directory on the agent.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] files        Vector of @c char*, initialized by the call;
 *                          release it with te_vec_deep_free().
 *
 * @return Status code.
 */
extern te_errno tapi_fuzz_list_dir(tapi_job_factory_t *factory,
                                   const char *dir, int timeout_ms,
                                   te_vec *files);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_FUZZ_CRASH_H__ */

/**@} <!-- END tapi_fuzz_crash --> */
