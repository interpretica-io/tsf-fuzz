/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Crash triage
 *
 * Replaying the artifacts a campaign left, reducing them to distinct
 * defects, and keeping one reproducer of each.
 */

#define TE_LGR_USER "TAPI FUZZ CRASH"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_kvpair.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_fuzz_crash.h"
#include "tapi_fuzz_internal.h"

/** The last component of a path. */
static const char *
crash_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return (slash != NULL) ? slash + 1 : path;
}

/** Files a fuzzer leaves in a crash directory that are not crashes. */
static bool
crash_is_artifact(const char *path)
{
    const char *name = crash_basename(path);

    if (strncmp(name, "README", 6) == 0)
        return false;

    /* AFL++ keeps its own bookkeeping next to the crashes. */
    if (strcmp(name, ".state") == 0 || strcmp(name, "fuzzer_stats") == 0 ||
        strcmp(name, "fuzz_bitmap") == 0 || strcmp(name, "plot_data") == 0 ||
        strcmp(name, "cmdline") == 0)
        return false;

    return true;
}

/* See description in tapi_fuzz_crash.h */
te_errno
tapi_fuzz_list_dir(tapi_job_factory_t *factory, const char *dir,
                   int timeout_ms, te_vec *files)
{
    te_vec args = TE_VEC_INIT(char *);
    tapi_devtool_output output;
    tapi_devtool_run run;
    char *text = NULL;
    char *line;
    char *saveptr = NULL;
    te_errno rc;

    *files = (te_vec)TE_VEC_INIT(char *);

    /*
     * RCF moves files but does not enumerate them, so the enumeration
     * is a command like any other.
     */
    TE_VEC_APPEND_RVALUE(&args, char *, TE_STRDUP(dir));
    TE_VEC_APPEND_RVALUE(&args, char *, TE_STRDUP("-maxdepth"));
    TE_VEC_APPEND_RVALUE(&args, char *, TE_STRDUP("1"));
    TE_VEC_APPEND_RVALUE(&args, char *, TE_STRDUP("-type"));
    TE_VEC_APPEND_RVALUE(&args, char *, TE_STRDUP("f"));

    rc = tapi_fuzz_cmd(factory, "find", "find", &args, timeout_ms, &run);
    te_vec_deep_free(&args);
    if (rc != 0)
        return rc;

    tapi_devtool_run_get_output(&run, &output);

    if (output.status.type != TAPI_JOB_STATUS_EXITED ||
        output.status.value != 0)
    {
        /* An empty or missing directory is an answer, not a failure. */
        RING("Nothing to list in %s", dir);
        tapi_devtool_run_fini(&run);
        return 0;
    }

    text = TE_STRDUP(output.out);
    tapi_devtool_run_fini(&run);

    for (line = strtok_r(text, "\n", &saveptr);
         line != NULL;
         line = strtok_r(NULL, "\n", &saveptr))
    {
        char *path;

        if (*line == '\0' || !crash_is_artifact(line))
            continue;

        path = TE_STRDUP(line);
        TE_VEC_APPEND(files, path);
    }

    free(text);

    return 0;
}

/** Build the command that replays one artifact. */
static void
crash_replay_args(const tapi_fuzz_opt *opt, const char *artifact,
                  const char **program, te_vec *args)
{
    if (opt->kind == TAPI_FUZZ_CARGO)
    {
        *program = (opt->runner != NULL) ? opt->runner : "cargo";
        TE_VEC_APPEND_RVALUE(args, char *, TE_STRDUP("fuzz"));
        TE_VEC_APPEND_RVALUE(args, char *, TE_STRDUP("run"));
        TE_VEC_APPEND_RVALUE(args, char *, TE_STRDUP(opt->target));
        TE_VEC_APPEND_RVALUE(args, char *, TE_STRDUP(artifact));
        return;
    }

    /*
     * Everything else takes the input as a file argument, which is how
     * the fuzzers were told to run it in the first place.
     */
    *program = opt->target;
    TE_VEC_APPEND_RVALUE(args, char *, TE_STRDUP(artifact));
}

/** Replay one artifact and read what the target said about it. */
static te_errno
crash_replay(tapi_job_factory_t *factory, const tapi_fuzz_opt *opt,
             const char *artifact, int timeout_ms,
             tapi_sanitizer_report *report)
{
    te_vec args = TE_VEC_INIT(char *);
    tapi_devtool_output output;
    tapi_devtool_run run;
    const char *program = NULL;
    te_errno rc;

    crash_replay_args(opt, artifact, &program, &args);

    rc = tapi_fuzz_cmd(factory, "replay", program, &args, timeout_ms, &run);
    te_vec_deep_free(&args);
    if (rc != 0)
        return rc;

    tapi_devtool_run_get_output(&run, &output);

    /* Sanitizers write to stderr; a panic may go to either. */
    if (!tapi_sanitizer_parse(output.err, report))
    {
        tapi_sanitizer_report_free(report);
        tapi_sanitizer_parse(output.out, report);
    }

    if (report->kind == TAPI_SANITIZER_NONE &&
        output.status.type == TAPI_JOB_STATUS_SIGNALED)
    {
        report->kind = TAPI_SANITIZER_SIGNAL;
        free(report->error);
        report->error = NULL;
        {
            te_string text = TE_STRING_INIT;

            te_string_append(&text, "killed by signal %d",
                             output.status.value);
            report->error = text.ptr;
        }
    }

    /*
     * Nothing recognisable: the artifact is still the identity of the
     * input, and a fuzzer names it after its contents.
     */
    tapi_sanitizer_signature_fallback(report, crash_basename(artifact));

    tapi_devtool_run_fini(&run);

    return 0;
}

/* See description in tapi_fuzz_crash.h */
te_errno
tapi_fuzz_crashes_collect(tapi_job_factory_t *factory,
                          const tapi_fuzz_opt *opt, const char *save_dir,
                          int timeout_ms, te_vec *crashes)
{
    const char *ta = tapi_job_factory_ta(factory);
    te_string crash_dir = TE_STRING_INIT;
    te_vec artifacts;
    te_kvpair_h seen;
    char *const *artifact;
    te_errno rc;

    *crashes = (te_vec)TE_VEC_INIT(tapi_fuzz_crash);
    te_kvpair_init(&seen);

    if (ta == NULL)
    {
        te_kvpair_fini(&seen);
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    tapi_fuzz_crash_dir(opt, &crash_dir);

    rc = tapi_fuzz_list_dir(factory, crash_dir.ptr, timeout_ms, &artifacts);
    if (rc != 0)
        goto out;

    RING("The campaign left %u artifacts in %s",
         (unsigned int)te_vec_size(&artifacts), crash_dir.ptr);

    TE_VEC_FOREACH(&artifacts, artifact)
    {
        tapi_sanitizer_report report;
        tapi_fuzz_crash crash;
        const char *known;

        rc = crash_replay(factory, opt, *artifact, timeout_ms, &report);
        if (rc != 0)
        {
            tapi_sanitizer_report_free(&report);
            goto out_artifacts;
        }

        known = te_kvpairs_get_nth(&seen, report.signature, 0);
        if (known != NULL)
        {
            /* The same defect, reached by another input. */
            tapi_fuzz_crash *first;
            unsigned int index;

            if (te_strtoui(known, 10, &index) == 0 &&
                index < te_vec_size(crashes))
            {
                first = te_vec_get(crashes, index);
                first->count++;
            }
            tapi_sanitizer_report_free(&report);
            continue;
        }

        memset(&crash, 0, sizeof(crash));
        crash.artifact = TE_STRDUP(*artifact);
        crash.count = 1;
        crash.report = report;

        if (save_dir != NULL)
        {
            te_string local = TE_STRING_INIT;

            te_string_append(&local, "%s/%s", save_dir,
                             crash_basename(*artifact));
            rc = tapi_file_copy_ta(ta, *artifact, NULL, local.ptr);
            if (rc != 0)
            {
                ERROR("Failed to save the reproducer of %s: %r",
                      report.signature, rc);
                te_string_free(&local);
                tapi_sanitizer_report_free(&crash.report);
                free(crash.artifact);
                goto out_artifacts;
            }
            crash.saved = local.ptr;
        }

        {
            te_string index = TE_STRING_INIT;

            te_string_append(&index, "%u",
                             (unsigned int)te_vec_size(crashes));
            te_kvpair_push(&seen, report.signature, "%s", index.ptr);
            te_string_free(&index);
        }

        TE_VEC_APPEND(crashes, crash);
    }

out_artifacts:
    te_vec_deep_free(&artifacts);

out:
    te_string_free(&crash_dir);
    te_kvpair_fini(&seen);

    if (rc != 0)
        tapi_fuzz_crashes_free(crashes);

    return rc;
}

/* See description in tapi_fuzz_crash.h */
te_errno
tapi_fuzz_crashes_check(const te_vec *crashes, tapi_cybersec_report *report)
{
    const tapi_fuzz_crash *crash;

    TE_VEC_FOREACH(crashes, crash)
    {
        tapi_cybersec_report_add(report,
                                 tapi_sanitizer_severity(crash->report.kind,
                                                         crash->report.error),
                                 "fuzz.crash", crash->report.signature,
                                 "%s, reached by %u input%s; reproducer %s",
                                 crash->report.error != NULL ?
                                     crash->report.error : "no error text",
                                 crash->count, crash->count == 1 ? "" : "s",
                                 crash->saved != NULL ? crash->saved :
                                     crash->artifact);
    }

    return 0;
}

/* See description in tapi_fuzz_crash.h */
void
tapi_fuzz_crashes_log(const te_vec *crashes)
{
    const tapi_fuzz_crash *crash;

    RING("Distinct defects: %u", (unsigned int)te_vec_size(crashes));

    TE_VEC_FOREACH(crashes, crash)
    {
        RING("  %s (%u input%s)", crash->report.signature, crash->count,
             crash->count == 1 ? "" : "s");
        tapi_sanitizer_report_log(&crash->report);
    }
}

/* See description in tapi_fuzz_crash.h */
void
tapi_fuzz_crashes_free(te_vec *crashes)
{
    tapi_fuzz_crash *crash;

    TE_VEC_FOREACH(crashes, crash)
    {
        free(crash->artifact);
        free(crash->saved);
        tapi_sanitizer_report_free(&crash->report);
    }

    te_vec_free(crashes);
}

/* See description in tapi_fuzz_crash.h */
te_errno
tapi_fuzz_seed_add(const char *ta, const char *corpus_dir,
                   const char *local_file)
{
    te_string remote = TE_STRING_INIT;
    te_errno rc;

    te_string_append(&remote, "%s/%s", corpus_dir,
                     crash_basename(local_file));

    rc = tapi_file_copy_ta(NULL, local_file, ta, remote.ptr);
    if (rc != 0)
        ERROR("Failed to put the seed %s on TA %s: %r", local_file, ta, rc);
    else
        RING("Seed %s is now in the corpus of TA %s", remote.ptr, ta);

    te_string_free(&remote);

    return rc;
}
