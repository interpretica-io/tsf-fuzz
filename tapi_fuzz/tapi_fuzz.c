/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Fuzzing campaign TAPI
 *
 * The four fuzzers differ in their command line and in where they put
 * their statistics; everything else about a campaign is the same, so
 * only those two things are written out per kind.
 */

#define TE_LGR_USER "TAPI FUZZ"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_devtool_run.h"
#include "tapi_fuzz.h"
#include "tapi_fuzz_internal.h"

struct tapi_fuzz_app {
    /** Fuzzer job. */
    tapi_devtool_run run;
    /** Options, kept for reading the statistics afterwards. */
    tapi_fuzz_opt opt;
    /** Agent the campaign runs on. */
    char *ta;
};

const tapi_fuzz_opt tapi_fuzz_default_opt = {
    .kind         = TAPI_FUZZ_LIBFUZZER,
    .detect_leaks = true,
};

/** An argument vector built by hand. */
typedef struct fuzz_args_opt {
    size_t n_args;
    const char **args;
} fuzz_args_opt;

static const tapi_job_opt_bind fuzz_args_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(fuzz_args_opt, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/* See description in tapi_fuzz_internal.h */
te_errno
tapi_fuzz_cmd(tapi_job_factory_t *factory, const char *name,
              const char *program, const te_vec *args, int timeout_ms,
              tapi_devtool_run *run)
{
    fuzz_args_opt opt = { .n_args = te_vec_size(args),
                          .args = (const char **)args->data.ptr };
    te_errno rc;

    *run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;

    rc = tapi_devtool_run_init(run, factory, name, program, fuzz_args_binds,
                               &opt, NULL);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(run, timeout_ms);

    if (rc != 0)
        tapi_devtool_run_fini(run);

    return rc;
}

/* See description in tapi_fuzz.h */
const char *
tapi_fuzz_kind2str(tapi_fuzz_kind kind)
{
    switch (kind)
    {
        case TAPI_FUZZ_CARGO:
            return "cargo-fuzz";
        case TAPI_FUZZ_AFLPP:
            return "afl++";
        case TAPI_FUZZ_HONGGFUZZ:
            return "honggfuzz";
        default:
            return "libfuzzer";
    }
}

/** The program that does the fuzzing. */
static const char *
fuzz_runner(const tapi_fuzz_opt *opt)
{
    if (opt->runner != NULL)
        return opt->runner;

    switch (opt->kind)
    {
        case TAPI_FUZZ_CARGO:
            return "cargo";
        case TAPI_FUZZ_AFLPP:
            return "afl-fuzz";
        case TAPI_FUZZ_HONGGFUZZ:
            return "honggfuzz";
        default:
            /* libFuzzer is the target itself. */
            return opt->target;
    }
}

/** Append one argument, taking ownership of a freshly built string. */
static void
fuzz_arg(te_vec *args, const char *fmt, ...) TE_LIKE_PRINTF(2, 3);

static void
fuzz_arg(te_vec *args, const char *fmt, ...)
{
    te_string text = TE_STRING_INIT;
    char *value;
    va_list ap;

    va_start(ap, fmt);
    te_string_append_va(&text, fmt, ap);
    va_end(ap);

    value = text.ptr;
    TE_VEC_APPEND(args, value);
}

/** The libFuzzer options, shared by libFuzzer itself and cargo-fuzz. */
static void
fuzz_libfuzzer_args(const tapi_fuzz_opt *opt, te_vec *args)
{
    te_string prefix = TE_STRING_INIT;

    /*
     * libFuzzer treats the prefix as a string to concatenate, so the
     * separator has to be part of it or every artifact lands next to
     * the directory instead of inside it.
     */
    te_string_append(&prefix, "%s/", opt->output_dir);
    fuzz_arg(args, "-artifact_prefix=%s", prefix.ptr);
    te_string_free(&prefix);

    if (opt->max_total_time != 0)
        fuzz_arg(args, "-max_total_time=%u", opt->max_total_time);
    if (opt->runs != 0)
        fuzz_arg(args, "-runs=%u", opt->runs);
    if (opt->max_len != 0)
        fuzz_arg(args, "-max_len=%u", opt->max_len);
    if (opt->timeout_s != 0)
        fuzz_arg(args, "-timeout=%u", opt->timeout_s);
    if (opt->rss_limit_mb != 0)
        fuzz_arg(args, "-rss_limit_mb=%u", opt->rss_limit_mb);
    if (opt->workers != 0)
    {
        fuzz_arg(args, "-jobs=%u", opt->workers);
        fuzz_arg(args, "-workers=%u", opt->workers);
    }
    if (opt->seed != 0)
        fuzz_arg(args, "-seed=%u", opt->seed);
    if (opt->dict != NULL)
        fuzz_arg(args, "-dict=%s", opt->dict);

    fuzz_arg(args, "-detect_leaks=%d", opt->detect_leaks ? 1 : 0);
}

/** Build the whole command line for a campaign. */
static void
fuzz_build_args(const tapi_fuzz_opt *opt, te_vec *args)
{
    size_t i;

    switch (opt->kind)
    {
        case TAPI_FUZZ_LIBFUZZER:
            fuzz_libfuzzer_args(opt, args);
            fuzz_arg(args, "%s", opt->corpus_dir);
            break;

        case TAPI_FUZZ_CARGO:
            fuzz_arg(args, "fuzz");
            fuzz_arg(args, "run");
            fuzz_arg(args, "%s", opt->target);
            fuzz_arg(args, "%s", opt->corpus_dir);
            /* Everything after -- goes to libFuzzer inside. */
            fuzz_arg(args, "--");
            fuzz_libfuzzer_args(opt, args);
            break;

        case TAPI_FUZZ_AFLPP:
            fuzz_arg(args, "-i");
            fuzz_arg(args, "%s", opt->corpus_dir);
            fuzz_arg(args, "-o");
            fuzz_arg(args, "%s", opt->output_dir);
            if (opt->max_total_time != 0)
            {
                fuzz_arg(args, "-V");
                fuzz_arg(args, "%u", opt->max_total_time);
            }
            if (opt->timeout_s != 0)
            {
                fuzz_arg(args, "-t");
                fuzz_arg(args, "%u", opt->timeout_s * 1000);
            }
            if (opt->rss_limit_mb != 0)
            {
                fuzz_arg(args, "-m");
                fuzz_arg(args, "%u", opt->rss_limit_mb);
            }
            if (opt->dict != NULL)
            {
                fuzz_arg(args, "-x");
                fuzz_arg(args, "%s", opt->dict);
            }
            if (opt->seed != 0)
            {
                fuzz_arg(args, "-s");
                fuzz_arg(args, "%u", opt->seed);
            }
            break;

        case TAPI_FUZZ_HONGGFUZZ:
            fuzz_arg(args, "-i");
            fuzz_arg(args, "%s", opt->corpus_dir);
            fuzz_arg(args, "-W");
            fuzz_arg(args, "%s", opt->output_dir);
            if (opt->max_total_time != 0)
                fuzz_arg(args, "--run_time=%u", opt->max_total_time);
            if (opt->timeout_s != 0)
                fuzz_arg(args, "-t%u", opt->timeout_s);
            if (opt->workers != 0)
                fuzz_arg(args, "-n%u", opt->workers);
            if (opt->max_len != 0)
                fuzz_arg(args, "-F%u", opt->max_len);
            if (opt->dict != NULL)
            {
                fuzz_arg(args, "-w");
                fuzz_arg(args, "%s", opt->dict);
            }
            break;
    }

    for (i = 0; i < opt->n_extra_args; i++)
        fuzz_arg(args, "%s", opt->extra_args[i]);

    /*
     * The drivers take the target after a separator, and each has its
     * own spelling for "put the input in a file here".
     */
    if (opt->kind == TAPI_FUZZ_AFLPP)
    {
        fuzz_arg(args, "--");
        fuzz_arg(args, "%s", opt->target);
        fuzz_arg(args, "@@");
    }
    else if (opt->kind == TAPI_FUZZ_HONGGFUZZ)
    {
        fuzz_arg(args, "--");
        fuzz_arg(args, "%s", opt->target);
        fuzz_arg(args, "___FILE___");
    }
}

/* See description in tapi_fuzz.h */
void
tapi_fuzz_crash_dir(const tapi_fuzz_opt *opt, te_string *dest)
{
    /*
     * AFL++ owns its output directory and keeps the crashes in a
     * subdirectory named after the instance; without -M or -S that
     * name is "default".
     */
    if (opt->kind == TAPI_FUZZ_AFLPP)
        te_string_append(dest, "%s/default/crashes", opt->output_dir);
    else
        te_string_append(dest, "%s", opt->output_dir);
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_create(tapi_job_factory_t *factory, const tapi_fuzz_opt *opt,
                 tapi_fuzz_app **app)
{
    const char *ta = tapi_job_factory_ta(factory);
    fuzz_args_opt args_opt;
    te_vec args = TE_VEC_INIT(char *);
    tapi_fuzz_app *result;
    te_errno rc;

    if (opt->target == NULL || opt->corpus_dir == NULL ||
        opt->output_dir == NULL)
    {
        ERROR("A campaign needs a target, a corpus and an output directory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    fuzz_build_args(opt, &args);

    args_opt.n_args = te_vec_size(&args);
    args_opt.args = (const char **)args.data.ptr;

    result = TE_ALLOC(sizeof(*result));
    result->run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;
    result->opt = *opt;
    result->ta = TE_STRDUP(ta);

    rc = tapi_devtool_run_init(&result->run, factory,
                               tapi_fuzz_kind2str(opt->kind),
                               fuzz_runner(opt), fuzz_args_binds, &args_opt,
                               opt->workdir);

    te_vec_deep_free(&args);

    if (rc != 0)
    {
        free(result->ta);
        free(result);
        return rc;
    }

    *app = result;

    return 0;
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_start(tapi_fuzz_app *app)
{
    return tapi_devtool_run_start(&app->run);
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_wait(tapi_fuzz_app *app, int timeout_ms)
{
    /*
     * The exit status is not checked on purpose: libFuzzer exits
     * non-zero exactly when it found something, which is what the test
     * asked it to do.
     */
    return tapi_devtool_run_wait(&app->run, timeout_ms);
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_stop(tapi_fuzz_app *app)
{
    te_errno rc;

    rc = tapi_devtool_run_stop(&app->run);
    if (rc != 0)
        return rc;

    return tapi_devtool_run_wait(&app->run, TAPI_DEVTOOL_TERM_TIMEOUT_MS * 5);
}

/* See description in tapi_fuzz.h */
void
tapi_fuzz_get_output(const tapi_fuzz_app *app, tapi_devtool_output *output)
{
    tapi_devtool_run_get_output(&app->run, output);
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_destroy(tapi_fuzz_app *app)
{
    te_errno rc;

    if (app == NULL)
        return 0;

    rc = tapi_devtool_run_fini(&app->run);
    free(app->ta);
    free(app);

    return rc;
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_do(tapi_job_factory_t *factory, const tapi_fuzz_opt *opt,
             int timeout_ms, tapi_fuzz_app **app)
{
    te_errno rc;

    rc = tapi_fuzz_create(factory, opt, app);
    if (rc != 0)
        return rc;

    rc = tapi_fuzz_start(*app);
    if (rc != 0)
        return rc;

    return tapi_fuzz_wait(*app, timeout_ms);
}

/** Read an unsigned number that follows @p key in @p line. */
static bool
fuzz_read_after(const char *line, const char *key, uint64_t *value)
{
    const char *found = strstr(line, key);
    uintmax_t parsed;
    char *number;

    if (found == NULL)
        return false;

    found += strlen(key);
    while (*found == ' ' || *found == '\t')
        found++;

    number = TE_STRDUP(found);
    number[strcspn(number, " \t/%,")] = '\0';

    if (te_strtoumax(number, 10, &parsed) != 0)
    {
        free(number);
        return false;
    }

    free(number);
    *value = parsed;

    return true;
}

/** Read the statistics libFuzzer prints on every interesting input. */
static bool
fuzz_stats_libfuzzer(const char *text, tapi_fuzz_stats *stats)
{
    char *copy = TE_STRDUP(text);
    char *line;
    char *saveptr = NULL;
    bool found = false;

    for (line = strtok_r(copy, "\n", &saveptr);
         line != NULL;
         line = strtok_r(NULL, "\n", &saveptr))
    {
        uint64_t value;

        /* Keep the last one: it is the state the campaign ended in. */
        if (line[0] != '#' || strstr(line, "exec/s:") == NULL)
            continue;

        found = true;

        /* The number right after '#' is how many inputs have run. */
        {
            uintmax_t executed;
            char *digits = TE_STRDUP(line + 1);

            digits[strcspn(digits, " \t")] = '\0';
            if (te_strtoumax(digits, 10, &executed) == 0)
                stats->execs = executed;
            free(digits);
        }

        if (fuzz_read_after(line, "cov:", &value))
            stats->coverage = value;
        if (fuzz_read_after(line, "ft:", &value))
            stats->features = value;
        if (fuzz_read_after(line, "corp:", &value))
            stats->corpus_size = value;
        if (fuzz_read_after(line, "exec/s:", &value))
            stats->execs_per_sec = value;
    }

    free(copy);

    return found;
}

/** Read the summary honggfuzz prints when it stops. */
static bool
fuzz_stats_honggfuzz(const char *text, tapi_fuzz_stats *stats)
{
    bool found = false;

    found |= fuzz_read_after(text, "iterations:", &stats->execs);
    found |= fuzz_read_after(text, "speed:", &stats->execs_per_sec);
    found |= fuzz_read_after(text, "crashes_count:", &stats->crashes);
    found |= fuzz_read_after(text, "timeout_count:", &stats->timeouts);

    return found;
}

/** Trim the spaces off both ends of a string, in place. */
static char *
fuzz_trim(char *text)
{
    size_t len;

    while (*text == ' ' || *text == '\t')
        text++;

    len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                       text[len - 1] == '\r'))
        text[--len] = '\0';

    return text;
}

/**
 * Read the fuzzer_stats file AFL++ keeps in its output directory.
 *
 * Every line of it is "key : value", so it is read as such rather than
 * by hunting for keys inside the text.
 */
static bool
fuzz_stats_aflpp(const char *ta, const tapi_fuzz_opt *opt,
                 tapi_fuzz_stats *stats)
{
    te_string path = TE_STRING_INIT;
    char *content = NULL;
    char *line;
    char *saveptr = NULL;
    bool found = false;
    te_errno rc;

    te_string_append(&path, "%s/default/fuzzer_stats", opt->output_dir);

    /* A regular file, so RCF can fetch it as it is. */
    rc = tapi_file_read_ta(ta, path.ptr, &content);
    te_string_free(&path);
    if (rc != 0)
    {
        RING("AFL++ has not written its statistics yet: %r", rc);
        return false;
    }

    for (line = strtok_r(content, "\n", &saveptr);
         line != NULL;
         line = strtok_r(NULL, "\n", &saveptr))
    {
        char *colon = strchr(line, ':');
        uintmax_t number = 0;
        const char *key;
        char *value;

        if (colon == NULL)
            continue;

        *colon = '\0';
        key = fuzz_trim(line);
        value = fuzz_trim(colon + 1);

        if (strcmp(key, "bitmap_cvg") == 0)
        {
            /*
             * "1.23%" of the bitmap. Kept as per mille so that a whole
             * number carries the first decimal.
             */
            stats->coverage = (uint64_t)(strtod(value, NULL) * 10.0);
            found = true;
            continue;
        }

        if (te_strtoumax(value, 10, &number) != 0)
            continue;

        if (strcmp(key, "execs_done") == 0)
            stats->execs = number;
        else if (strcmp(key, "execs_per_sec") == 0)
            stats->execs_per_sec = number;
        else if (strcmp(key, "corpus_count") == 0)
            stats->corpus_size = number;
        else if (strcmp(key, "saved_crashes") == 0 ||
                 strcmp(key, "unique_crashes") == 0)
            stats->crashes = number;
        else if (strcmp(key, "saved_hangs") == 0 ||
                 strcmp(key, "unique_hangs") == 0)
            stats->timeouts = number;
        else
            continue;

        found = true;
    }

    free(content);

    return found;
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_get_stats(tapi_fuzz_app *app, tapi_fuzz_stats *stats)
{
    tapi_devtool_output output;

    memset(stats, 0, sizeof(*stats));

    tapi_fuzz_get_output(app, &output);

    switch (app->opt.kind)
    {
        case TAPI_FUZZ_LIBFUZZER:
        case TAPI_FUZZ_CARGO:
            /* libFuzzer writes its progress to stderr. */
            stats->valid = fuzz_stats_libfuzzer(output.err, stats) ||
                           fuzz_stats_libfuzzer(output.out, stats);
            break;

        case TAPI_FUZZ_AFLPP:
            stats->valid = fuzz_stats_aflpp(app->ta, &app->opt, stats);
            break;

        case TAPI_FUZZ_HONGGFUZZ:
            stats->valid = fuzz_stats_honggfuzz(output.err, stats) ||
                           fuzz_stats_honggfuzz(output.out, stats);
            break;
    }

    return 0;
}

/* See description in tapi_fuzz.h */
void
tapi_fuzz_stats_log(const tapi_fuzz_stats *stats)
{
    if (!stats->valid)
    {
        WARN("The campaign left no statistics to read");
        return;
    }

    RING("Fuzzing campaign:");
    RING("  executed: %" PRIu64 " inputs, %" PRIu64 "/s", stats->execs,
         stats->execs_per_sec);
    RING("  corpus: %" PRIu64, stats->corpus_size);
    RING("  coverage: %" PRIu64 "%s", stats->coverage,
         stats->features != 0 ? "" : " (fuzzer's own unit)");
    if (stats->features != 0)
        RING("  features: %" PRIu64, stats->features);
    RING("  crashes: %" PRIu64 ", timeouts: %" PRIu64, stats->crashes,
         stats->timeouts);
}

/* See description in tapi_fuzz.h */
te_errno
tapi_fuzz_check_progress(const tapi_fuzz_stats *stats, uint64_t min_execs,
                         uint64_t min_coverage, tapi_cybersec_report *report)
{
    if (!stats->valid)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "fuzz.no-statistics", "campaign",
                                 "the fuzzer left nothing to read, so there "
                                 "is no evidence it ran");
        return 0;
    }

    if (min_execs != 0 && stats->execs < min_execs)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "fuzz.no-progress", "campaign",
                                 "only %" PRIu64 " inputs were executed, "
                                 "fewer than the %" PRIu64 " a working "
                                 "harness would have managed", stats->execs,
                                 min_execs);
    }

    if (min_coverage != 0 && stats->coverage < min_coverage)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "fuzz.low-coverage", "campaign",
                                 "coverage reached %" PRIu64 ", below the "
                                 "%" PRIu64 " expected: the harness is "
                                 "probably rejecting inputs before they "
                                 "reach the code", stats->coverage,
                                 min_coverage);
    }

    return 0;
}
