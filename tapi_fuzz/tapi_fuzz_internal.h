/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Fuzzing TAPI: internal command helper
 *
 * Internal to tsf-fuzz; not installed.
 */

#ifndef __TSF_TAPI_FUZZ_INTERNAL_H__
#define __TSF_TAPI_FUZZ_INTERNAL_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_devtool_run.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run @p program with @p args and wait for it.
 *
 * The command is waited for, not checked: a crashing reproducer exits
 * badly by design.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  name         Tool name for log messages.
 * @param[in]  program      Program name or path.
 * @param[in]  args         Arguments after @c argv[0], a vector of
 *                          @c char* owned by the caller.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] run          Run handle; release it with
 *                          tapi_devtool_run_fini().
 *
 * @return Status code of running the command, not of the command.
 */
extern te_errno tapi_fuzz_cmd(tapi_job_factory_t *factory, const char *name,
                              const char *program, const te_vec *args,
                              int timeout_ms, tapi_devtool_run *run);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_FUZZ_INTERNAL_H__ */
