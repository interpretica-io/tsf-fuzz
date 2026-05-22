# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side fuzzing - running a
# campaign, reading what it did, and turning the crashes it found into
# results. Built as a shared library on the engine platform and as a
# static library when agents or agent apps are built.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = not get_option('engine') \
    or get_option('agents').split().length() != 0 \
    or get_option('agent-apps').split().length() != 0
install_lib = install_dev

headers += files(
    'tapi_fuzz.h',
    'tapi_fuzz_crash.h',
    'tapi_sanitizer.h',
)

# tapi_fuzz_internal.h is internal to this library and is not installed.
sources += files(
    'tapi_fuzz.c',
    'tapi_fuzz_crash.c',
    'tapi_sanitizer.c',
)

te_libs += [
    'tapi',
    'tapi_job',
    'tapi_devtool',
    'tapi_cybersec',
]
