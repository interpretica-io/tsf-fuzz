# tsf-fuzz

Fuzzing from a Test Environment (TE) suite, packaged as an external TE
repository and consumed with the `TE_EXT_REPO` builder directive.

Library:

- `tapi_fuzz` — engine-side, built as a shared library:
  - `tapi_fuzz` — the campaign: run a fuzzer, read its statistics, and
    check that it actually fuzzed;
  - `tapi_sanitizer` — what a crashing process printed, reduced to an
    identity that is the same every time;
  - `tapi_fuzz_crash` — the artifacts a campaign left: replay,
    deduplicate, report, and keep as regression seeds.

Every other security check in these repositories looks for a weakness
whose shape somebody wrote down first. A fuzzer does not — it is the one
thing that finds defects nobody had thought of. What it needs in
exchange is somewhere to put the answer, and that is what this is.

## Usage

Declare the repositories in an external libraries catalog and bind them
in `builder.conf`:

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_kernel], [], [tapi_kernel])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_fuzz], [], [tapi_fuzz])
```

Then add `tapi_fuzz` to `te_libs` in the suite's `meson.build`.

Findings use the report model of
[tsf-cybersec](https://github.com/interpretica-io/tsf-cybersec), so a
fuzzing group and a scanning group produce the same kind of result and
share one verdict. That is deliberate — but it does mean a suite that
only wants to fuzz still pulls in tsf-cybersec, and through it tsf-kernel
and tsf-devtool. If that becomes a nuisance, the answer is to lift
`tapi_cybersec.h` into a repository of its own rather than to grow a
second finding model here.

Requires TE with `TE_EXT_REPO` support and an **RPC** job factory.

## Four fuzzers, one interface

The shape of a campaign is the same whichever fuzzer runs it, so only
the command line and the place the statistics live are written out per
kind.

| Kind | Runs | Needs |
|---|---|---|
| `TAPI_FUZZ_LIBFUZZER` | the target itself | a target built with `-fsanitize=fuzzer` |
| `TAPI_FUZZ_CARGO` | `cargo fuzz run` | a Rust `fuzz_target`, which is libFuzzer underneath |
| `TAPI_FUZZ_AFLPP` | `afl-fuzz` | a target built with an `afl-cc`, or QEMU mode |
| `TAPI_FUZZ_HONGGFUZZ` | `honggfuzz` | a target, instrumented or not |

Building the target is [tsf-devtool](https://github.com/interpretica-io/tsf-devtool)'s
job: `tapi_cc` with the right `-fsanitize=` flags, or `tapi_make` for a
project that knows how to build its own harness.

```c
tapi_fuzz_opt opt = tapi_fuzz_default_opt;
tapi_fuzz_app *app = NULL;
tapi_fuzz_stats stats;
te_vec crashes;

opt.kind = TAPI_FUZZ_LIBFUZZER;
opt.target = "/opt/dut/fuzz_parser";
opt.corpus_dir = corpus;
opt.output_dir = artifacts;
opt.max_total_time = 300;

CHECK_RC(tapi_fuzz_do(factory, &opt, 400000, &app));
CHECK_RC(tapi_fuzz_get_stats(app, &stats));
tapi_fuzz_stats_log(&stats);
```

## The check that keeps a fuzzing test honest

```c
CHECK_RC(tapi_fuzz_check_progress(&stats, 10000, 1, &report));
```

A harness that dies on startup, or that rejects every input before it
reaches the code, finds no crashes — and a test that only looks for
crashes calls that a pass. This is the most common way a fuzzing suite
goes quietly useless, and it is why `tapi_fuzz_get_stats()` exists at
all. Assert that the campaign executed something and that coverage
moved, or the rest is theatre.

Coverage is the fuzzer's own number and the fuzzers do not agree on the
unit — libFuzzer counts covered edges, AFL++ reports the share of its
bitmap — so compare it with itself across runs, not with another fuzzer.
For a real coverage figure, wire TE's own `tce` at the suite level;
that is a build-system setting, not something a library can do for you.

## From a crash to a fix that stays fixed

A directory of crashing inputs is not a test result. Half of them are
the same defect reached by different paths, none says what went wrong,
and a week later nobody can tell which are fixed.

```c
CHECK_RC(tapi_fuzz_crashes_collect(factory, &opt, seeds_dir, 30000,
                                   &crashes));
tapi_fuzz_crashes_log(&crashes);
CHECK_RC(tapi_fuzz_crashes_check(&crashes, &report));
```

Each artifact is replayed against the target, the sanitizer report is
reduced to a **signature** — the kind of error and the names of the top
frames, with addresses, offsets and the sanitizer's own frames left out
— artifacts sharing a signature are counted as one, and one reproducer
of each is saved on the engine.

The signature is the point. It is the same on every run and on every
machine, so it works as the subject of a finding and as an entry in
`conf/trc.xml`:

1. the campaign finds a crash;
2. it is reported with a verdict built from the signature, and goes into
   TRC as a known issue — so the next run reports a known issue, not a
   regression, and a *new* crash stands out;
3. the saved reproducer is committed into the suite's corpus with
   `tapi_fuzz_seed_add()`, so every later campaign starts by replaying
   it;
4. when it is fixed, the TRC entry flips to `PASSED` and the seed guards
   the fix from then on.

Rust panics are parsed alongside the C sanitizers. They come out of the
same campaign and a test should not have to care which language produced
the crash it is looking at.

## Running a campaign as a test

A campaign is not a unit test: it takes as long as it is told to. Give
the group its own requirement so an ordinary run does not sit through
it, and keep the corpus in the suite so every run starts where the last
one got to — a fuzzer that starts from an empty corpus every night is a
fuzzer that finds the same shallow bug every night.

The timeout passed to `tapi_fuzz_do()` must be longer than
`max_total_time`, or the job is killed while the fuzzer is still tidying
up and the statistics are lost.

## Notes

- Listing a directory on an agent is done by running `find`, because RCF
  transfers files but does not enumerate them. This is the same gap that
  keeps `tapi_binscan` to explicit paths.
- Replaying an artifact assumes the target takes the input as a file
  argument, which is how all four fuzzers were told to run it. A target
  that reads standard input needs a wrapper.
- The exit status of a fuzzer is not treated as the result: libFuzzer
  exits non-zero exactly when it found something, which is a success for
  the test that asked it to look.
- AFL++ keeps its crashes in `<output_dir>/default/crashes`, which is
  what `tapi_fuzz_crash_dir()` knows and the other kinds do not need.
  Running AFL++ with `-M`/`-S` changes that name; this library does not
  set them.
