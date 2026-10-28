# `seqrlabs/seqr-ci` — the SeQr PQC gate in a container

A slim image that runs [`seqr ci`](../../docs/CI_GATE.md) on any runner that can pull a
container: Jenkins, GitLab, Drone, CircleCI, a pre-commit hook, or a plain `docker run`.
The GitHub Action wraps the same command; this is the everything-else path.

> **Exit 0 by default.** Arm the gate with `--fail-on`, `--policy`, or `--fail-on-drift`.

## Build

```bash
docker build -f docker/seqr-ci/Dockerfile -t seqrlabs/seqr-ci:latest ./cli
```

The build context is `./cli` on purpose — it keeps the image small and installs the CLI
from source (the `ci` command is newer than the PyPI 0.1.1 release).

## Run

```bash
# advisory scan of the whole tree (never fails)
docker run --rm -v "$PWD:/src" seqrlabs/seqr-ci:latest ci . --all

# gate a change against a base ref, writing the report + SARIF
docker run --rm -v "$PWD:/src" seqrlabs/seqr-ci:latest \
  ci . --base origin/main --fail-on-drift \
  --comment-file seqr-pqc-report.md --sarif-file seqr-pqc.sarif
```

The container's `ENTRYPOINT` is `seqr`, so the first argument is the subcommand.

## Jenkins (declarative pipeline)

```groovy
pipeline {
  agent { docker { image 'seqrlabs/seqr-ci:latest' args '-u root' } }
  stages {
    stage('PQC gate') {
      steps {
        // advisory by default; add --fail-on-drift / --policy strict to block the build
        sh 'seqr ci . --base origin/main --comment-file seqr-pqc-report.md --sarif-file seqr-pqc.sarif'
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'seqr-pqc-report.md,seqr-pqc.sarif', allowEmptyArchive: true
    }
  }
}
```

Jenkins overrides the entrypoint with a shell, so `seqr` is invoked from `PATH`. Keep a
`seqr-baseline.json` in the repo so only NEW drift trips an armed gate.

## Smoke test

[`smoke-test.sh`](smoke-test.sh) builds the image and runs it against a tiny sample repo
containing one known quantum-vulnerable pattern, asserting the gate reports it and that an
armed `--fail-on-drift` exits non-zero.
