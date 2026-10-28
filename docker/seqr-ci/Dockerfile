# Slim image that runs `seqr ci` — for Jenkins, GitLab, pre-commit, or any CI runner
# that can pull a container. One image, every non-GitHub consumer.
#
# Build with the CLI directory as the context (keeps the image small and self-contained):
#
#   docker build -f docker/seqr-ci/Dockerfile -t seqrlabs/seqr-ci:latest ./cli
#
# The CLI is installed from source on purpose: the current `seqr ci` command is not yet
# on the PyPI release (0.1.1 predates it), so we install the in-repo `./cli`.
FROM python:3.12-slim

# git: `seqr ci` diffs the change set against a base ref (merge-base <base> HEAD).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

# Install the SeQr CLI (context is ./cli, so COPY . brings the package + pyproject).
COPY . /opt/seqr-cli
RUN pip install --no-cache-dir /opt/seqr-cli \
 && rm -rf /root/.cache/pip

# CI mounts the repo owned by a different uid; without this git refuses ("dubious
# ownership") and the diff fails.
RUN git config --global --add safe.directory '*'

# UTF-8 so the Markdown report's emoji don't trip a legacy locale.
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    LANG=C.UTF-8

WORKDIR /src
# ENTRYPOINT is `seqr` so callers pass the subcommand — `seqr ci …`. In GitLab/Jenkins,
# which override the entrypoint with a shell, `seqr` is still on PATH.
ENTRYPOINT ["seqr"]
CMD ["ci", ".", "--all"]
