#!/usr/bin/env bash

set -ex

# PREREQUISITES:
# 1.  $ docker built -t vt /path/to/VirusTotalApi/Dockerfile
# 2.  Create VirusTotal account, obtain API key, and place in `~/.vtapi` config file

# EXPLANATION:
#    "docker run" instructs docker to run a container.
#    "--rm" instructs docker to clean up after itself once container stops.
#    "-v $HOME/.vtapi:/root/.vtapi" instructs docker to mount a volume inside the container. This is used to provide the config file from the host to the container.
#    "vt" is the name of the container image we're executing. This name can be anything and it is basically what you decided to call the image at build-time with "-t" flag.
#    "-u http://upload-dropbox.com" are the flags and arguments. The URL in this example is a known malicious URL used in Cambodian RAT, called KHRAT.
docker run --rm -v $HOME/.vtapi:/root/.vtapi vt -u http://upload-dropbox.com
