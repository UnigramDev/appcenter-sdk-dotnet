#!/bin/bash
# Note: Run this from within the root directory

storageid=$1

./build.sh -t "MergeAssemblies" -StorageId storageid

