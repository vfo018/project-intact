#!/bin/bash
set -x
pwd
echo "$@"

#PWD is current dir that is the directory of the project will be rsync
DIR=$(basename "$PWD")

TARGET="mmt"

echo "Copy $(pwd) to montimage@nsit-intact-master:$TARGET"

#rsync --progress -e "ssh -oProxyCommand='ssh -i ~/.ssh/id_rsa -p 2222 -W %h:%p mmt@localhost' -i ~/.ssh/id_intact" -rca ./ubitech .git montimage@100.64.0.64:$TARGET
scp -r -o ProxyCommand='ssh -i ~/.ssh/id_rsa -p 2222 -W %h:%p mmt@localhost' -i ~/.ssh/id_intact ./ubitech montimage@100.64.0.64:mmt

date