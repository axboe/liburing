#!/usr/bin/env bash

TESTS=("$@")
RESULT_FILE=$(mktemp)
./runtests.sh "${TESTS[@]}" 2>&1 > $RESULT_FILE
RET="$?"
if [ "${RET}" -ne 0 ]; then
    cat $RESULT_FILE
fi
rm $RESULT_FILE
exit $RET
