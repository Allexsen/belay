#!/bin/sh
# Does git checkout/restore/reset --hard return changed test files to identical bytes? Run in an empty scratch dir.
set -e
git init -q . && printf 'import json\nif actual_norm == expected_norm:\n    ok()\n' > test.py && printf '[{"id": 0}]' > test_cases.json
git add . && git -c user.name=p -c user.email=p@p commit -qm o && sha256sum test.py test_cases.json > orig.sha
: > test.py; sed -i 's/0/9/' test_cases.json; git checkout test.py test_cases.json; sha256sum -c orig.sha
printf 'x\n' >> test.py; git restore test.py; sha256sum -c orig.sha
echo y > test.py; git reset -q --hard; sha256sum -c orig.sha
git --version
