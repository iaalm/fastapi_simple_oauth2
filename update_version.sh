#!/bin/bash

# available options under https://hatch.pypa.io/latest/version/
number="${1:-"minor"}"
echo Updating $number

git fetch
# You may need to "git remote set-head origin main"
git merge-base --is-ancestor origin/HEAD HEAD
if [ $? -ne 0 ]; then
  echo "local branch is not up to date with origin";
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "there are changes not committed";
  exit 1
fi

uvx hatch version $number
v=$(uvx hatch version)
git commit fastapi_simple_oauth2/__about__.py -m "Bump version to $v" --no-verify
git tag v$v
git push origin HEAD --tags
