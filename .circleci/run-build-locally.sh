#!/usr/bin/env bash
curl --user ${CIRCLE_TOKEN}: \
    --request POST \
    --form revision=$(git rev-parse HEAD)\
    --form config=@config.yml \
    --form notify=false \
    https://circleci.com/api/v1.1/project/github/reid-fitzroy/circleci-tf-test/tree/$(git rev-parse --abbrev-ref HEAD)
