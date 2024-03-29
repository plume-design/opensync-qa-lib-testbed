#!/usr/bin/env bash

get_container_name_for_jenkins_job()
{
    echo "$JOB_BASE_NAME-$BUILD_ID" | sed 's/[^a-zA-Z0-9_-]//g'
}

kill_jenkins_job_container_name()
{
    local CONTAINER_NAME=$(get_container_name_for_jenkins_job)
    local CONTAINER_ID=`docker ps -f name=$CONTAINER_NAME -q`

    if [ -n "$CONTAINER_ID" ]; then
        echo "Killing container '$CONTAINER_ID' ..."
        docker kill $CONTAINER_ID
    else
        echo "Container ID for name '$CONTAINER_NAME' not found."
    fi
}
