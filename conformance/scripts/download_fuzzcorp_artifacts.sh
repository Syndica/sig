#!/bin/bash
# This script grabs the requisite solfuzz .so's from GitHub Artifacts and collects head_branch and head_sha.
set -e

repo_solfuzz="firedancer-io/solfuzz"
repo_agave="firedancer-io/solfuzz-agave"

repos=("$repo_agave" "$repo_solfuzz")
artifacts_agave=("libsolfuzz-agave.so")
artifacts_solfuzz=("solfuzz-bins-regular")

# Associate repos with their corresponding artifacts lists
declare -A repo_artifacts
repo_artifacts["$repo_agave"]="${artifacts_agave[@]}"
repo_artifacts["$repo_solfuzz"]="${artifacts_solfuzz[@]}"

mkdir -p temp/

for repo in "${repos[@]}"; do
    artifact_names=(${repo_artifacts[$repo]})
    
    for artifact_name in "${artifact_names[@]}"; do
        # Get the list of artifacts for the repository
        artifacts_url="https://api.github.com/repos/$repo/actions/artifacts"
        echo $artifacts_url
        artifacts_response=$(curl -s -H "Authorization: Bearer $PAT" \
                            -H "Accept: application/vnd.github+json" \
                            -H "X-GitHub-Api-Version: 2022-11-28" \
                            "$artifacts_url")

        # Check if the API request was successful
        if [ $? -ne 0 ]; then
            echo "Failed to retrieve the list of artifacts for repository $repo"
            continue
        fi
        echo "Got artifacts response for ${artifact_name}"
        echo "$artifacts_response"
        # Find the artifact with the desired name and extract relevant information
        artifact_info=$(echo "$artifacts_response" | jq -r ".artifacts | sort_by(.created_at) | reverse | .[] | select(.name == \"$artifact_name\") | {id: .id, head_branch: .workflow_run.head_branch, head_sha: .workflow_run.head_sha}" | head -n 5)

        artifact_id=$(echo "$artifact_info" | jq -r ".id")
        head_branch=$(echo "$artifact_info" | jq -r ".head_branch")
        head_sha=$(echo "$artifact_info" | jq -r ".head_sha")

        # Check if the artifact was found
        if [ -z "$artifact_id" ]; then
            echo "Artifact with name '$artifact_name' not found in repository $repo"
            continue
        fi

        echo "Found artifact ID: $artifact_id for repository $repo"
        echo "Head branch: $head_branch"
        echo "Head SHA: $head_sha"

        # Get the artifact details
        artifact_url="https://api.github.com/repos/$repo/actions/artifacts/$artifact_id"
        artifact_response=$(curl -s -H "Authorization: Bearer $PAT" "$artifact_url")

        # Check if the API request was successful
        if [ $? -ne 0 ]; then
            echo "Failed to retrieve the artifact details for repository $repo"
            continue
        fi

        # Extract the artifact download URL
        download_url=$(echo "$artifact_response" | jq -r ".archive_download_url")

        echo "Downloading artifact '$artifact_name' from repository $repo..."
        echo $download_url
        # Download the artifact to ./test/lib directory
        curl -s -L -H "Authorization: Bearer $PAT" -o "./temp/$artifact_name.zip" "$download_url"
        # echo the name and hash to file in same dir for later usage in bundle-for-fuzzcorp
        echo $head_sha > ./temp/$artifact_name.hash

        # Check if the artifact download was successful
        if [ $? -ne 0 ]; then
            echo "Failed to download artifact '$artifact_name.zip' from repository $repo"
        else
            echo "Artifact '$artifact_name.zip' downloaded successfully from repository $repo"
            # now we need to unzip this in-place
            cd ./temp/ && ls $artifact_name* && file $artifact_name* && unzip $artifact_name.zip && cd -
            chmod +x ./temp/*.so
            rm ./temp/$artifact_name.zip
        fi
    done
done
