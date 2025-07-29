#!/bin/bash
set -e

# Specifically this commit of solfuzz-agave: e3bced475fda09b253748e73f9c095d323d0c49c
# TODO: update the sig-fuzz fixtures to work with the latest agave
artifact_id=3480947062
artifact_name="libsolfuzz-agave.so"

artifacts_url="https://api.github.com/repos/firedancer-io/solfuzz-agave/actions/artifacts"
echo $artifacts_url
artifacts_response=$(curl -s -H "Authorization: Bearer $PAT" \
                    -H "Accept: application/vnd.github+json" \
                    -H "X-GitHub-Api-Version: 2022-11-28" \
                    "$artifacts_url")

if [ $? -ne 0 ]; then
    echo "Failed to retrieve the list of artifacts for repository $repo"
    continue
fi
echo "Got artifacts response for ${artifact_name}"
echo "$artifacts_response"

artifact_url="https://api.github.com/repos/firedancer-io/solfuzz-agave/actions/artifacts/$artifact_id"
artifact_response=$(curl -s -H "Authorization: Bearer $PAT" "$artifact_url")

if [ $? -ne 0 ]; then
    echo "Failed to retrieve the artifact details for repository $repo"
    continue
fi

download_url=$(echo "$artifact_response" | jq -r ".archive_download_url")

echo "Downloading artifact '$artifact_name' from repository $repo..."
echo $download_url
curl -s -L -H "Authorization: Bearer $PAT" -o "./$artifact_name.zip" "$download_url"

if [ $? -ne 0 ]; then
    echo "Failed to download artifact '$artifact_name.zip' from repository $repo"
else
    echo "Artifact '$artifact_name.zip' downloaded successfully from repository $repo"
    ls $artifact_name* && file $artifact_name* && unzip $artifact_name.zip
    chmod +x ./*.so
    rm ./$artifact_name.zip
fi
