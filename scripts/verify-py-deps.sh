#! /bin/bash

#echo "Verifying Python requirements ..."
proj_dir=$(pwd)
while read -r fname; do
    #echo "Processing '$fname' ..."
    folder=$(dirname "$fname")
    pushd "$folder" >/dev/null || exit 1
    if ! diff -q <(pipenv requirements) ./requirements.txt 2> /dev/null >/dev/null; then
        echo "'$folder/requirements.txt' dependencies do not match '$folder/Pipfile.lock' dependencies."
        echo "Please cd to '$folder' and run 'pipenv requirements > requirements.txt'."
        exit 1
    fi
    popd >/dev/null || exit 1
done < <(find "$proj_dir" -iname 'Pipfile.lock' -not -path "$proj_dir"'/cdk.out/*')
exit 0
