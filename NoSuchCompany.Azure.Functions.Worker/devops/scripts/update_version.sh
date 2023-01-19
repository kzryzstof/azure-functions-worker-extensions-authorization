#!/bin/bash

echo "Updating the version to $1 for files in $PWD"

newVersion=$1
for assemblyInfoFile in $( find ../. -name "AssemblyInfo.cs" ); do
    echo "Editing file: $assemblyInfoFile $newVersion"
	cmd="ed -s $assemblyInfoFile <<< $'H\n,s/\"1.0.0\"/\"$newVersion\"/g\nw'"
	echo $cmd
	eval $cmd
done

exit 0

