#!/bin/bash -x

package=$1
if [[ -z "$package" ]]; then
  echo "usage: $0 <package-name>"
  exit 1
fi
if [[ "$package" == */* ]]; then
  package_split=(${package//\// })
  package_name=${package_split[${#package_split[@]}-1]}
else
  package_name=$package
fi

platforms=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64")

for platform in "${platforms[@]}"
do
	platform_split=(${platform//\// })
	GOOS=${platform_split[0]}
	GOARCH=${platform_split[1]}

	# Map architecture names for output filename
  arch_name=$GOARCH
  if [ "$GOARCH" = "amd64" ]; then
    arch_name="x86_64"
  elif [ "$GOARCH" = "arm64" ]; then
    arch_name="aarch64"
  fi

  output_name=$package_name'-'$GOOS'-'$arch_name
	if [ $GOOS = "windows" ]; then
		output_name+='.exe'
	fi

  echo "Building for $platform"
	env GOOS=$GOOS GOARCH=$GOARCH go build -o $output_name $package
	if [ $? -ne 0 ]; then
   		echo 'An error has occurred! Aborting the script execution...'
		exit 1
	fi
done