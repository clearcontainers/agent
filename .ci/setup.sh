#!/bin/bash
#
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script will clone `clearcontainers/tests` repository and 
# will use the CI scripts that live in that repository to create 
# a proper environment (Installing dependencies and building the
# components) to test the Clear Containers project 

set -e
set -x

# Retrieve OS information
source /etc/os-release

script_dir=$(dirname $(readlink -f "$0"))
source "${script_dir}/ci-common.sh"

export github_project="github.com/clearcontainers/agent"
export project_dir="${GOPATH}/src/${github_project}"

export test_repo="github.com/clearcontainers/tests"
export test_repo_dir="${GOPATH}/src/${test_repo}"

export RACE_DETECTION=true

# Clone Tests repository.
go get "$test_repo"

# Install libudev-dev required for go-udev vendor dependency
if [ "$ID" == fedora ]
then
	sudo dnf install -y libudev-devel
elif [ "$ID" == ubuntu ]
then
	sudo apt-get install -y libudev-dev
fi

# Check the commits in the branch
checkcommits_dir="${test_repo_dir}/cmd/checkcommits"
(cd "${checkcommits_dir}" && make)
checkcommits \
	--need-fixes \
	--need-sign-offs \
	--body-length 72 \
	--subject-length 75 \
	--ignore-fixes-for-subsystem "release" \
	--verbose

pushd "${test_repo_dir}"
sudo -E PATH=$PATH bash -c ".ci/setup.sh"
popd

# Make sure we have the package dependencies this project needs to be built.
# In semaphoreci the agent repo is already on the Semaphore system
# at the commit version we want to test.
# Note: this won't move the commit version (which is what we want).
go get -d ${github_project} || true
pushd ${project_dir}
echo "Build ${github_project}"
make -j$(nproc)
popd

#Verify Clear Containers installation is working
docker info | grep 'Default Runtime: cc-runtime'

#Install agent in last image
clr_dl_site="https://download.clearlinux.org"
clr_release=$(curl -L "${clr_dl_site}/latest")
MOUNT_DIR="$(pwd)/mount_dir"

# Download last container image
if [ ! -f "clear-${clr_release}-containers.img.xz" ] ;then
	curl -OL "${clr_dl_site}/releases/${clr_release}/clear/clear-${clr_release}-containers.img.xz"
fi

if [ ! -f "clear-${clr_release}-containers.img" ] ;then
	unxz clear-${clr_release}-containers.img.xz
fi

#Mount clear-containers image
mkdir -p ${MOUNT_DIR}
loop=$(sudo losetup -f --show "clear-${clr_release}-containers.img")
sudo partprobe ${loop}
sudo mount "${loop}p1" "${MOUNT_DIR}"

DESTDIR=${MOUNT_DIR}
sudo -E PATH=$PATH bash -c "make install DESTDIR=${MOUNT_DIR}"

sudo umount "${MOUNT_DIR}"
sudo losetup -d "${loop}"

#Change conatiner image symlink to use last agent
sudo ln -sf "$(pwd)/clear-${clr_release}-containers.img" "${cc_image_path}"
