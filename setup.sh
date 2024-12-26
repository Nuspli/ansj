#!/bin/bash

echo "checking if the script is running as root ..."
if [ "$EUID" -ne 0 ]
    then echo "fail: please run as root"
    exit
fi

echo "checking if the user ctf exists ..."
if id "ctf" &>/dev/null; then
    uid=$(id -u ctf)
    echo "... user ctf exists with uid $uid"
else
    echo "creating user ctf:ctf ..."
    useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
    uid=$(id -u ctf)
fi

echo "checking if ./challenges exists ..."
if [ ! -d "./challenges" ]; then
    echo "... creating ./challenges"
    mkdir ./challenges
fi

# config format:
# :key:dirname_in_challenges:file_in_dir_to_exec:timeout_in_seconds:flag_path_in_jail:flag:challenge_file_dir_path_in_jail:
# example:
# :bash:default:bash:120:/flag:flag{default}:/challenge:
# all files in ./challenges/default will be copied to /challenge in the jail.
# ./challenges/default/bash will be executed in the jail (as /challenge/bash)

echo "checking if config exists ..."
if [ ! -f "./config" ]; then
    echo "... creating ./config"
    echo "... creating default challenge entry ..."
    echo "... ... key          : bash"
    echo "... ... dir name     : default"
    echo "... ... file to exec : bash"
    echo "... ... timeout      : 120"
    echo "... ... flag path    : /flag"
    echo "... ... flag         : flag{default}"
    echo "... ... challenge dir: /challenge"
    echo ":bash:default:bash:120:/flag:flag{default}:/challenge:" > ./config
    echo "... creating default challenge file"
    mkdir ./challenges/default
    ln -s /bin/bash ./challenges/default/bash
fi

echo "all set."
