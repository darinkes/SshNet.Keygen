#!/usr/bin/env bash
set -ex

function gen_key {
	filename=$1
	t=$2
	bits=$3
	pass=$4

	[ -n "$pass" ] && filename=$filename.encrypted
	[ -n "$bits" ] && bits="-b $bits"
	ssh-keygen -t $t $bits -N "$pass" -C '' -f $filename -m RFC4716
	for h in md5 sha1 sha256 sha384 sha512; do
		cat $filename.pub | ssh-keygen -l -E $h -f - | sed 's/no comment//' > $filename.fingerprint.$h
	done
}

for p in '' '12345'; do
	# RSA
	for b in 2048 3072 4096 8192; do
		gen_key RSA$b RSA $b $p
	done
	# ECDSA
	for b in 256 384 521; do
		gen_key ECDSA$b ecdsa $b $p
	done
	# ED25519
	gen_key ED25519 ed25519 '' $p
done
