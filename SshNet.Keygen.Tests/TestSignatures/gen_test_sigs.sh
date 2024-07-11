#!/usr/bin/env bash
set -ex

function gen_sig {
	key=$1

	rm -f file.txt.sig
	cp ../TestKeys/$key key
	chmod 0600 key
	ssh-keygen -Y sign -f key -n file file.txt
	mv file.txt.sig file.txt.$key.sig
}

# RSA
for b in 2048 3072 4096 8192; do
	gen_sig RSA$b
done
# ECDSA
for b in 256 384 521; do
	gen_sig ECDSA$b
done
# ED25519
gen_sig ED25519
