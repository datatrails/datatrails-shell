#!/bin/bash

set -eu

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SCRIPTNAME=$(basename "$0")

# check that the required tools are installed
type openssl 2>/dev/null || ( echo >&2 "openssl command not found, please install or add to PATH" && exit 1 )

case $1 in
	gen-ca)
		openssl req \
			-config "$SCRIPTDIR/combined.cnf" \
			-newkey rsa:4096 \
			-sha256 \
			-keyform PEM \
			-keyout "$2.key" \
			-nodes \
			-x509 \
			-days 3650 \
			-outform PEM \
			-out "$2.pem" \
			-subj "/C=GB/CN=$2-$(uuidgen)" \
			-extensions x509v3_CA
		;;
	gen-client)
		openssl genrsa \
			-out "$2.key" \
			2048
		openssl req \
			-new \
			-key "$2.key" \
			-out "$2.req" \
			-sha256 \
			-nodes \
			-subj "/C=GB/CN=$2"
		openssl x509 \
			-req \
			-in "$2.req" \
			-sha256 \
			-CA "$3.pem" \
			-CAkey "$3.key" \
			-set_serial 101 \
			-extensions client \
			-days 365 \
			-outform PEM \
			-out "$2.pem"
		;;

	print)
		openssl x509 \
			-in "$2.pem" \
			-text
		;;

	verify)
		openssl verify \
			-CAfile "$3.pem" \
			"$2.pem"
		;;

	*) echo >&2 "Usage: $SCRIPTNAME (gen-ca NAME | gen-client NAME CANAME | print NAME | verify NAME CANAME)" && exit 1
esac
