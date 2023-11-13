#!/bin/bash
set -eu

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SCRIPTNAME=$(basename "$0")

AUTHORITY="test"
ARCHIVIST_HOST="app.datatrails.ai"
TLSARCHIVIST_HOST="auth.$ARCHIVIST_HOST"

# check that the required tools are installed
type curl 2>/dev/null || ( echo >&2 "curl command not found, please install or add to PATH" && exit 1 )

usage() {
    cat >&2 <<EOF

Create and configure a TLS certificate authority and TLS client certificate for
use with DataTrails

Usage: $SCRIPTNAME [-a AUTHORITY] COMMON_NAME

    -a AUTHORITY    CN for certificate authority (default '$AUTHORITY')

    Note that a uuid is appendede to the AUTHORITY when creating the CA
    certification Common Name as they must be unique

    Creates a tarball (named [COMMON_NAME].tar.gz) containing the resulting
    client key and certificate

EOF
    exit 1
}

while getopts ":a:" o; do
    case "${o}" in
        a)  AUTHORITY="$OPTARG"
            ;;
        *)  usage
            ;;
    esac
done
shift $((OPTIND-1))

# check args
[ $# -eq 1 ] || ( echo >&2 "Must supply common name" && exit 1 )

COMMON_NAME="$1"
shift

echo "Checking certficate authority..."
[ -f "$AUTHORITY-ca.pem" ] || "$SCRIPTDIR"/certificateauth.sh gen-ca "$AUTHORITY-ca"

echo "Checking user cert..."
[ -f "$COMMON_NAME-client.pem" ] || "$SCRIPTDIR"/certificateauth.sh gen-client "$COMMON_NAME-client" "$AUTHORITY-ca"

echo "Verifying that certs are coherent"
"$SCRIPTDIR"/certificateauth.sh verify "$COMMON_NAME-client" "$AUTHORITY-ca"

echo "Add root cert ($AUTHORITY-ca.pem) to archivist and press any key to continue ..."
read -r

echo "Testing client cert"

curl -fSs --cert "$COMMON_NAME-client.pem" --key "$COMMON_NAME-client.key" \
    -H "Content-Type: application/json" \
    https://$TLSARCHIVIST_HOST/archivist/v2/assets

echo
echo

echo "Done - client key: $COMMON_NAME-client.key  certificate: $COMMON_NAME-client.pem"
