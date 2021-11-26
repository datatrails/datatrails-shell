#!/usr/bin/env bash
#
# Scrape a docker image and upload as public or private SBOM file 
#
# Preparation:
#
# Install syft  - https://github.com/anchore/syft
# 
#    Read the docs on syft usage.
#
# Create App registration called "SBOM scraper" following the flow described in
# https://docs.rkvst.com/docs/setup-and-administration/getting-access-tokens-using-app-registrations/#using-the-rkvst-ui-(required-for-first-time-setup)
# and note down the CLIENT_ID and SECRET.
#
# Copy the SECRET generated to the file specified by ${CLIENTSECRET_FILE} below. This
# file should reside in a subdirectory with 0600 permissions.
#
# Use the CLIENT_ID as the first fixed argument to this script.
# 

SCRIPTNAME=$(basename "$0")

SYFT=$(which syft)
if [ -z "${SYFT}" ]
then
    echo "syft command not found"
    exit 10
fi
JQ=$(which jq)
if [ -z "${JQ}" ]
then
    JQ="cat"
else
    JQ="jq ."
fi

set -e
set -u

LOGTAG=$$
log() {
    echo "${LOGTAG}:$(date --rfc-3339=seconds):$* ..."
}

# defaults
FORMAT=cyclonedx

# credentials directory has 0600 permissions
CLIENTSECRET_FILE=credentials/client_secret
SBOM=false
PRIVACY=PUBLIC

URL=https://app.rkvst.io

usage() {
    cat >&2 <<EOF

Scrape an SBOM from a docker image and upload to abom archivist

Usage: $SCRIPTNAME [-p] [-c clientsecretfile] [-o output format] [-s sbomFile ] [-u url] client_id [docker-image|sbom file]

   -c clientsecretfile containing client secret (default ${CLIENTSECRET_FILE})
   -o FORMAT           default ($FORMAT) [cyclonedx]
   -s                  default ($SBOM) if specified the second argument is an sbom file
                       and -o is ignored.
   -p                  upload private SBOM
   -u URL              URL Default ($URL)

Example:

    $0 29b48af4-45ca-465b-b136-206674f8aa9b ubuntu:21.10

EOF

    exit 1
}

while getopts "c:ho:psu:" o; do
    case "${o}" in
        c) CLIENTSECRET_FILE="${OPTARG}"
           ;;
        o) FORMAT=${OPTARG}
           ;;
        p) PRIVACY=PRIVATE
           ;;
        s) SBOM=true
           ;;
        u) URL=$OPTARG
           ;;
        *)
           usage
           ;;
    esac
done
shift $((OPTIND-1))

[ $# -lt 1 ] && usage
CLIENT_ID=$1
shift 1
[ $# -lt 1 ] && usage
DOCKER_IMAGE=$1
shift 1

[ $# -ge 1 ] && usage

# ----------------------------------------------------------------------------
# Setup exit handling and temporary directory
# ----------------------------------------------------------------------------
TEMPDIR=$( mktemp -d /tmp/.sbom_scraper.XXXXXXXX )

# report on exit
function finalise {
    CODE=$?
    rm -rf "$TEMPDIR"
    exit $CODE
}
trap finalise EXIT INT TERM

OUTFILE=$(echo "${DOCKER_IMAGE}" | tr '/:' '-').${FORMAT}.sbom

# ----------------------------------------------------------------------------
# Extract client secrets
# ----------------------------------------------------------------------------
if [ ! -s "${CLIENTSECRET_FILE}" ]
then
    log "${CLIENTSECRET_FILE} does not exist or is empty"
    exit 1
fi
SECRET=$(cat "${CLIENTSECRET_FILE}")

# ----------------------------------------------------------------------------
# Extract SBOM
# ----------------------------------------------------------------------------
if [ "${SBOM}" = "false" ]
then
    log "Scrape ${FORMAT} SBOM from ${DOCKER_IMAGE} to ${OUTFILE}..."
    OUTPUT="${TEMPDIR}/${OUTFILE}"
    ${SYFT} -q packages -o "${FORMAT}" "${DOCKER_IMAGE}"> "${OUTPUT}"
else
    OUTPUT="${DOCKER_IMAGE}"
fi

# ----------------------------------------------------------------------------
# Handle client id and secrets for SBOM scraper via App registrations
# ----------------------------------------------------------------------------
HTTP_STATUS=""
# get token
log "Get token"
HTTP_STATUS=$(curl -sS -w "%{http_code}" \
    -o "${TEMPDIR}/access_token" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${SECRET}" \
    "${URL}/archivist/iam/v1/appidp/token")
if [ "${HTTP_STATUS}" != "200" ]
then
    log "Get token failure ${HTTP_STATUS}"
    exit 2
fi

TOKEN=$(jq -r .access_token "${TEMPDIR}"/access_token )

# create token file
BEARER_TOKEN_FILE=${TEMPDIR}/token
cat > "${BEARER_TOKEN_FILE}" <<EOF
Authorization: Bearer $TOKEN
EOF
#
# ----------------------------------------------------------------------------
# Upload SBOM
# ----------------------------------------------------------------------------
log "Upload ${PRIVACY} ${OUTPUT}"

HTTP_STATUS=$(curl -s -w "%{http_code}" -X POST \
    -o "${TEMPDIR}/upload" \
    -H "@${BEARER_TOKEN_FILE}" \
    -H "content_type=text/xml" \
    -F "sbom=@${OUTPUT}" \
    "${URL}/archivist/v1/sboms?privacy=${PRIVACY}")

if [ "${HTTP_STATUS}" != "200" ]
then
    log "Upload failure ${HTTP_STATUS}"
    exit 4
fi
log "Upload success: "
${JQ} "${TEMPDIR}/upload"
exit 0
