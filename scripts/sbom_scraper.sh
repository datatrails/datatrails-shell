#!/usr/bin/env bash
#
# Scrape a docker image and upload as public (default) or private SBOM file 
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
# file should reside in a subdirectory with 0700 permissions.
#
# Use the CLIENT_ID as the first fixed argument to this script.
# 

SCRIPTNAME=$(basename "$0")

for TOOL in syft jq xq xmllint python3 openssl curl shasum
do
    if ! type $TOOL > /dev/null
    then
        echo >&2 "please make sure this tool is on your PATH"
        exit 10
    fi
done

set -e
set -u

LOGTAG=$$
log() {
    echo "${LOGTAG}:$(date):$*"
}

# ----------------------------------------------------------------------------
# Option parsing
# ----------------------------------------------------------------------------

# Prepare defaults
if type git > /dev/null 2>&1 && git rev-parse --git-dir > /dev/null 2>&1
then
    # we are in a git repo so set defaults using git
    GIT_STATUS=$(git status --porcelain)

    AUTHOR_NAME="$(git config user.name || echo "$USER")"
    AUTHOR_EMAIL="$(git config user.email || true)"
    TOOL_NAME="$(git config --get remote.origin.url) $(git ls-files --full-name "$SCRIPTNAME")"
    TOOL_VERSION=$(git describe --tags)${GIT_STATUS:++}
else
    AUTHOR_NAME="$USER"
    AUTHOR_EMAIL=""
    TOOL_NAME="$SCRIPTNAME"
    TOOL_VERSION="unknown"
fi

FORMAT=cyclonedx
COMPONENT_AUTHOR_NAME="$AUTHOR_NAME"
SUPPLIER_NAME=dockerhub
SUPPLIER_URL=https://hub.docker.com
TOOL_VENDOR="Jitsuin Inc"
TOOL_HASH_ALG=SHA-256
# shellcheck disable=SC2002
TOOL_HASH_CONTENT=$(shasum -a 256 "$0" | cut -d' ' -f1)
# credentials directory should have 0700 permissions
CLIENTSECRET_FILE=credentials/client_secret
SBOM=false
PRIVACY=PUBLIC

URL=https://app.rkvst.io

usage() {
    cat >&2 <<EOF

Create a Cyclone DX 1.2 XML SBOM from a docker image and upload to RKVST SBOM Hub

Usage: $SCRIPTNAME [-a AUTHOR_NAME] [-A AUTHOR_NAME] [-c CLIENT_SECRET_FILE] [-e AUTHOR_EMAIL] [-s] [-p] [-u URL] CLIENT_ID [docker-image:tag|sbom file]

   -a AUTHOR             name of the author of the SBOM.  Default ($AUTHOR_NAME)
   -A COMPONENT_AUTHOR   name of the author and publisher of the docker image.  Default ($COMPONENT_AUTHOR_NAME)
   -c CLIENT_SECRET_FILE containing client secret (default ${CLIENTSECRET_FILE})
   -e AUTHOR_EMAIL       email address of the author of the SBOM.  Default ($AUTHOR_EMAIL)
   -s                    if specified the second argument is an sbom file.
                         Default ($SBOM) 
   -p                    upload private SBOM
   -u URL                URL of archivist SBOM hub. Default ($URL)

Examples:

    $0 29b48af4-45ca-465b-b136-206674f8aa9b ubuntu:21.10
    $0 -s 29b48af4-45ca-465b-b136-206674f8aa9b ./my-sbom.xml

EOF

    exit 1
}

while getopts "a:A:c:e:hpsu:" o; do
    case "${o}" in
        a) AUTHOR_NAME="${OPTARG}"
           ;;
        A) COMPONENT_AUTHOR_NAME="${OPTARG}"
           ;;
        c) CLIENTSECRET_FILE="${OPTARG}"
           ;;
        e) AUTHOR_EMAIL="${OPTARG}"
           ;;
        p) PRIVACY=PRIVATE
           ;;
        s) SBOM=true
           ;;
        u) URL="$OPTARG"
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
    log "Scrape ${FORMAT} SBOM from ${DOCKER_IMAGE} to ${OUTFILE} ..."
    OUTPUT="${TEMPDIR}/${OUTFILE}"
    syft -q packages -o "${FORMAT}" "${DOCKER_IMAGE}"> "${OUTPUT}"
else
    OUTPUT="${DOCKER_IMAGE}"
fi

# ----------------------------------------------------------------------------
# Update SBOM including NTIA minimum elments
# ----------------------------------------------------------------------------
ORIG_COMPONENT_NAME=$(xq -r .bom.metadata.component.name "$OUTPUT")
ORIG_COMPONENT_VERSION=$(xq -r .bom.metadata.component.version "$OUTPUT")
COMPONENT_NAME=${ORIG_COMPONENT_NAME%%:*}
COMPONENT_VERSION=${ORIG_COMPONENT_NAME##*:}
HASH_ALG="${ORIG_COMPONENT_VERSION%%:*}"
case ${HASH_ALG^^} in
  SHA256) COMPONENT_HASH_ALG="SHA-256"
          ;;
  *)      echo >&2 "Unknonwn hash algorithm $HASH_ALG"
esac
COMPONENT_HASH_CONTENT="${ORIG_COMPONENT_VERSION##*:}"

echo "metadata:"
echo "  tools:"
echo "    tool:"
echo "      vendor: $TOOL_VENDOR"
echo "      name: $TOOL_NAME"
echo "      version: $TOOL_VERSION"
echo "      hashes:"
echo "        hash:"
echo "          alg: $TOOL_HASH_ALG"
echo "          content: $TOOL_HASH_CONTENT"
echo "  authors:"
echo "    author:"
echo "      name: $AUTHOR_NAME"
echo "      email: $AUTHOR_EMAIL"
echo "  component:"
echo "    supplier:"
echo "      name: $SUPPLIER_NAME"
echo "      url: $SUPPLIER_URL"
echo "    author: $COMPONENT_AUTHOR_NAME"
echo "    publisher: $COMPONENT_AUTHOR_NAME"
echo "    name: $ORIG_COMPONENT_NAME -> $COMPONENT_NAME"
echo "    version: $ORIG_COMPONENT_VERSION -> $COMPONENT_VERSION"
echo "    hashes:"
echo "      hash:"
echo "        alg: $COMPONENT_HASH_ALG"
echo "        content: $COMPONENT_HASH_CONTENT"

[ -z "$TOOL_VENDOR" ] && echo >&2 "Unable to determine SBOM tool vendor" && exit 1
[ -z "$TOOL_NAME" ] && echo >&2 "Unable to determine SBOM tool name" && exit 1
[ -z "$TOOL_HASH_ALG" ] && echo >&2 "Unable to determine SBOM tool hash algorithm" && exit 1
[ -z "$TOOL_HASH_CONTENT" ] && echo >&2 "Unable to determine SBOM tool hash content" && exit 1
[ -z "$AUTHOR_NAME" ] && echo >&2 "Unable to determine SBOM author name" && exit 1
[ -z "$SUPPLIER_NAME" ] && echo >&2 "Unable to determine component supplier name" && exit 1
[ -z "$SUPPLIER_URL" ] && echo >&2 "Unable to determine component supplier url" && exit 1
[ -z "$COMPONENT_AUTHOR_NAME" ] && echo >&2 "Unable to determine component author name" && exit 1
[ -z "$COMPONENT_NAME" ] && echo >&2 "Unable to determine component name" && exit 1
[ -z "$COMPONENT_VERSION" ] && echo >&2 "Unable to determine component version" && exit 1
[ -z "$COMPONENT_HASH_ALG" ] && echo >&2 "Unable to determine component hash algorithm" && exit 1
[ -z "$COMPONENT_HASH_CONTENT" ] && echo >&2 "Unable to determine component hash content" && exit 1

PATCHED_OUTPUT="${OUTPUT}.patched"

python3 <(cat <<END
import sys
import xml.etree.ElementTree as ET

def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

ET.register_namespace('', 'http://cyclonedx.org/schema/bom/1.2')
ns = {'': 'http://cyclonedx.org/schema/bom/1.2'}

# Open original file
et = ET.parse(sys.stdin)
root = et.getroot()

metadata = root.find('metadata', ns)

# Add this tool
tools = metadata.find('tools', ns)
if not tools:
    tools = ET.SubElement(metadata, 'tools')
tool = ET.SubElement(tools, 'tool')
ET.SubElement(tool, 'vendor').text = '$TOOL_VENDOR'
ET.SubElement(tool, 'name').text = '$TOOL_NAME'
ET.SubElement(tool, 'version').text = '$TOOL_VERSION'
hashes = ET.SubElement(tool, 'hashes')
hash = ET.SubElement(hashes, 'hash', alg='${TOOL_HASH_ALG}')
hash.text = '$TOOL_HASH_CONTENT'

# Add sbom authors elements
authors = metadata.find('authors', ns)
if not authors:
    authors = ET.Element('authors')
    metadata.insert(2, authors)
author = ET.SubElement(authors, 'author')
ET.SubElement(author, 'name').text = '$AUTHOR_NAME'
ET.SubElement(author, 'email').text = '$AUTHOR_EMAIL'

component = metadata.find('component', ns)

# Update component publisher and author
publisher = component.find('publisher', ns)
if not publisher:
    publisher = ET.Element('publisher')
    component.insert(0, publisher)
publisher.text = '$COMPONENT_AUTHOR_NAME'
author = component.find('author', ns)
if not author:
    author = ET.Element('author')
    component.insert(0, author)
author.text = '$COMPONENT_AUTHOR_NAME'

# Update component name and version
component.find('name', ns).text = '$COMPONENT_NAME'
component.find('version', ns).text = '$COMPONENT_VERSION'

# Update component hash
hashes = component.find('hashes', ns)
if not hashes:
    hashes = ET.SubElement(component, 'hashes')
hash = ET.SubElement(hashes, 'hash', alg='${COMPONENT_HASH_ALG}')
hash.text = '$COMPONENT_HASH_CONTENT'

# Add component supplier
supplier = component.find('supplier', ns)
if not supplier:
    supplier = ET.Element('supplier')
    component.insert(0, supplier)
ET.SubElement(supplier, 'name').text = '$SUPPLIER_NAME'
ET.SubElement(supplier, 'url').text = '$SUPPLIER_URL'

# Add supplier (it appears twice in the schema)
supplier = metadata.find('supplier', ns)
if not supplier:
    supplier = ET.SubElement(metadata, 'supplier')
ET.SubElement(supplier, 'name').text = '$SUPPLIER_NAME'
ET.SubElement(supplier, 'url').text = '$SUPPLIER_URL'

indent(root)

et.write(sys.stdout, encoding='unicode', xml_declaration=True, default_namespace='')
END
) < "$OUTPUT" > "$PATCHED_OUTPUT"

# ----------------------------------------------------------------------------
# Check that the patched SBOM is valid against the cyclonedx schema
# ----------------------------------------------------------------------------
[ -f spdx.xsd ] || curl -fsS -o spdx.xsd https://cyclonedx.org/schema/spdx
[ -f cyclonedx.xsd ] || curl -fsS -o cyclonedx.xsd https://cyclonedx.org/schema/bom/1.2

# xmllint complains about a double import of the spdx schema, but we have to import via
# the wrapper to set the schema location to a local file, as xmllint fails to download
# them from the internet as they are https
xmllint "$PATCHED_OUTPUT" --schema cyclonedx-wrapper.xsd --noout 2>&1 | grep -Fv "Skipping import of schema located at 'http://cyclonedx.org/schema/spdx' for the namespace 'http://cyclonedx.org/schema/spdx'"
[ "${PIPESTATUS[0]}" -ne 0 ] && exit "${PIPESTATUS[0]}"

# ----------------------------------------------------------------------------
# Handle client id and secrets for SBOM scraper via App registrations
# ----------------------------------------------------------------------------
HTTP_STATUS=""
# get token
log "Get token ..."
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
log "Upload ${PRIVACY} ${OUTPUT} ..."

HTTP_STATUS=$(curl -s -w "%{http_code}" -X POST \
    -o "${TEMPDIR}/upload" \
    -H "@${BEARER_TOKEN_FILE}" \
    -H "content_type=text/xml" \
    -F "sbom=@${PATCHED_OUTPUT}" \
    "${URL}/archivist/v1/sboms?privacy=${PRIVACY}")

if [ "${HTTP_STATUS}" != "200" ]
then
    log "Upload failure ${HTTP_STATUS}"
    exit 4
fi
log "Upload success: "
jq . "${TEMPDIR}/upload"
exit 0
