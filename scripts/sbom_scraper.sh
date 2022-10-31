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

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SCRIPTNAME=$(basename "$0")
#
# cdx - https://github.com/CycloneDX/cyclonedx-cli/releases/tag/v0.22.0
# jar, jdeps - sudo apt install default-jre
# syft - https://github.com/anchore/syft/releases/tag/v0.37.10
# jq - sudo apt install jq
# xq - python3 -m pip install --user yq
# xmllint - sudo apt install libxml2-utils
# python3 - should come with distro
# openssl - sudo apt install openssl
# curl - sudo apt install curl
NOTFOUND=0
for TOOL in cdx jar jdeps syft jq xq xmllint python3 openssl curl shasum
do
    if ! type $TOOL > /dev/null
    then
        echo >&2 "please make sure this tool is on your PATH"
	NOTFOUND=$((NOTFOUND + 1))
    fi
done
if [ "$NOTFOUND" -gt 0 ]
then
    echo >&2 "Some tools not found"
    exit 10
fi
SYFT_VERSION=$(syft version | grep '^Version' | tr -s ' ' | cut -d' ' -f2)
compare_version() {
    local x=$1
    first=${x%%.*}          # Delete first dot and what follows.
    last=${x##*.}           # Delete up to last dot.
    mid=${x##"$first".}       # Delete first number and dot.
    mid=${mid%%."$last"}      # Delete dot and last number.
    if [ "$mid" -lt 34 ]
    then
        echo >&2 "syft must be at least version 0.34.0"
        exit 10
    fi
}
compare_version "${SYFT_VERSION}"

set -e
set -u

LOGTAG=$$
log() {
    echo "${LOGTAG}:$(date):$*"
}

# ----------------------------------------------------------------------------
# Option parsing
# ----------------------------------------------------------------------------
TOOL_NAME="https://github.com/jitsuin-inc/archivist-shell $SCRIPTNAME"
#
# Set this value just before release
TOOL_VERSION="v0.3.5"
TOOL_VENDOR="RKVST Inc"
TOOL_HASH_ALG=SHA-256
TOOL_HASH_CONTENT=$(shasum -a 256 "$0" | cut -d' ' -f1)

DEFAULT_AUTHOR_NAME="$USER"
AUTHOR_NAME="$DEFAULT_AUTHOR_NAME"
AUTHOR_EMAIL=""

FORMAT=cyclonedx
COMPONENT_AUTHOR_NAME="$DEFAULT_AUTHOR_NAME"
SBOM_UPLOAD_TIMEOUT=10
# shellcheck disable=SC2002
# credentials directory should have 0700 permissions
CLIENTSECRET_FILE=$SCRIPTDIR/../credentials/client_secret
SBOM=false
PRIVACY=PUBLIC
JARFILE=false
UPLOAD=true

URL=https://app.rkvst.io

usage() {
    cat >&2 <<EOF

Create a Cyclone DX 1.3 XML SBOM from a docker image and upload to RKVST SBOM Hub

Usage: $SCRIPTNAME [-a AUTHOR_NAME] [-A COMPONENT_AUTHOR] [-c CLIENT_SECRET_FILE] [-e AUTHOR_EMAIL] [-sp] [-u URL] CLIENT_ID [docker-image:tag|sbom file|jar URL]

   -a AUTHOR             name of the author of the SBOM.  Default ($AUTHOR_NAME)
   -A COMPONENT_AUTHOR   name of the author and publisher of the docker image.  Default ($COMPONENT_AUTHOR_NAME)
   -c CLIENT_SECRET_FILE containing client secret (default ${CLIENTSECRET_FILE})
   -e AUTHOR_EMAIL       email address of the author of the SBOM.  Default ($AUTHOR_EMAIL)
   -s                    if specified the second argument is an sbom file.
   -n                    don't upload
                         Default ($SBOM) 
   -p                    upload private SBOM
   -u URL                URL of archivist SBOM hub. Default ($URL)

Examples:

    $0 29b48af4-45ca-465b-b136-206674f8aa9b ubuntu:21.10
    $0 -s 29b48af4-45ca-465b-b136-206674f8aa9b ./my-sbom.xml
    $0 -s 29b48af4-45ca-465b-b136-206674f8aa9b https://repo1.maven.org/maven2/org/assertj/assertj-core/1.0.0/assertj-core-1.0.0.jar

EOF

    exit 1
}

while getopts "a:A:c:e:hpnsu:" o; do
    case "${o}" in
        a) AUTHOR_NAME="${OPTARG}"
           ;;
        A) COMPONENT_AUTHOR_NAME="${OPTARG}"
           ;;
        c) CLIENTSECRET_FILE="${OPTARG}"
           ;;
        e) AUTHOR_EMAIL="${OPTARG}"
           ;;
        n) UPLOAD=false
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

[ $# -lt 1 ] && echo "No client id specified" && usage
CLIENT_ID=$1
shift 1
[ $# -lt 1 ] && echo "No source specified" && usage
SOURCE=$1
shift 1

[ $# -ge 1 ] && echo "Spurious positional arguments specified" && usage

if [ "${COMPONENT_AUTHOR_NAME}" = "${DEFAULT_AUTHOR_NAME}" ]
then
    COMPONENT_AUTHOR_NAME="${AUTHOR_NAME}"
fi

EXT=$(echo "${SOURCE}" | rev | cut -d '.' -f1 | rev | tr '[:upper:]' '[:lower:]')
if [ "$EXT" = "jar" ]
then
    JARFILE=true
    JARTYPE=$(echo "${SOURCE}" | cut -d':' -f1)
    if [ "${JARTYPE}" != "https" ]
    then
        echo "Jar file must be specified with https URL" && usage
    fi
fi
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

OUTFILE=$(echo "${SOURCE}" | tr '/:' '-').${FORMAT}.sbom

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
# Deal with jar files - the argument should be of form
# https://repo1.maven.org/maven2/org/assertj/assertj-core/1.0.0/assertj-core-1.0.0.jar
# ----------------------------------------------------------------------------
if [ "${JARFILE}" = "true" ]
then
    WORKDIR="${TEMPDIR}/jarfile"
    mkdir "${WORKDIR}"
    SUPPLIER_NAME=$(echo "${SOURCE}" | cut -d'/' -f4)
    SUPPLIER_URL=$(echo "${SOURCE}" | cut -d'/' -f1-4)
    (cd "${WORKDIR}" && curl -sSO "${SOURCE}")
    pushd "${WORKDIR}" > /dev/null
    INPUT=$(ls)
    OUTFILE=${INPUT}.${FORMAT}.sbom
    OUTPUT="${TEMPDIR}/${OUTFILE}"
    syftjar -q packages --scope all-layers -o "${FORMAT}" "file:${INPUT}" > "${OUTPUT}"
    popd > /dev/null

    COMPONENT_NAME=$(xq -r .bom.metadata.component.name "$OUTPUT")
    COMPONENT_VERSION=$(xq -r .bom.metadata.component.version  "${OUTPUT}")
    ORIG_COMPONENT_NAME=
    ORIG_COMPONENT_VERSION=
    COMPONENT_HASH_ALG=
    COMPONENT_HASH_CONTENT=
    if [ "$COMPONENT_VERSION" = "null" ]
    then
        echo "No pom.xml in archive. Skipping $COMPONENT_NAME"
        exit 3
    fi

    # handle case where syft didn't find sutable substitution for parametrised version number
    if [ "$COMPONENT_VERSION" = "\${parent.version}" ]
    then
        echo "syft could not get valid version from archive. Skipping $COMPONENT_NAME"
        exit 3
    fi

else
# ----------------------------------------------------------------------------
# Deal with dockerfiles - assume that raw sbom files originally came from
# docker image
# ----------------------------------------------------------------------------
    SUPPLIER_NAME=dockerhub
    SUPPLIER_URL=https://hub.docker.com
    if [ "${SBOM}" = "false" ]
    then
        log "Scrape ${FORMAT} SBOM from ${SOURCE} to ${OUTFILE} ..."
        OUTPUT="${TEMPDIR}/${OUTFILE}"
        syft -q packages --scope all-layers -o "${FORMAT}" "${SOURCE}"> "${OUTPUT}"
    else
        OUTPUT="${SOURCE}"
    fi

    ORIG_COMPONENT_NAME=$(xq -r .bom.metadata.component.name "$OUTPUT")
    ORIG_COMPONENT_VERSION=$(xq -r .bom.metadata.component.version "$OUTPUT")
    COMPONENT_NAME=${ORIG_COMPONENT_NAME%%:*}
    COMPONENT_VERSION=${ORIG_COMPONENT_NAME##*:}
    HASH_ALG="${ORIG_COMPONENT_VERSION%%:*}"
    case ${HASH_ALG^^} in
        SHA256) COMPONENT_HASH_ALG="SHA-256"
                ;;
        *)      echo >&2 "Unknown hash algorithm $HASH_ALG"
                ;;
    esac
    COMPONENT_HASH_CONTENT="${ORIG_COMPONENT_VERSION##*:}"
fi

if [ "$UPLOAD" = "true" ]
then

cat >&1 <<EOF
metadata:
  tools:
    tool:
      vendor: $TOOL_VENDOR
      name: $TOOL_NAME
      version: $TOOL_VERSION
      hashes:
        hash:
          alg: $TOOL_HASH_ALG
          content: $TOOL_HASH_CONTENT
  authors:
    author:
      name: $AUTHOR_NAME
      email: $AUTHOR_EMAIL
  component:
    supplier:
      name: $SUPPLIER_NAME
      url: $SUPPLIER_URL
    author: $COMPONENT_AUTHOR_NAME
    publisher: $COMPONENT_AUTHOR_NAME
    name: $ORIG_COMPONENT_NAME -> $COMPONENT_NAME
    version: $ORIG_COMPONENT_VERSION -> $COMPONENT_VERSION
    hashes:
      hash:
        alg: $COMPONENT_HASH_ALG
        content: $COMPONENT_HASH_CONTENT
EOF

fi

[ -z "$TOOL_VENDOR" ] && echo >&2 "Unable to determine SBOM tool vendor" && exit 1
[ -z "$TOOL_NAME" ] && echo >&2 "Unable to determine SBOM tool name" && exit 1
[ -z "$TOOL_HASH_ALG" ] && echo >&2 "Unable to determine SBOM tool hash algorithm" && exit 1
[ -z "$TOOL_HASH_CONTENT" ] && echo >&2 "Unable to determine SBOM tool hash content" && exit 1
[ -z "$AUTHOR_NAME" ] && echo >&2 "Unable to determine SBOM author name" && exit 1
[ -z "$SUPPLIER_NAME" ] && echo >&2 "Unable to determine component supplier name" && exit 1
[ -z "$SUPPLIER_URL" ] && echo >&2 "Unable to determine component supplier url" && exit 1
[ -z "$COMPONENT_AUTHOR_NAME" ] && echo >&2 "Unable to determine component author name" && exit 1
[ -z "$COMPONENT_NAME" ] && echo >&2 "Unable to determine component name" && exit 1

if [ -z "$COMPONENT_VERSION" ]
then
    [ -z "$COMPONENT_HASH_ALG" ] && echo >&2 "Unable to determine component version or hash algorithm" && exit 1
    [ -z "$COMPONENT_HASH_CONTENT" ] && echo >&2 "Unable to determine component hash content" && exit 1
fi
PATCHED_OUTPUT="${OUTPUT}.patched"

if [ "${JARFILE}" = "true" ]
then

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

ET.register_namespace('', 'http://cyclonedx.org/schema/bom/1.3')
ns = {'': 'http://cyclonedx.org/schema/bom/1.3'}

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

indent(root)

et.write(sys.stdout, encoding='unicode', xml_declaration=True, default_namespace='')
END
) < "$OUTPUT" > "$PATCHED_OUTPUT"

else

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

ET.register_namespace('', 'http://cyclonedx.org/schema/bom/1.3')
ns = {'': 'http://cyclonedx.org/schema/bom/1.3'}

# Open original file
et = ET.parse(sys.stdin)
root = et.getroot()

metadata = root.find('metadata', ns)
if not metadata:
    metadata = ET.SubElement(root, 'metadata')

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
if not component:
    component = ET.SubElement(metadata, 'component')

# Update component publisher and author
publisher = component.find('publisher', ns)
if not publisher:
    publisher = ET.Element('publisher')
    component.insert(0, publisher)
publisher.text = '$COMPONENT_AUTHOR_NAME'
author = component.find('author', ns)
if not author:
    author = ET.Element('author')
    component.insert(1, author)
author.text = '$COMPONENT_AUTHOR_NAME'

# Update component name and version
name = component.find('name', ns)
if not name:
    name = ET.SubElement(component, 'name')

name.text = '$COMPONENT_NAME'
component_version = '$COMPONENT_VERSION'
if component_version:
    version = component.find('version', ns)
    if not version:
        version = ET.SubElement(component, 'version')
    version.text = component_version

# Update component hash
component_hash_alg = '${COMPONENT_HASH_ALG}'
if component_hash_alg:
    hashes = component.find('hashes', ns)
    if not hashes:
        hashes = ET.SubElement(component, 'hashes')
    hash = ET.SubElement(hashes, 'hash', alg=component_hash_alg)
    hash.text = '$COMPONENT_HASH_CONTENT'

# Add component supplier
supplier = component.find('supplier', ns)
if not supplier:
    supplier = ET.Element('supplier')
    component.insert(4, supplier)
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
fi

# ----------------------------------------------------------------------------
# Check that the patched SBOM is valid against the cyclonedx schema
# ----------------------------------------------------------------------------
[ -f "$SCRIPTDIR"/spdx.xsd ] || curl -fsS -o "$SCRIPTDIR"/spdx.xsd https://cyclonedx.org/schema/spdx
[ -f "$SCRIPTDIR"/cyclonedx.xsd ] || curl -fsS -o "$SCRIPTDIR"/cyclonedx.xsd https://cyclonedx.org/schema/bom/1.3

# xmllint complains about a double import of the spdx schema, but we have to import via
# the wrapper to set the schema location to a local file, as xmllint fails to download
# them from the internet as they are https
_=$(xmllint "$PATCHED_OUTPUT" --schema "$SCRIPTDIR"/cyclonedx-wrapper.xsd --noout 2>&1 | grep -Fv "Skipping import of schema located at 'http://cyclonedx.org/schema/spdx' for the namespace 'http://cyclonedx.org/schema/spdx'")
[ "${PIPESTATUS[0]}" -ne 0 ] && cat "${PATCHED_OUTPUT}" && exit "${PIPESTATUS[0]}"

if [ "${UPLOAD}" = "false" ]
then
    # not uploading - just output the xml
    cat "${PATCHED_OUTPUT}"
else
    # ----------------------------------------------------------------------------
    # Handle client id and secrets for SBOM scraper via App registrations
    # ----------------------------------------------------------------------------
    HTTP_STATUS=""
    # get token
    log "Get token ..."
    HTTP_STATUS=$(curl -sS -w "%{http_code} %{json}" \
        -o "${TEMPDIR}/access_token" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "client_id=${CLIENT_ID}" \
        --data-urlencode "client_secret=${SECRET}" \
        "${URL}/archivist/iam/v1/appidp/token")
    if [ "${HTTP_STATUS:0:1}" != "2" ]
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

    HTTP_STATUS=$(timeout ${SBOM_UPLOAD_TIMEOUT} \
        curl -s -w "%{http_code} %{json}" -X POST \
        -o "${TEMPDIR}/upload" \
        -H "@${BEARER_TOKEN_FILE}" \
        -H "content_type=text/xml" \
        -F "sbom=@${PATCHED_OUTPUT}" \
        "${URL}/archivist/v1/sboms?privacy=${PRIVACY}")

    RETURN_CODE=$?

    # timeout returns 124 if the command exceeded the time limit
    if [ ${RETURN_CODE} -eq 124 ]
    then
        log "Upload failure: Timeout"
        exit 3
    # all other non-zero return codes
    elif [ ${RETURN_CODE} -gt 0 ]
    then
        log "Upload failure: Error code ${RETURN_CODE}"
        exit 4
    fi

    if [ "${HTTP_STATUS:0:1}" != "2" ]
    then
        log "Upload failure ${HTTP_STATUS}"
        exit 5
    fi
    log "Upload success: "
    jq . "${TEMPDIR}/upload"
fi
exit 0
