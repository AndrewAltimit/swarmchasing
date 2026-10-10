#!/usr/bin/env bash
# Send a plain-text email over SMTP with curl. Used by the watch workflow for
# run digests and failure alerts. Sends to the admin only, never to report contacts.
#
#   scripts/ci/send-mail.sh "<subject>" <body-file>
#
# Environment: SMTP_URL (e.g. smtps://smtp.example.com:465 or smtp://host:587),
# SMTP_USER, SMTP_PASSWORD, MAIL_FROM, MAIL_TO. MAIL_FROM and MAIL_TO may be a
# bare address or `Name <address>`.
#
# Header injection: the subject and both addresses go into the message header,
# so a CR or LF in any of them would start a new header (or the body). They
# are refused, not stripped. The body is only ever written after the blank
# line that ends the header.
#
# Every message carries a Date (RFC 5322, UTC) and a Message-ID
# (<epoch.random@domain-of-MAIL_FROM>). Without them some relays add their own
# and some spam filters mark the mail down.
set -euo pipefail

subject="$1"
body_file="$2"
: "${SMTP_URL:?}" "${SMTP_USER:?}" "${SMTP_PASSWORD:?}" "${MAIL_FROM:?}" "${MAIL_TO:?}"

for name in subject MAIL_FROM MAIL_TO; do
    if [[ "${!name}" == *$'\r'* || "${!name}" == *$'\n'* ]]; then
        echo "send-mail: refusing a line break in $name (header injection)" >&2
        exit 2
    fi
done

# The envelope wants the bare address: the part inside <...> when there is one.
addr() {
    local v="$1"
    if [[ "$v" =~ \<([^\<\>]+)\> ]]; then
        v="${BASH_REMATCH[1]}"
    fi
    v="${v#"${v%%[![:space:]]*}"}"
    printf '%s' "${v%"${v##*[![:space:]]}"}"
}
from_addr="$(addr "$MAIL_FROM")"
to_addr="$(addr "$MAIL_TO")"

# Message-ID domain: MAIL_FROM's domain, when it is a plain hostname.
domain="${from_addr##*@}"
if [[ "$from_addr" != *@* || ! "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
    domain="localhost"
fi
rand="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
message_id="<$(date -u +%s).${rand}@${domain}>"
mail_date="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"

# Credentials go in a private netrc file so they never appear in the process list.
host="$(printf '%s' "$SMTP_URL" | sed -E 's#^[a-z]+://([^:/]+).*#\1#')"
umask 077
printf 'machine %s login %s password %s\n' "$host" "$SMTP_USER" "$SMTP_PASSWORD" >"$tmp/netrc"

{
  printf 'From: %s\r\n' "$MAIL_FROM"
  printf 'To: %s\r\n' "$MAIL_TO"
  printf 'Subject: %s\r\n' "$subject"
  printf 'Date: %s\r\n' "$mail_date"
  printf 'Message-ID: %s\r\n' "$message_id"
  printf 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'
  sed 's/$/\r/' "$body_file"
} >"$tmp/mail.txt"

curl --silent --show-error --ssl-reqd \
  --url "$SMTP_URL" \
  --netrc-file "$tmp/netrc" \
  --mail-from "$from_addr" \
  --mail-rcpt "$to_addr" \
  --upload-file "$tmp/mail.txt"
echo "sent: $subject"
