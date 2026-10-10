#!/usr/bin/env bash
# Send a plain-text email over SMTP with curl. Used by the watch workflow for
# run digests and failure alerts. Sends to the admin only, never to report contacts.
#
#   scripts/ci/send-mail.sh "<subject>" <body-file>
#
# Environment: SMTP_URL (e.g. smtps://smtp.example.com:465 or smtp://host:587),
# SMTP_USER, SMTP_PASSWORD, MAIL_FROM, MAIL_TO.
set -euo pipefail

subject="$1"
body_file="$2"
: "${SMTP_URL:?}" "${SMTP_USER:?}" "${SMTP_PASSWORD:?}" "${MAIL_FROM:?}" "${MAIL_TO:?}"

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
  printf 'Date: %s\r\n' "$(date -R)"
  printf 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'
  sed 's/$/\r/' "$body_file"
} >"$tmp/mail.txt"

curl --silent --show-error --ssl-reqd \
  --url "$SMTP_URL" \
  --netrc-file "$tmp/netrc" \
  --mail-from "$MAIL_FROM" \
  --mail-rcpt "$MAIL_TO" \
  --upload-file "$tmp/mail.txt"
echo "sent: $subject"
