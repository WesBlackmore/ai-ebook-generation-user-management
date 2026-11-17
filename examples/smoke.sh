#!/bin/sh
# End-to-end run of the example with curl. No keys needed. Usage: sh examples/smoke.sh
set -e
cd "$(dirname "$0")/.."
PORT=${PORT:-8765}
TMP=$(mktemp -d)
export APP_URL="http://localhost:$PORT" USER_MGMT_DB="$TMP/example.db"
unset GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET GOOGLE_REDIRECT_URI MAIL_FROM TURNSTILE_SECRET
php -S "localhost:$PORT" examples/index.php >"$TMP/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$TMP"' EXIT
sleep 1
B="http://localhost:$PORT"; J="$TMP/jar"
csrf() { curl -s -b "$J" -c "$J" "$B$1" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p'; }
post() { # path, data...
  p=$1; shift; t=$(csrf "${SRC:-$p}")
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -b "$J" -c "$J" --data-urlencode "csrf=$t" "$@" "$B$p"
}
fail() { echo "FAIL: $1"; exit 1; }
EMAIL=smoke@example.com

echo "register:   $(post /register -d email=$EMAIL -d password=first-password-1 -d name=Smoke)"
curl -s -b "$J" "$B/dashboard" | grep -q "Hello Smoke" || fail "dashboard after register"
echo "logout:     $(SRC=/dashboard post /logout)"
curl -s -o /dev/null -w '%{http_code}\n' -b "$J" "$B/dashboard" | grep -q 302 || fail "dashboard should redirect when signed out"
echo "bad login:  $(post /login -d email=$EMAIL -d password=nope-nope-1)"
curl -s -b "$J" -c "$J" "$B/login" >/dev/null
echo "login:      $(post /login -d email=$EMAIL -d password=first-password-1)"
curl -s -b "$J" "$B/dashboard" | grep -q "Hello Smoke" || fail "dashboard after login"
echo "logout:     $(SRC=/dashboard post /logout)"
echo "forgot:     $(post /forgot -d email=$EMAIL)"
echo "forgot (unknown): $(post /forgot -d email=ghost@example.com)"
LINK=$(grep -o 'http://localhost:[0-9]*/reset?token=[0-9a-f]*' "$TMP/server.log" | tail -1)
[ -n "$LINK" ] || fail "no reset link in the server log"
echo "reset link logged: ${LINK%token=*}token=<64 hex>"
TOKEN=${LINK#*token=}
echo "reset:      $(post "/reset?token=$TOKEN" -d password=second-password-2 -d confirm_password=second-password-2)"
curl -s -b "$J" "$B/dashboard" | grep -q "Hello Smoke" || fail "signed in after reset"
echo "reuse link: $(curl -s "$B/reset?token=$TOKEN" | grep -o 'That link no longer works')"
curl -s "$B/login" | grep -q "Sign in with Google" && fail "google button should be hidden without keys"
echo "google button hidden without keys: yes"
echo "SMOKE PASSED"
