#!/usr/bin/env bash
# Tests for MAXSYS Secure Email, run over HTTP against a throwaway WordPress on the bench.
# Usage: se-tests.sh <base-url> <mail-log-file>
# Prints PASS or FAIL for each case and ends with the counts; exit 1 if any failed.
U="$1"; MAIL="$2"; API="$U/wp-json/maxsys-contact/v1"; T="$U/wp-json/test/v1"
pass=0; fail=0; failed=()
ok()   { pass=$((pass+1)); echo "PASS  $1"; }
no()   { fail=$((fail+1)); failed+=("$1"); echo "FAIL  $1   [$2]"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "wanted $3, got $2"; fi; }
tj()   { curl -s -m 60 -X POST -H 'Content-Type: application/json' -d "$2" "$T/$1" >/dev/null; }
reset(){ tj reset "{\"timezone\":\"${1:-UTC}\"}"; }
state(){ curl -s -m 60 "$T/state"; }
jq_()  { python3 -I -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
now_ms(){ echo $(( $(date +%s) * 1000 )); }
body() { echo "{\"name\":\"${1:-Test Person}\",\"email\":\"t@example.org\",\"message\":\"${2:-Hello, this is a test message.}\",\"subject\":\"Hi\",\"timestamp\":${3:-$(now_ms)}${4:+,$4}}"; }
# submit <json> [extra curl args] -> prints "<http code> <error code or status>"
submit(){ local d="$1"; shift; local out; out=$(curl -s -m 60 -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' "$@" -d "$d" "$API/submit"); local code="${out##*$'\n'}"; local b="${out%$'\n'*}"; echo "$code $(echo "$b" | jq_ 'd.get("code") or d.get("status")')"; }
mails(){ [ -f "$MAIL" ] && wc -l < "$MAIL" || echo 0; }

tj options '{"delete":true}'; reset

# --- the plain flow
check "config endpoint answers with the validation rules" "$(curl -s -m 60 "$API/config" | jq_ '"validation_rules" in d')" "True"
r=$(submit "$(body)"); check "a valid submission is accepted" "$r" "200 success"
check "  and one mail is sent" "$(mails)" "1"
check "  and it is stored as sent" "$(state | jq_ 'd["submissions"][0]["status"]')" "sent"
reset; r=$(submit "$(body 'Test Person' 'Hello, this is a test message.' "$(now_ms)" '"website":"x"')"); check "a filled honeypot is refused" "$r" "400 spam_detected"
check "  and nothing is stored" "$(state | jq_ 'len(d["submissions"])')" "0"
reset; r=$(submit "$(body 'Test Person' 'short')"); check "a too-short message is refused" "$r" "400 validation_error"
reset; r=$(submit "$(body 'Test Person' 'Hello, this is a test message.' 1000)"); check "an expired form timestamp is refused" "$r" "400 invalid_timestamp"
reset; r=$(submit "$(body 'Test Person' 'Please visit my casino tonight friends')"); check "a spam keyword is refused" "$r" "400 validation_error"
reset; r=$(submit "$(body 'Test Person' 'See https://example.com for details ok')"); check "a message with an address is refused when addresses are blocked" "$r" "400 validation_error"

# --- names in other scripts
reset; r=$(submit "$(body 'José Núñez')"); check "a name with accents is accepted" "$r" "200 success"
reset; r=$(submit "$(body 'ജോസഫ് പോൾ')"); check "a name in Malayalam is accepted" "$r" "200 success"
reset; r=$(submit "$(body 'Robert<script>alert(1)</script>')"); check "markup in a name is stripped before it is accepted" "$r" "200 success"
check "  and what is stored is the clean name" "$(state | jq_ 'd["submissions"][0]["name"]')" "Robert"

# --- rate limit
rl(){ reset "$1"; local a b c d; a=$(submit "$(body)"); b=$(submit "$(body)"); c=$(submit "$(body)"); d=$(submit "$(body)"); echo "${a%% *} ${b%% *} ${c%% *} ${d%% *}"; }
check "rate limit: three allowed, the fourth refused (site clock UTC)" "$(rl UTC)" "200 200 200 429"
check "rate limit: the same with the site clock behind UTC (New York)" "$(rl America/New_York)" "200 200 200 429"
check "rate limit: the same with the site clock ahead of UTC (Kolkata)" "$(rl Asia/Kolkata)" "200 200 200 429"
reset Asia/Kolkata; submit "$(body)" >/dev/null; submit "$(body)" >/dev/null; submit "$(body)" >/dev/null; tj age '{"seconds":900}'
r=$(submit "$(body)"); check "rate limit: attempts older than the window are forgotten (Kolkata)" "${r%% *}" "200"
check "  and old rows are cleaned out" "$(state | jq_ 'd["rate_rows"]')" "1"

# --- which address is the caller's
reset; submit "$(body)" >/dev/null; submit "$(body)" >/dev/null; submit "$(body)" >/dev/null
r=$(submit "$(body)" -H 'X-Forwarded-For: 203.0.113.9'); check "a forged forwarded address does not escape the rate limit by default" "${r%% *}" "429"
tj options '{"merge":{"ip_source":"forwarded"}}'; reset; submit "$(body)" >/dev/null; submit "$(body)" >/dev/null; submit "$(body)" >/dev/null
r=$(submit "$(body)" -H 'X-Forwarded-For: 203.0.113.9'); check "behind a declared proxy, the forwarded address is the caller's" "${r%% *}" "200"
check "  and it is the address stored" "$(state | jq_ 'd["submissions"][0]["ip_address"]')" "203.0.113.9"
tj options '{"delete":true}'

# --- origins
reset; tj options '{"merge":{"allowed_origins":"https://allowed.example"}}'
hdr(){ curl -s -m 30 -o /dev/null -D - "$@" | tr -d '\r' | grep -i "^access-control-allow-origin:" | awk '{print $2}'; }
check "allowed origin gets the cross-origin header" "$(hdr -X OPTIONS -H 'Origin: https://allowed.example' -H 'Access-Control-Request-Method: POST' "$API/submit")" "https://allowed.example"
check "another origin gets no cross-origin header" "$(hdr -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST' "$API/submit")" ""
r=$(submit "$(body)" -H 'Origin: https://evil.example'); check "a submission from another origin is refused" "$r" "403 origin_not_allowed"
reset; r=$(submit "$(body)" -H 'Origin: https://allowed.example'); check "a submission from an allowed origin is accepted" "$r" "200 success"
reset; r=$(submit "$(body)" -H "Origin: $U"); check "a submission from the site itself is accepted" "$r" "200 success"
reset; r=$(submit "$(body)"); check "a submission with no origin (not a browser) is accepted" "$r" "200 success"
check "other plugins' routes keep WordPress's own cross-origin answer" "$(hdr -H 'Origin: https://evil.example' "$U/wp-json/wp/v2/posts")" "https://evil.example"
check "  and get no extra headers from this plugin" "$(curl -s -m 30 -o /dev/null -D - -H 'Origin: https://evil.example' "$U/wp-json/wp/v2/posts" | grep -c -i '^x-frame-options')" "0"
tj options '{"delete":true}'

# --- mail server certificate
reset; tj options '{"merge":{"smtp_enabled":true,"smtp_host":"smtp.example.org","smtp_verify_certificate":true}}'
check "SMTP: certificate checks are left on" "$(state | jq_ 'd["smtp_options"]')" "[]"
tj options '{"merge":{"smtp_verify_certificate":false}}'
check "SMTP: they can be switched off on purpose" "$(state | jq_ 'd["smtp_options"]["ssl"]["verify_peer"]')" "False"
tj options '{"delete":true}'

# --- defaults, and an install upgraded from 3.5.5
reset; s=$(state)
check "a new install takes the caller's address from the connection" "$(echo "$s" | jq_ 'd["options"]["ip_source"]')" "remote_addr"
check "a new install checks the mail server's certificate" "$(echo "$s" | jq_ 'd["options"]["smtp_verify_certificate"]')" "True"
check "a new install allows its own origin, not maxsys.org" "$(echo "$s" | jq_ '"maxsys.org" in d["options"]["allowed_origins"]')" "False"
tj options '{"replace":{"smtp_enabled":true,"smtp_host":"smtp.gmail.com","smtp_port":587,"smtp_username":"u","smtp_password":"p","smtp_secure":"tls","smtp_from_email":"a@example.org","smtp_from_name":"A","recaptcha_enabled":false,"recaptcha_site_key":"","recaptcha_secret_key":"","recaptcha_min_score":0.7,"rate_limit_enabled":true,"rate_limit_attempts":3,"rate_limit_window":300,"rate_limit_block_duration":3600,"allowed_origins":"https://maxsys.org","honeypot_enabled":true,"timestamp_validation":true,"timestamp_max_age":86400,"notification_email":"a@example.org","email_template":"{message}","auto_reply_enabled":false,"auto_reply_template":"x","name_min_length":2,"name_max_length":100,"message_min_length":10,"message_max_length":5000,"subject_max_length":200,"spam_keywords":"casino","block_urls":true,"enable_logging":false,"log_successful_submissions":false,"log_failed_attempts":false}}'
s=$(state)
check "an upgraded install keeps its old way of finding the address" "$(echo "$s" | jq_ 'd["options"]["ip_source"]')" "auto"
check "an upgraded install keeps certificate checks as they were (off)" "$(echo "$s" | jq_ 'd["options"]["smtp_verify_certificate"]')" "False"
check "an upgraded install keeps its saved origins" "$(echo "$s" | jq_ 'd["options"]["allowed_origins"]')" "https://maxsys.org"
tj options '{"delete":true}'

# --- a failed send is not recorded as sent
reset; tj set '{"test_mail_fail":1}'; r=$(submit "$(body)"); check "when the mail cannot be sent the caller is told" "$r" "500 mail_failed"
check "  and the submission is stored as failed" "$(state | jq_ 'd["submissions"][0]["status"]')" "failed"
reset

check "both tables exist" "$(state | jq_ 'd["tables"]["submissions"] and d["tables"]["rate_limits"]')" "True"

echo; echo "passed: $pass   failed: $fail"
for f in "${failed[@]}"; do echo "  failed: $f"; done
[ "$fail" -eq 0 ]
