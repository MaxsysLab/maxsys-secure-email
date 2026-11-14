# Tests

These tests run the plugin over HTTP in a throwaway WordPress and check what it does:
the plain flow, names in other scripts, the rate limit under three site clocks, which
address the caller is taken to have, allowed websites, the mail server's certificate
check, the defaults of a new install, an install upgraded from 3.5.5, and a failed
send. Each repair made in 3.6.0 has a test here that fails on 3.5.5.

They need a WordPress where three folders are mounted:

- this plugin, as `wp-content/plugins/maxsys-secure-email`;
- `tests/mu-plugins`, as `wp-content/mu-plugins`. It holds a test harness that captures
  mail and lets the test script change settings. **Never install it on a real site**:
  it opens unauthenticated routes;
- any empty folder, as `/wordpress/vout`, where captured mail is written.

With the WordPress Playground command-line tool (`@wp-playground/cli`):

```bash
mkdir -p /tmp/vout
npx @wp-playground/cli server --port 9400 \
  --mount "$PWD:/wordpress/wp-content/plugins/maxsys-secure-email" \
  --mount "$PWD/tests/mu-plugins:/wordpress/wp-content/mu-plugins" \
  --mount "/tmp/vout:/wordpress/vout" \
  --blueprint tests/blueprint.json
```

and, in another terminal, once it says it is ready:

```bash
bash tests/run.sh http://127.0.0.1:9400 /tmp/vout/mail-log.jsonl
```

The script prints PASS or FAIL for each case and exits with an error if any failed.
`tests/blueprint-uninstall.json` checks the uninstall routine with `run-blueprint`.
