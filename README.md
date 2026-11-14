# MAXSYS Secure Email System

A WordPress plugin that is the back end of a contact form. It is for a site whose form
is not a WordPress page (a static site, or a front end built with a JavaScript
framework) and needs somewhere to send its submissions.

It adds one REST endpoint. Your form posts to it; the plugin checks the submission,
stores it, and mails it to you. Checks include a list of allowed websites, a rate
limit, a honeypot, content rules, and optionally Google reCAPTCHA v3. Mail can go
through your own SMTP server.

Everything a site owner needs is in [`readme.txt`](readme.txt), the file the WordPress
plugin directory reads: how a form uses the endpoint, what each protection does and
does not do, which outside services are contacted, and what is stored.

## Requirements

WordPress 6.2 or newer, PHP 7.4 or newer. Tested on WordPress 7.1 with PHP 8.3.

## Development

There is no build step. The plugin is `secure-plugin.php`, `uninstall.php` and two
small files in `assets/`.

Every pull request is checked for PHP syntax on the supported versions and with the
WordPress [Plugin Check](https://wordpress.org/plugins/plugin-check/) tool.

Changes to how a submission is checked need a test that shows the behaviour. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately, as
[SECURITY.md](SECURITY.md) describes.

## Who stands behind it

Published as open source by Maxsys International Incorporated, a nonprofit
(maxsys.org), through [MaxsysLab](https://github.com/MaxsysLab). Built by CSEAM
Technology Corporation for Maxsys's own sites, and released for anyone to use.

## License

GPL-2.0-or-later. See [`LICENSE`](LICENSE).

Copyright 2025-2026 Maxsys International Incorporated.
