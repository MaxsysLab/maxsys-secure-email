# MAXSYS Secure Email System

Every contact form needs somewhere to send what people write. This WordPress plugin is
that place. Your form posts each message to it, and the plugin checks the message,
keeps a copy on your site, and mails it to you through your own mail account.

We built it for the contact forms on our own sites, when we wanted their mail to go out
through our own SMTP account. It is released here for anyone who wants the same.

It has no form of its own, and that is on purpose. You write the form the way you like,
on a static site, a JavaScript front end, or any page that can send a web request, and
point it at the plugin.

## What it does

Mail goes out through your own SMTP server if you give it one, and the settings page
has a button to send yourself a test message. Each message is stored before it is
mailed, so it is still on your site, under Tools, then Form Submissions, if a mail ever
fails to go out.

It also keeps the form from being misused. Only the websites you list can use it from a
browser. One address can send only so many messages in a period of time. A hidden field
catches the simplest robots, your own rules decide what a valid name, email and message
look like, and Google reCAPTCHA v3 can be switched on if you want it. What each of
these does, and where its limits are, is explained in [`readme.txt`](readme.txt).

## Start in a few minutes

1. Copy this folder to `wp-content/plugins/maxsys-secure-email` and activate the
   plugin.
2. Open Settings, then Secure Email. On the SMTP Settings tab, enter your mail server
   and use "Send Test Email". Messages go to the site administrator's address unless
   you set another on the Email Templates tab.
3. On the Security tab, list the websites your form lives on, one per line.
4. Send a message from a terminal to see the whole path work:

   ```bash
   curl -X POST https://your-site.example/wp-json/maxsys-contact/v1/submit \
     -H 'Content-Type: application/json' \
     -d '{"name":"Test Person","email":"you@example.org","subject":"Hello","message":"Hello, this is a test message.","timestamp":'"$(date +%s)000"'}'
   ```

   A reply with `"status":"success"` means the message was checked, stored and mailed.
   It is now listed under Tools, then Form Submissions.
5. Point your form at the same address. The fields it sends are described in
   [`readme.txt`](readme.txt).

## Where it stands

Version 3.6.0. It needs WordPress 6.2 or newer and PHP 7.4 or newer, and we tested it
on WordPress 7.1 with PHP 8.3, with forty-one automated checks of how a message is
handled. Two things we could not try on our test bench are a live mail server and
reCAPTCHA with real keys, so after setting up, send yourself a test message, as you
would with any mail tool. If your site is moving up from 3.5.5, the settings page will
point you to two safety settings to review.

## Development

There is no build step. The plugin is `secure-plugin.php`, `uninstall.php` and two
small files in `assets/`. The tests and how to run them are in [`tests/`](tests/).

Pull requests are welcome, small ones especially. Each is checked for PHP syntax on the
supported versions and with the WordPress
[Plugin Check](https://wordpress.org/plugins/plugin-check/) tool. A change to how a
message is checked needs a test that shows the behaviour;
[CONTRIBUTING.md](CONTRIBUTING.md) has the rest. If you find a security problem, please
tell us privately first, as [SECURITY.md](SECURITY.md) describes.

## Who stands behind it

Published as open source by Maxsys International Incorporated, a nonprofit
(maxsys.org), through [MaxsysLab](https://github.com/MaxsysLab). Built by CSEAM
Technology Corporation for our own sites, and released for anyone to use.

## License

GPL-2.0-or-later. See [`LICENSE`](LICENSE).

Copyright 2025-2026 Maxsys International Incorporated.
