=== MAXSYS Secure Email System ===
Tags: contact form, rest api, smtp, recaptcha, spam protection
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 3.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

The back end of a contact form: a REST endpoint that checks, stores and mails each submission, with SMTP, reCAPTCHA v3 and rate limiting.

== Description ==

This plugin is for a site whose contact form is not a WordPress page: a static site, or a front end built with a JavaScript framework, that needs somewhere to send its form. It adds one endpoint to a WordPress site. Your form posts to it; the plugin checks the submission, stores it, and mails it to you.

It has no form of its own. You write the form; this is what it talks to.

What it does with each submission:

* refuses it if the sending website is not on your list of allowed websites;
* limits how many submissions one address may send in a period of time;
* checks a hidden honeypot field, and how old the form is;
* checks the name, email, phone, subject and message against rules you set;
* refuses messages containing words you list, or any web address if you choose;
* optionally scores it with Google reCAPTCHA v3;
* stores it, mails it to you through your own SMTP server if you set one, and can send an automatic reply.

= How a form uses it =

Send a `POST` request with a JSON body to `/wp-json/maxsys-contact/v1/submit`:

`{ "name": "...", "email": "...", "phone": "...", "subject": "...", "message": "...", "website": "", "timestamp": 1700000000000, "recaptcha_token": "..." }`

* `name`, `email` and `message` are required.
* `website` is the honeypot. Your form must leave it empty; a filled one is treated as spam.
* `timestamp` is when the form was loaded, in milliseconds.
* `recaptcha_token` is needed only when reCAPTCHA is on.

A successful reply has status `success`. A refusal carries a `code`: `validation_error`, `spam_detected`, `invalid_timestamp`, `rate_limited`, `recaptcha_failed`, `origin_not_allowed` or `mail_failed`.

`GET /wp-json/maxsys-contact/v1/config` returns what your form needs to set itself up: the reCAPTCHA site key and the length rules.

= What "allowed websites" does and does not do =

A browser page on a website that is not on your list cannot use the endpoint: the request is refused, and the browser is not given permission to read the reply. This stops other websites from using your form.

It does not stop a program that is not a browser, which can send any origin or none. The rate limit, the honeypot, the content rules and reCAPTCHA are the protection against those.

= The visitor's address =

The rate limit counts by the visitor's address. If your site sits behind Cloudflare or another proxy, tell the plugin so on the Security tab; otherwise every visitor appears to come from the proxy. Do not choose a proxy you are not behind: the address would then be read from a header any caller can write.

== External services ==

**Google reCAPTCHA v3**, only when you switch reCAPTCHA on and enter your keys. For each submission the plugin sends the reCAPTCHA token from your form and the visitor's IP address to Google, to get a score that says how likely the visitor is a person. Nothing is sent when reCAPTCHA is off.

* Service: https://www.google.com/recaptcha/
* Terms of use: https://policies.google.com/terms
* Privacy policy: https://policies.google.com/privacy

**Your mail server**, when you set up SMTP. Submissions are mailed through the server you name, with the username and password you enter.

The plugin contacts no other service.

== What it stores ==

In your site's own database:

* each submission: name, email address, phone, subject, message, the visitor's IP address and browser identification, the reCAPTCHA score, and whether the mail was sent;
* for the rate limit: the visitor's IP address and browser identification, and how many attempts were made. These records are removed once their period has passed.

Your SMTP password and reCAPTCHA secret are stored in the site's settings.

If your site has visitors who are protected by a privacy law, say in your privacy notice that the form stores these details, and that reCAPTCHA sends the visitor's address to Google if you use it. Deleting the plugin removes everything it stored.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`, or install it from the Plugins screen, and activate it.
2. Go to Settings, then Secure Email.
3. On the Security tab, list the websites allowed to use the form, one per line, and choose where the visitor's address is read from.
4. On the Email Templates tab, set the address that receives submissions.
5. Optionally set up SMTP and reCAPTCHA on their tabs. Use "Send Test Email" to check SMTP.
6. Point your form at `/wp-json/maxsys-contact/v1/submit`.

Submissions are listed under Tools, then Form Submissions.

== Frequently Asked Questions ==

= Does it include a form? =

No. It is the part a form sends to.

= My mail server uses a self-signed certificate. =

On the SMTP tab, switch off "Check the mail server's certificate". Do this only if you must: without the check, mail and the mail password can be intercepted on the way to the server.

= Can names be written in any script? =

Yes. Letters of any script are accepted, with spaces, hyphens, apostrophes and full stops.

== Changelog ==

= 3.6.0 =
First public release. If you are updating from 3.5.5, read the two notes marked "On update".

* Security: the mail server's certificate is now checked. On update: a site that already had settings keeps the old behaviour, checks off, until you switch it on in the SMTP tab; the settings page says so.
* Security: the visitor's address is no longer read from a header any caller can write, unless you say the site is behind that kind of proxy. On update: a site that already had settings keeps the old behaviour until you choose on the Security tab; the settings page says so.
* Security: the list of allowed websites now works. Before, it had no effect on current WordPress, and a page on any website could use the form.
* Fixed: the rate limit did not work on a site whose clock is not UTC. Behind UTC it never limited; ahead of UTC it never forgot.
* Fixed: a failed mail was recorded as sent.
* Fixed: names with accents, or in scripts other than Latin, were refused.
* Fixed: damaged characters on the settings and submissions screens.
* Changed: the plugin sets headers only on its own endpoint. It was written to change every REST response on the site.
* Changed: the tables are created once, not on every page load.
* Changed: a new install allows its own website by default, not maxsys.org.
* Added: the licence, this readme, and an uninstall routine that removes the plugin's data.
* Output escaping and database queries brought in line with the WordPress coding standards.

= 3.5.5 =
* The version used on Maxsys's own sites before public release.
