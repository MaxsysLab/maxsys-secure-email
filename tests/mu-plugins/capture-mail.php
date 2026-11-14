<?php
// Test harness only, never part of a plugin: record every mail WordPress would send, and do not send it.
// When the test option "test_mail_fail" is set, behave as a mail server that refuses the message.
add_filter( 'pre_wp_mail', function ( $null, $atts ) {
	if ( get_option( 'test_mail_fail' ) ) {
		return false;
	}
	file_put_contents( '/wordpress/vout/mail-log.jsonl', wp_json_encode( $atts ) . "\n", FILE_APPEND );
	return true;
}, 10, 2 );
