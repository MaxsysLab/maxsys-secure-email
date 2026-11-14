<?php
// Test harness only, never part of a plugin. Lets the test script change settings,
// reset state and look inside the test site. Loaded as a must-use plugin in the
// throwaway WordPress that runs on the bench.

add_filter( 'pre_wp_mail', function ( $result, $atts ) {
	if ( get_option( 'test_mail_fail' ) ) {
		return false;
	}
	return $result;
}, 5, 2 );

add_action( 'rest_api_init', function () {
	$open = array( 'permission_callback' => '__return_true' );

	register_rest_route( 'test/v1', '/options', $open + array(
		'methods'  => 'POST',
		'callback' => function ( WP_REST_Request $r ) {
			$p = $r->get_json_params();
			if ( ! empty( $p['delete'] ) ) {
				delete_option( 'maxsys_secure_email_options' );
				return array( 'deleted' => true );
			}
			if ( isset( $p['replace'] ) ) {
				update_option( 'maxsys_secure_email_options', $p['replace'] );
				return array( 'replaced' => true );
			}
			$cur = get_option( 'maxsys_secure_email_options', null );
			if ( ! is_array( $cur ) ) {
				$cur = MAXSYS_Secure_Email::get_instance()->options;
			}
			update_option( 'maxsys_secure_email_options', array_merge( $cur, (array) ( $p['merge'] ?? array() ) ) );
			return array( 'merged' => true );
		},
	) );

	register_rest_route( 'test/v1', '/reset', $open + array(
		'methods'  => 'POST',
		'callback' => function ( WP_REST_Request $r ) {
			global $wpdb;
			$p = $r->get_json_params();
			foreach ( array( 'maxsys_rate_limits', 'maxsys_form_submissions' ) as $t ) {
				$wpdb->query( 'DELETE FROM ' . $wpdb->prefix . $t );
			}
			delete_option( 'test_mail_fail' );
			update_option( 'timezone_string', $p['timezone'] ?? 'UTC' );
			@unlink( '/wordpress/vout/mail-log.jsonl' );
			return array( 'reset' => true );
		},
	) );

	register_rest_route( 'test/v1', '/set', $open + array(
		'methods'  => 'POST',
		'callback' => function ( WP_REST_Request $r ) {
			$p = $r->get_json_params();
			foreach ( $p as $k => $v ) {
				update_option( $k, $v );
			}
			return array( 'set' => array_keys( $p ) );
		},
	) );

	// Make every rate-limit row look $seconds older, in whatever clock it was stamped.
	register_rest_route( 'test/v1', '/age', $open + array(
		'methods'  => 'POST',
		'callback' => function ( WP_REST_Request $r ) {
			global $wpdb;
			$s = (int) ( $r->get_json_params()['seconds'] ?? 0 );
			$t = $wpdb->prefix . 'maxsys_rate_limits';
			$rows = $wpdb->get_results( "SELECT id, last_attempt, blocked_until FROM $t" );
			foreach ( $rows as $row ) {
				$la = gmdate( 'Y-m-d H:i:s', strtotime( $row->last_attempt . ' UTC' ) - $s );
				$bu = $row->blocked_until ? gmdate( 'Y-m-d H:i:s', strtotime( $row->blocked_until . ' UTC' ) - $s ) : null;
				$wpdb->update( $t, array( 'last_attempt' => $la, 'blocked_until' => $bu ), array( 'id' => $row->id ) );
			}
			return array( 'aged' => count( $rows ) );
		},
	) );

	register_rest_route( 'test/v1', '/state', $open + array(
		'methods'  => 'GET',
		'callback' => function () {
			global $wpdb;
			$s    = $wpdb->prefix . 'maxsys_form_submissions';
			$rl   = $wpdb->prefix . 'maxsys_rate_limits';
			$inst = MAXSYS_Secure_Email::get_instance();
			$mailer = new stdClass();
			if ( ! class_exists( 'PHPMailer\\PHPMailer\\PHPMailer' ) ) {
				require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
				require_once ABSPATH . WPINC . '/PHPMailer/SMTP.php';
				require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';
			}
			$pm = new PHPMailer\PHPMailer\PHPMailer( true );
			do_action_ref_array( 'phpmailer_init', array( &$pm ) );
			return array(
				'submissions'  => $wpdb->get_results( "SELECT name, email, status, ip_address FROM $s ORDER BY id DESC LIMIT 5", ARRAY_A ),
				'rate_rows'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM $rl" ),
				'tables'       => array(
					'submissions' => (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $s ) ),
					'rate_limits' => (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $rl ) ),
				),
				'options'      => array_intersect_key( $inst->options, array_flip( array( 'ip_source', 'smtp_verify_certificate', 'allowed_origins', 'smtp_enabled' ) ) ),
				'smtp_options' => $pm->SMTPOptions,
				'mailer'       => $pm->Mailer,
				'timezone'     => wp_timezone_string(),
			);
		},
	) );
} );
