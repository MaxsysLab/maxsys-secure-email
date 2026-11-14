<?php
/**
 * Plugin Name:       MAXSYS Secure Email System
 * Description:       The back end of a contact form: a REST endpoint that checks, stores and mails each submission, with SMTP, reCAPTCHA v3, rate limiting and a honeypot.
 * Version:           3.6.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            MAXSYS Dev Team
 * Author URI:        https://maxsys.org
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       maxsys-secure-email
 *
 * @package MaxsysSecureEmail
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MAXSYS_SECURE_EMAIL_VERSION', '3.6.0' );
define( 'MAXSYS_SECURE_EMAIL_DB_VERSION', '2' );
define( 'MAXSYS_SECURE_EMAIL_URL', plugin_dir_url( __FILE__ ) );
define( 'MAXSYS_SECURE_EMAIL_PATH', plugin_dir_path( __FILE__ ) );

class MAXSYS_Secure_Email {
	const REST_NAMESPACE = 'maxsys-contact/v1';

	private static $instance = null;
	public $options;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->options = $this->load_options();
		$this->init_hooks();
	}

	private function init_hooks() {
		add_action( 'init', array( $this, 'maybe_upgrade' ) );
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'admin_scripts' ) );
		add_action( 'phpmailer_init', array( $this, 'configure_smtp' ) );
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
		add_action( 'wp_ajax_maxsys_test_smtp', array( $this, 'test_smtp_connection' ) );
		add_action( 'wp_ajax_maxsys_clear_rate_limits', array( $this, 'clear_rate_limits' ) );
		// After WordPress's own cross-origin headers (priority 10), and only for this plugin's routes.
		add_filter( 'rest_pre_serve_request', array( $this, 'send_cors_headers' ), 20, 4 );
	}

	/**
	 * Runs when the plugin is activated.
	 */
	public static function activate() {
		self::get_instance()->maybe_upgrade();
	}

	/**
	 * Create the tables once, and again only when their version changes.
	 */
	public function maybe_upgrade() {
		if ( get_option( 'maxsys_secure_email_db_version' ) === MAXSYS_SECURE_EMAIL_DB_VERSION ) {
			return;
		}
		$this->create_rate_limit_table();
		$this->create_submissions_table();

		// Up to 3.5.5 the rate-limit rows were stamped in the site's clock. They are now
		// stamped in UTC, so rows left from before would be read wrongly. They are short-lived.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $wpdb->prefix . 'maxsys_rate_limits' ) );

		update_option( 'maxsys_secure_email_db_version', MAXSYS_SECURE_EMAIL_DB_VERSION );
	}

	/**
	 * The saved settings over the defaults.
	 */
	private function load_options() {
		$defaults = $this->get_default_options();
		$stored   = get_option( 'maxsys_secure_email_options', null );
		if ( ! is_array( $stored ) ) {
			return $defaults;
		}

		// Two settings were added in 3.6.0. A site that saved its settings before then
		// keeps behaving as it did, and its settings page says so.
		if ( ! array_key_exists( 'ip_source', $stored ) ) {
			$stored['ip_source'] = 'auto';
		}
		if ( ! array_key_exists( 'smtp_verify_certificate', $stored ) ) {
			$stored['smtp_verify_certificate'] = false;
		}

		return array_merge( $defaults, $stored );
	}

	private function get_default_options() {
		return array(
			'smtp_enabled'               => false,
			'smtp_host'                  => 'smtp.gmail.com',
			'smtp_port'                  => 587,
			'smtp_username'              => '',
			'smtp_password'              => '',
			'smtp_secure'                => 'tls',
			'smtp_verify_certificate'    => true,
			'smtp_from_email'            => get_option( 'admin_email' ),
			'smtp_from_name'             => get_bloginfo( 'name' ),
			'recaptcha_enabled'          => true,
			'recaptcha_site_key'         => '',
			'recaptcha_secret_key'       => '',
			'recaptcha_min_score'        => 0.7,
			'rate_limit_enabled'         => true,
			'rate_limit_attempts'        => 3,
			'rate_limit_window'          => 300,
			'rate_limit_block_duration'  => 3600,
			'ip_source'                  => 'remote_addr',
			'allowed_origins'            => $this->site_origin(),
			'honeypot_enabled'           => true,
			'timestamp_validation'       => true,
			'timestamp_max_age'          => 86400,
			'notification_email'         => get_option( 'admin_email' ),
			'email_template'             => $this->get_default_email_template(),
			'auto_reply_enabled'         => false,
			'auto_reply_template'        => $this->get_default_auto_reply(),
			'name_min_length'            => 2,
			'name_max_length'            => 100,
			'message_min_length'         => 10,
			'message_max_length'         => 5000,
			'subject_max_length'         => 200,
			'spam_keywords'              => "viagra\ncasino\npoker\nloan\ndebt\nclick here\nbuy now\nact now",
			'block_urls'                 => true,
			'enable_logging'             => true,
			'log_successful_submissions' => true,
			'log_failed_attempts'        => true,
		);
	}

	/**
	 * This site's own origin, for example https://example.org.
	 */
	private function site_origin() {
		$parts = wp_parse_url( home_url() );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$origin = $parts['scheme'] . '://' . $parts['host'];
		if ( ! empty( $parts['port'] ) ) {
			$origin .= ':' . $parts['port'];
		}
		return $origin;
	}

	private function get_default_email_template() {
		return "New secure contact form submission:\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nSubject: {subject}\nIP Address: {ip_address}\nUser Agent: {user_agent}\nSubmitted: {submission_time}\n\nMessage:\n{message}";
	}

	private function get_default_auto_reply() {
		return "Dear {name},\n\nThank you for contacting us. We have received your message and will respond as soon as possible.\n\nBest regards,\n" . get_bloginfo( 'name' );
	}

	public function create_rate_limit_table() {
		global $wpdb;
		$table_name      = $wpdb->prefix . 'maxsys_rate_limits';
		$charset_collate = $wpdb->get_charset_collate();
		$sql             = "CREATE TABLE IF NOT EXISTS $table_name ( id mediumint(9) NOT NULL AUTO_INCREMENT, ip_address varchar(45) NOT NULL, endpoint varchar(100) NOT NULL, attempts int(11) DEFAULT 0, last_attempt datetime DEFAULT CURRENT_TIMESTAMP, blocked_until datetime NULL, user_agent text, PRIMARY KEY (id), UNIQUE KEY ip_endpoint (ip_address, endpoint), KEY blocked_until (blocked_until), KEY last_attempt (last_attempt) ) $charset_collate;";
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public function create_submissions_table() {
		global $wpdb;
		$table_name      = $wpdb->prefix . 'maxsys_form_submissions';
		$charset_collate = $wpdb->get_charset_collate();
		$sql             = "CREATE TABLE IF NOT EXISTS $table_name ( id mediumint(9) NOT NULL AUTO_INCREMENT, name varchar(100) NOT NULL, email varchar(254) NOT NULL, phone varchar(50), subject varchar(200), message text NOT NULL, ip_address varchar(45) NOT NULL, user_agent text, recaptcha_score decimal(3,2), status varchar(20) DEFAULT 'sent', created_at datetime DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id), KEY email (email), KEY ip_address (ip_address), KEY created_at (created_at), KEY status (status) ) $charset_collate;";
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public function add_admin_menu() {
		add_options_page( __( 'MAXSYS Secure Email', 'maxsys-secure-email' ), __( 'Secure Email', 'maxsys-secure-email' ), 'manage_options', 'maxsys-secure-email', array( $this, 'admin_page' ) );
		add_management_page( __( 'Form Submissions', 'maxsys-secure-email' ), __( 'Form Submissions', 'maxsys-secure-email' ), 'manage_options', 'maxsys-form-submissions', array( $this, 'submissions_page' ) );
	}

	public function register_settings() {
		register_setting( 'maxsys_secure_email_options', 'maxsys_secure_email_options', array( 'sanitize_callback' => array( $this, 'sanitize_options' ) ) );
	}

	public function sanitize_options( $input ) {
		$sanitized       = array();
		$current_options = $this->options;
		if ( ! is_array( $input ) ) {
			return $current_options;
		}

		$sanitized['smtp_password']        = ( ! empty( $input['smtp_password'] ) ) ? sanitize_text_field( $input['smtp_password'] ) : ( $current_options['smtp_password'] ?? '' );
		$sanitized['recaptcha_secret_key'] = ( ! empty( $input['recaptcha_secret_key'] ) ) ? sanitize_text_field( $input['recaptcha_secret_key'] ) : ( $current_options['recaptcha_secret_key'] ?? '' );

		$sanitized['smtp_enabled']               = ! empty( $input['smtp_enabled'] );
		$sanitized['smtp_host']                  = sanitize_text_field( $input['smtp_host'] ?? '' );
		$sanitized['smtp_port']                  = absint( $input['smtp_port'] ?? 587 );
		$sanitized['smtp_username']              = sanitize_text_field( $input['smtp_username'] ?? '' );
		$sanitized['smtp_secure']                = in_array( $input['smtp_secure'] ?? 'tls', array( 'tls', 'ssl', 'none' ), true ) ? $input['smtp_secure'] : 'tls';
		$sanitized['smtp_verify_certificate']    = ! empty( $input['smtp_verify_certificate'] );
		$sanitized['smtp_from_email']            = sanitize_email( $input['smtp_from_email'] ?? '' );
		$sanitized['smtp_from_name']             = sanitize_text_field( $input['smtp_from_name'] ?? '' );
		$sanitized['recaptcha_enabled']          = ! empty( $input['recaptcha_enabled'] );
		$sanitized['recaptcha_site_key']         = sanitize_text_field( $input['recaptcha_site_key'] ?? '' );
		$sanitized['recaptcha_min_score']        = max( 0, min( 1, floatval( $input['recaptcha_min_score'] ?? 0.7 ) ) );
		$sanitized['rate_limit_enabled']         = ! empty( $input['rate_limit_enabled'] );
		$sanitized['rate_limit_attempts']        = max( 1, absint( $input['rate_limit_attempts'] ?? 3 ) );
		$sanitized['rate_limit_window']          = max( 60, absint( $input['rate_limit_window'] ?? 300 ) );
		$sanitized['rate_limit_block_duration']  = max( 300, absint( $input['rate_limit_block_duration'] ?? 3600 ) );
		$sanitized['ip_source']                  = in_array( $input['ip_source'] ?? 'remote_addr', array( 'remote_addr', 'cloudflare', 'forwarded', 'auto' ), true ) ? $input['ip_source'] : 'remote_addr';
		$sanitized['allowed_origins']            = sanitize_textarea_field( $input['allowed_origins'] ?? '' );
		$sanitized['honeypot_enabled']           = ! empty( $input['honeypot_enabled'] );
		$sanitized['timestamp_validation']       = ! empty( $input['timestamp_validation'] );
		$sanitized['timestamp_max_age']          = max( 300, absint( $input['timestamp_max_age'] ?? 86400 ) );
		$sanitized['notification_email']         = sanitize_email( $input['notification_email'] ?? '' );
		$sanitized['email_template']             = wp_kses_post( $input['email_template'] ?? '' );
		$sanitized['auto_reply_enabled']         = ! empty( $input['auto_reply_enabled'] );
		$sanitized['auto_reply_template']        = wp_kses_post( $input['auto_reply_template'] ?? '' );
		$sanitized['name_min_length']            = max( 1, absint( $input['name_min_length'] ?? 2 ) );
		$sanitized['name_max_length']            = max( 10, absint( $input['name_max_length'] ?? 100 ) );
		$sanitized['message_min_length']         = max( 1, absint( $input['message_min_length'] ?? 10 ) );
		$sanitized['message_max_length']         = max( 100, absint( $input['message_max_length'] ?? 5000 ) );
		$sanitized['subject_max_length']         = max( 10, absint( $input['subject_max_length'] ?? 200 ) );
		$sanitized['spam_keywords']              = sanitize_textarea_field( $input['spam_keywords'] ?? '' );
		$sanitized['block_urls']                 = ! empty( $input['block_urls'] );
		$sanitized['enable_logging']             = ! empty( $input['enable_logging'] );
		$sanitized['log_successful_submissions'] = ! empty( $input['log_successful_submissions'] );
		$sanitized['log_failed_attempts']        = ! empty( $input['log_failed_attempts'] );
		return $sanitized;
	}

	public function admin_scripts( $hook ) {
		if ( 'settings_page_maxsys-secure-email' !== $hook && 'tools_page_maxsys-form-submissions' !== $hook ) {
			return;
		}
		wp_enqueue_script( 'maxsys-secure-email-admin', MAXSYS_SECURE_EMAIL_URL . 'assets/admin.js', array( 'jquery' ), MAXSYS_SECURE_EMAIL_VERSION, true );
		wp_enqueue_style( 'maxsys-secure-email-admin', MAXSYS_SECURE_EMAIL_URL . 'assets/admin.css', array(), MAXSYS_SECURE_EMAIL_VERSION );
		wp_localize_script(
			'maxsys-secure-email-admin',
			'maxsysAjax',
			array(
				'ajaxurl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'maxsys_admin_nonce' ),
				'strings' => array(
					'testing'       => __( 'Testing...', 'maxsys-secure-email' ),
					'success'       => __( 'Success!', 'maxsys-secure-email' ),
					'error'         => __( 'Error:', 'maxsys-secure-email' ),
					'confirm_clear' => __( 'Are you sure you want to clear all rate limits?', 'maxsys-secure-email' ),
				),
			)
		);
	}

	public function configure_smtp( $phpmailer ) {
		if ( empty( $this->options['smtp_enabled'] ) ) {
			return;
		}
		$phpmailer->isSMTP();
		// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHPMailer's own property names.
		$phpmailer->Host     = $this->options['smtp_host'];
		$phpmailer->SMTPAuth = ! empty( $this->options['smtp_username'] );
		$phpmailer->Port     = (int) $this->options['smtp_port'];
		$phpmailer->Username = $this->options['smtp_username'];
		$phpmailer->Password = $this->options['smtp_password'];
		if ( 'none' !== $this->options['smtp_secure'] ) {
			$phpmailer->SMTPSecure = $this->options['smtp_secure'];
		}
		$phpmailer->From     = $this->options['smtp_from_email'];
		$phpmailer->FromName = $this->options['smtp_from_name'];

		// The mail server's certificate is checked unless the site owner has switched
		// that off, which is only for a server with a self-signed certificate.
		if ( empty( $this->options['smtp_verify_certificate'] ) ) {
			$phpmailer->SMTPOptions = array(
				'ssl' => array(
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'allow_self_signed' => true,
				),
			);
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			$phpmailer->SMTPDebug   = 2;
			$phpmailer->Debugoutput = function ( $str, $level ) {
				if ( false === stripos( $str, 'pass' ) && false === stripos( $str, 'auth' ) ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- only when the site owner has switched debug logging on.
					error_log( "SMTP Debug Level $level: $str" );
				}
			};
		}
		// phpcs:enable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
	}

	/**
	 * The origins allowed to call the form endpoint from a browser.
	 */
	private function allowed_origins() {
		$origins = array_filter( array_map( 'trim', explode( "\n", (string) $this->options['allowed_origins'] ) ) );
		// The site itself is always allowed.
		$origins[] = $this->site_origin();
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$origins = array_merge( $origins, array( 'http://localhost:3000', 'http://localhost:4321', 'http://localhost:8080' ) );
		}
		return array_values( array_unique( array_filter( array_map( 'untrailingslashit', $origins ) ) ) );
	}

	private function is_origin_allowed( $origin ) {
		return in_array( untrailingslashit( (string) $origin ), $this->allowed_origins(), true );
	}

	/**
	 * Cross-origin headers for this plugin's routes only. Other routes are left exactly
	 * as WordPress serves them.
	 */
	public function send_cors_headers( $served, $result, $request, $server ) {
		if ( ! ( $request instanceof WP_REST_Request ) || 0 !== strpos( $request->get_route(), '/' . self::REST_NAMESPACE ) ) {
			return $served;
		}

		$origin = get_http_origin();
		if ( $origin && $this->is_origin_allowed( $origin ) ) {
			header( 'Access-Control-Allow-Origin: ' . esc_url_raw( $origin ) );
			header( 'Vary: Origin', false );
		} else {
			header_remove( 'Access-Control-Allow-Origin' );
			header_remove( 'Access-Control-Allow-Credentials' );
		}
		header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS' );
		header( 'Access-Control-Allow-Headers: Content-Type' );
		header( 'Access-Control-Max-Age: 86400' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: DENY' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );

		return $served;
	}

	public function register_rest_routes() {
		register_rest_route(
			self::REST_NAMESPACE,
			'/submit',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_secure_contact' ),
				'permission_callback' => array( $this, 'check_origin' ),
			)
		);
		register_rest_route(
			self::REST_NAMESPACE,
			'/config',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_public_config' ),
				// Public by design: it returns only what a form needs to render.
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * The form endpoint is public, but a browser on another website may use it only if
	 * that website is in the allowed list. A caller that sends no Origin header is not a
	 * browser page on another site, and is let through to the other checks.
	 */
	public function check_origin() {
		$origin = get_http_origin();
		if ( $origin && ! $this->is_origin_allowed( $origin ) ) {
			return new WP_Error( 'origin_not_allowed', __( 'This website is not allowed to use this form.', 'maxsys-secure-email' ), array( 'status' => 403 ) );
		}
		return true;
	}

	public function get_public_config() {
		return rest_ensure_response(
			array(
				'recaptcha_enabled'    => $this->options['recaptcha_enabled'],
				'recaptcha_site_key'   => $this->options['recaptcha_site_key'],
				'honeypot_enabled'     => $this->options['honeypot_enabled'],
				'timestamp_validation' => $this->options['timestamp_validation'],
				'validation_rules'     => array(
					'name_min_length'    => $this->options['name_min_length'],
					'name_max_length'    => $this->options['name_max_length'],
					'message_min_length' => $this->options['message_min_length'],
					'message_max_length' => $this->options['message_max_length'],
					'subject_max_length' => $this->options['subject_max_length'],
				),
			)
		);
	}

	/**
	 * Count this attempt and say whether it is within the limit. All times are UTC.
	 */
	public function check_rate_limit( $ip, $endpoint ) {
		if ( empty( $this->options['rate_limit_enabled'] ) ) {
			return true;
		}
		global $wpdb;
		$table        = $wpdb->prefix . 'maxsys_rate_limits';
		$now_ts       = time();
		$now          = gmdate( 'Y-m-d H:i:s', $now_ts );
		$window_start = gmdate( 'Y-m-d H:i:s', $now_ts - (int) $this->options['rate_limit_window'] );
		$user_agent   = $this->get_user_agent();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table; a rate limit must not be cached.

		// Forget rows whose window has passed and whose block, if any, is over.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE last_attempt < %s AND ( blocked_until IS NULL OR blocked_until < %s )', $table, $window_start, $now ) );

		$blocked = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE ip_address = %s AND endpoint = %s AND blocked_until > %s', $table, $ip, $endpoint, $now ) );
		if ( $blocked > 0 ) {
			return false;
		}

		$current_attempts = $wpdb->get_var( $wpdb->prepare( 'SELECT attempts FROM %i WHERE ip_address = %s AND endpoint = %s AND last_attempt > %s', $table, $ip, $endpoint, $window_start ) );
		$attempts         = intval( $current_attempts ) + 1;
		$row              = array(
			'ip_address'    => $ip,
			'endpoint'      => $endpoint,
			'attempts'      => $attempts,
			'last_attempt'  => $now,
			'blocked_until' => null,
			'user_agent'    => $user_agent,
		);

		if ( $attempts > $this->options['rate_limit_attempts'] ) {
			$row['blocked_until'] = gmdate( 'Y-m-d H:i:s', $now_ts + (int) $this->options['rate_limit_block_duration'] );
			$wpdb->replace( $table, $row );
			return false;
		}
		$wpdb->replace( $table, $row );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return true;
	}

	public function verify_recaptcha( $token, $action = 'contact' ) {
		if ( empty( $this->options['recaptcha_enabled'] ) || empty( $this->options['recaptcha_secret_key'] ) ) {
			return true;
		}
		if ( empty( $token ) ) {
			return false;
		}
		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			array(
				'body'      => array(
					'secret'   => $this->options['recaptcha_secret_key'],
					'response' => $token,
					'remoteip' => $this->get_real_ip(),
				),
				'timeout'   => 10,
				'sslverify' => true,
			)
		);
		if ( is_wp_error( $response ) ) {
			$this->log_error( 'reCAPTCHA API error: ' . $response->get_error_message() );
			return false;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! isset( $data['success'] ) || ! $data['success'] || ( isset( $data['action'] ) && $data['action'] !== $action ) ) {
			$this->log_error( 'reCAPTCHA verification failed: ' . wp_json_encode( $data ) );
			return false;
		}
		if ( isset( $data['score'] ) && $data['score'] < $this->options['recaptcha_min_score'] ) {
			$this->log_error( "reCAPTCHA score too low: {$data['score']}" );
			return false;
		}
		return $data['score'] ?? 1.0;
	}

	/**
	 * One value from $_SERVER, cleaned, or an empty string.
	 */
	private function server_value( $key ) {
		return isset( $_SERVER[ $key ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) : '';
	}

	private function get_user_agent() {
		$agent = $this->server_value( 'HTTP_USER_AGENT' );
		return '' !== $agent ? $agent : 'unknown';
	}

	/**
	 * The caller's address.
	 *
	 * A header such as X-Forwarded-For is set by whoever sends the request, so it is
	 * believed only when the site owner has said the site sits behind that kind of proxy.
	 */
	public function get_real_ip() {
		$source = $this->options['ip_source'] ?? 'remote_addr';

		if ( in_array( $source, array( 'cloudflare', 'auto' ), true ) ) {
			$ip = $this->server_value( 'HTTP_CF_CONNECTING_IP' );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		if ( in_array( $source, array( 'forwarded', 'auto' ), true ) ) {
			$forwarded = $this->server_value( 'HTTP_X_FORWARDED_FOR' );
			if ( '' !== $forwarded ) {
				$ip = trim( explode( ',', $forwarded )[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		$ip = $this->server_value( 'REMOTE_ADDR' );
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}

		return '0.0.0.0';
	}

	public function validate_contact_input( $data ) {
		$errors      = array();
		$name_length = mb_strlen( (string) $data['name'] );
		if ( empty( $data['name'] ) || ! is_string( $data['name'] ) ) {
			$errors[] = __( 'Name is required', 'maxsys-secure-email' );
		} elseif ( $name_length < $this->options['name_min_length'] || $name_length > $this->options['name_max_length'] ) {
			/* translators: 1: minimum number of characters, 2: maximum number of characters. */
			$errors[] = sprintf( __( 'Name must be between %1$d and %2$d characters', 'maxsys-secure-email' ), $this->options['name_min_length'], $this->options['name_max_length'] );
		} elseif ( ! preg_match( '/^[\p{L}\p{M}\s\-\'\.]+$/u', $data['name'] ) ) {
			// Letters of any script, their combining marks, spaces, hyphens, apostrophes and full stops.
			$errors[] = __( 'Name contains invalid characters', 'maxsys-secure-email' );
		}

		if ( empty( $data['email'] ) || ! is_email( $data['email'] ) ) {
			$errors[] = __( 'Valid email address is required', 'maxsys-secure-email' );
		} elseif ( strlen( $data['email'] ) > 254 ) {
			$errors[] = __( 'Email address is too long', 'maxsys-secure-email' );
		}

		if ( ! empty( $data['phone'] ) && ! preg_match( '/^[\+]?[\d\s\-\(\)]{10,}$/', $data['phone'] ) ) {
			$errors[] = __( 'Invalid phone number format', 'maxsys-secure-email' );
		}

		$message_length = mb_strlen( (string) $data['message'] );
		if ( empty( $data['message'] ) || ! is_string( $data['message'] ) ) {
			$errors[] = __( 'Message is required', 'maxsys-secure-email' );
		} elseif ( $message_length < $this->options['message_min_length'] || $message_length > $this->options['message_max_length'] ) {
			/* translators: 1: minimum number of characters, 2: maximum number of characters. */
			$errors[] = sprintf( __( 'Message must be between %1$d and %2$d characters', 'maxsys-secure-email' ), $this->options['message_min_length'], $this->options['message_max_length'] );
		}

		if ( ! empty( $data['subject'] ) && mb_strlen( (string) $data['subject'] ) > $this->options['subject_max_length'] ) {
			/* translators: %d: maximum number of characters. */
			$errors[] = sprintf( __( 'Subject must be less than %d characters', 'maxsys-secure-email' ), $this->options['subject_max_length'] );
		}

		if ( $this->is_spam( $data ) ) {
			$errors[] = __( 'Message contains prohibited content', 'maxsys-secure-email' );
		}
		return $errors;
	}

	private function is_spam( $data ) {
		$spam_keywords = array_filter( array_map( 'trim', explode( "\n", strtolower( (string) $this->options['spam_keywords'] ) ) ) );
		$content       = strtolower( $data['message'] . ' ' . $data['name'] . ' ' . ( $data['subject'] ?? '' ) );
		foreach ( $spam_keywords as $keyword ) {
			if ( false !== strpos( $content, $keyword ) ) {
				return true;
			}
		}
		if ( ! empty( $this->options['block_urls'] ) && preg_match( '/(http:\/\/|https:\/\/|www\.)/i', $content ) ) {
			return true;
		}
		return false;
	}

	public function handle_secure_contact( WP_REST_Request $request ) {
		$ip         = $this->get_real_ip();
		$user_agent = $this->get_user_agent();

		if ( ! $this->check_rate_limit( $ip, 'contact_submit' ) ) {
			$this->log_error( "Rate limit exceeded for IP: $ip" );
			return new WP_Error( 'rate_limited', __( 'Too many requests. Please try again later.', 'maxsys-secure-email' ), array( 'status' => 429 ) );
		}

		$params = $request->get_json_params();
		if ( empty( $params ) ) {
			return new WP_Error( 'no_data', __( 'No form data received', 'maxsys-secure-email' ), array( 'status' => 400 ) );
		}

		if ( ! empty( $this->options['honeypot_enabled'] ) && ! empty( $params['website'] ) ) {
			$this->log_error( "Honeypot triggered from IP: $ip" );
			return new WP_Error( 'spam_detected', __( 'Spam detected', 'maxsys-secure-email' ), array( 'status' => 400 ) );
		}

		if ( ! empty( $this->options['timestamp_validation'] ) && isset( $params['timestamp'] ) ) {
			$submission_time = intval( $params['timestamp'] ) / 1000;
			$age             = time() - $submission_time;
			if ( $age > $this->options['timestamp_max_age'] || $age < 0 ) {
				return new WP_Error( 'invalid_timestamp', __( 'Form submission expired', 'maxsys-secure-email' ), array( 'status' => 400 ) );
			}
		}

		$data = array(
			'name'            => sanitize_text_field( $params['name'] ?? '' ),
			'email'           => sanitize_email( $params['email'] ?? '' ),
			'phone'           => sanitize_text_field( $params['phone'] ?? '' ),
			'message'         => sanitize_textarea_field( $params['message'] ?? '' ),
			'subject'         => sanitize_text_field( $params['subject'] ?? '' ),
			'recaptcha_token' => sanitize_text_field( $params['recaptcha_token'] ?? '' ),
		);

		$validation_errors = $this->validate_contact_input( $data );
		if ( ! empty( $validation_errors ) ) {
			return new WP_Error( 'validation_error', implode( ' | ', $validation_errors ), array( 'status' => 400 ) );
		}

		$recaptcha_score = $this->verify_recaptcha( $data['recaptcha_token'] );
		if ( false === $recaptcha_score ) {
			return new WP_Error( 'recaptcha_failed', __( 'Security verification failed', 'maxsys-secure-email' ), array( 'status' => 400 ) );
		}

		$submission_id = $this->store_submission( $data, $ip, $user_agent, $recaptcha_score );
		$email_sent    = $this->send_notification_email( $data, $ip, $user_agent );
		$this->set_submission_status( $submission_id, $email_sent ? 'sent' : 'failed' );

		if ( ! $email_sent ) {
			$this->log_error( 'Failed to send email notification' );
			return new WP_Error( 'mail_failed', __( 'Message could not be sent. Please try again.', 'maxsys-secure-email' ), array( 'status' => 500 ) );
		}

		if ( ! empty( $this->options['auto_reply_enabled'] ) ) {
			$this->send_auto_reply( $data );
		}

		$this->log_success( "Secure email sent successfully from $ip" );
		return rest_ensure_response(
			array(
				'status'        => 'success',
				'message'       => __( 'Thank you! Your message has been sent successfully.', 'maxsys-secure-email' ),
				'timestamp'     => current_time( 'mysql' ),
				'submission_id' => $submission_id,
			)
		);
	}

	private function store_submission( $data, $ip, $user_agent, $recaptcha_score ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'maxsys_form_submissions';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- the plugin's own table.
		$result = $wpdb->insert(
			$table_name,
			array(
				'name'            => $data['name'],
				'email'           => $data['email'],
				'phone'           => $data['phone'],
				'subject'         => $data['subject'],
				'message'         => $data['message'],
				'ip_address'      => $ip,
				'user_agent'      => $user_agent,
				'recaptcha_score' => $recaptcha_score,
				'status'          => 'received',
				'created_at'      => current_time( 'mysql' ),
			)
		);
		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Record whether the notification for a stored submission was sent.
	 */
	private function set_submission_status( $submission_id, $status ) {
		if ( ! $submission_id ) {
			return;
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table.
		$wpdb->update( $wpdb->prefix . 'maxsys_form_submissions', array( 'status' => $status ), array( 'id' => $submission_id ) );
	}

	private function send_notification_email( $data, $ip, $user_agent ) {
		$to      = $this->options['notification_email'];
		$subject = ! empty( $data['subject'] ) ? '[' . get_bloginfo( 'name' ) . '] ' . $data['subject'] : '[' . get_bloginfo( 'name' ) . '] ' . __( 'Message from', 'maxsys-secure-email' ) . ' ' . $data['name'];

		$template_vars = array(
			'{name}'            => $data['name'],
			'{email}'           => $data['email'],
			'{phone}'           => $data['phone'] ? $data['phone'] : __( 'Not provided', 'maxsys-secure-email' ),
			'{subject}'         => $data['subject'] ? $data['subject'] : __( 'No subject', 'maxsys-secure-email' ),
			'{message}'         => $data['message'],
			'{ip_address}'      => $ip,
			'{user_agent}'      => $user_agent,
			'{submission_time}' => current_time( 'mysql' ),
		);
		$body          = str_replace( array_keys( $template_vars ), array_values( $template_vars ), $this->options['email_template'] );
		$headers       = array( 'Reply-To: ' . $data['name'] . ' <' . $data['email'] . '>', 'Content-Type: text/plain; charset=UTF-8' );
		return wp_mail( $to, $subject, $body, $headers );
	}

	private function send_auto_reply( $data ) {
		$template_vars = array(
			'{name}'      => $data['name'],
			'{email}'     => $data['email'],
			'{site_name}' => get_bloginfo( 'name' ),
		);
		$body          = str_replace( array_keys( $template_vars ), array_values( $template_vars ), $this->options['auto_reply_template'] );
		/* translators: %s: the site's name. */
		$subject = sprintf( __( 'Thank you for contacting %s', 'maxsys-secure-email' ), get_bloginfo( 'name' ) );
		$headers = array( 'From: ' . $this->options['smtp_from_name'] . ' <' . $this->options['smtp_from_email'] . '>', 'Content-Type: text/plain; charset=UTF-8' );
		return wp_mail( $data['email'], $subject, $body, $headers );
	}

	private function log_error( $message ) {
		if ( ! empty( $this->options['enable_logging'] ) && ! empty( $this->options['log_failed_attempts'] ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- logging is a setting the site owner switches on.
			error_log( "MAXSYS Secure Email: $message" );
		}
	}

	private function log_success( $message ) {
		if ( ! empty( $this->options['enable_logging'] ) && ! empty( $this->options['log_successful_submissions'] ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- logging is a setting the site owner switches on.
			error_log( "MAXSYS Secure Email: $message" );
		}
	}

	public function test_smtp_connection() {
		check_ajax_referer( 'maxsys_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Unauthorized', 'maxsys-secure-email' ), 403 );
		}
		$test_email = isset( $_POST['test_email'] ) ? sanitize_email( wp_unslash( $_POST['test_email'] ) ) : '';
		if ( empty( $test_email ) ) {
			wp_send_json_error( __( 'Test email address is required', 'maxsys-secure-email' ), 400 );
		}
		$subject = __( 'MAXSYS SMTP Test', 'maxsys-secure-email' );
		$message = __( 'This is a test email to verify SMTP configuration.', 'maxsys-secure-email' );
		if ( wp_mail( $test_email, $subject, $message ) ) {
			wp_send_json_success( __( 'Test email sent successfully!', 'maxsys-secure-email' ) );
		} else {
			wp_send_json_error( __( 'Failed to send test email. Check your SMTP settings.', 'maxsys-secure-email' ), 500 );
		}
	}

	public function clear_rate_limits() {
		check_ajax_referer( 'maxsys_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Unauthorized', 'maxsys-secure-email' ), 403 );
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table.
		$cleared = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $wpdb->prefix . 'maxsys_rate_limits' ) );
		if ( false !== $cleared ) {
			wp_send_json_success( __( 'Rate limits cleared successfully!', 'maxsys-secure-email' ) );
		} else {
			wp_send_json_error( __( 'Failed to clear rate limits.', 'maxsys-secure-email' ), 500 );
		}
	}

	/**
	 * Print one table row of the settings form: a label and its field.
	 */
	private function row_open( $label ) {
		echo '<tr><th>' . esc_html( $label ) . '</th><td>';
	}

	private function row_close( $description = '' ) {
		if ( '' !== $description ) {
			echo '<p class="description">' . esc_html( $description ) . '</p>';
		}
		echo '</td></tr>';
	}

	private function field_name( $key ) {
		return 'maxsys_secure_email_options[' . $key . ']';
	}

	private function checkbox_row( $label, $key, $text, $description = '' ) {
		$this->row_open( $label );
		echo '<label><input type="checkbox" name="' . esc_attr( $this->field_name( $key ) ) . '" value="1" ' . checked( ! empty( $this->options[ $key ] ), true, false ) . '> ' . esc_html( $text ) . '</label>';
		$this->row_close( $description );
	}

	private function input_row( $label, $key, $type = 'text', $description = '', $attributes = '' ) {
		$this->row_open( $label );
		// $attributes is a fixed string written in this file, never user input.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<input type="' . esc_attr( $type ) . '" name="' . esc_attr( $this->field_name( $key ) ) . '" value="' . esc_attr( $this->options[ $key ] ) . '" ' . $attributes . '>';
		$this->row_close( $description );
	}

	private function secret_row( $label, $key, $description ) {
		$this->row_open( $label );
		$placeholder = ! empty( $this->options[ $key ] ) ? str_repeat( '*', 16 ) : '';
		echo '<input type="password" name="' . esc_attr( $this->field_name( $key ) ) . '" value="" class="regular-text" autocomplete="new-password" placeholder="' . esc_attr( $placeholder ) . '">';
		$this->row_close( $description );
	}

	private function textarea_row( $label, $key, $rows, $description = '' ) {
		$this->row_open( $label );
		echo '<textarea name="' . esc_attr( $this->field_name( $key ) ) . '" rows="' . esc_attr( $rows ) . '" class="large-text">' . esc_textarea( $this->options[ $key ] ) . '</textarea>';
		$this->row_close( $description );
	}

	public function admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		global $wpdb;
		$stored            = get_option( 'maxsys_secure_email_options', null );
		$legacy_ip_source  = 'auto' === $this->options['ip_source'];
		$certificate_off   = empty( $this->options['smtp_verify_certificate'] );
		$kept_from_upgrade = is_array( $stored ) && ( ! array_key_exists( 'ip_source', $stored ) || ! array_key_exists( 'smtp_verify_certificate', $stored ) );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'MAXSYS Secure Email Settings', 'maxsys-secure-email' ); ?></h1>
			<?php if ( $kept_from_upgrade ) : ?>
				<div class="notice notice-warning"><p><?php esc_html_e( 'Two safety settings were added in version 3.6.0. This site keeps behaving as it did before the update until you review them: "Check the mail server\'s certificate" on the SMTP tab, and "Visitor address" on the Security tab.', 'maxsys-secure-email' ); ?></p></div>
			<?php endif; ?>
			<form method="post" action="options.php">
				<?php settings_fields( 'maxsys_secure_email_options' ); ?>
				<div class="maxsys-admin-tabs">
					<nav class="nav-tab-wrapper">
						<a href="#smtp" class="nav-tab nav-tab-active"><?php esc_html_e( 'SMTP Settings', 'maxsys-secure-email' ); ?></a>
						<a href="#recaptcha" class="nav-tab"><?php esc_html_e( 'reCAPTCHA', 'maxsys-secure-email' ); ?></a>
						<a href="#security" class="nav-tab"><?php esc_html_e( 'Security', 'maxsys-secure-email' ); ?></a>
						<a href="#email" class="nav-tab"><?php esc_html_e( 'Email Templates', 'maxsys-secure-email' ); ?></a>
						<a href="#validation" class="nav-tab"><?php esc_html_e( 'Validation', 'maxsys-secure-email' ); ?></a>
						<a href="#advanced" class="nav-tab"><?php esc_html_e( 'Advanced', 'maxsys-secure-email' ); ?></a>
					</nav>

					<div id="smtp" class="tab-content">
						<h2><?php esc_html_e( 'SMTP Configuration', 'maxsys-secure-email' ); ?></h2>
						<table class="form-table">
							<?php
							$this->checkbox_row( __( 'Enable SMTP', 'maxsys-secure-email' ), 'smtp_enabled', __( 'Use custom SMTP settings', 'maxsys-secure-email' ) );
							$this->input_row( __( 'SMTP Host', 'maxsys-secure-email' ), 'smtp_host', 'text', __( 'e.g., smtp.gmail.com', 'maxsys-secure-email' ), 'class="regular-text"' );
							$this->input_row( __( 'SMTP Port', 'maxsys-secure-email' ), 'smtp_port', 'number', __( 'Common ports: 587 (TLS), 465 (SSL)', 'maxsys-secure-email' ), 'min="1" max="65535"' );

							$this->row_open( __( 'Encryption', 'maxsys-secure-email' ) );
							echo '<select name="' . esc_attr( $this->field_name( 'smtp_secure' ) ) . '">';
							echo '<option value="tls" ' . selected( $this->options['smtp_secure'], 'tls', false ) . '>TLS</option>';
							echo '<option value="ssl" ' . selected( $this->options['smtp_secure'], 'ssl', false ) . '>SSL</option>';
							echo '<option value="none" ' . selected( $this->options['smtp_secure'], 'none', false ) . '>' . esc_html__( 'None', 'maxsys-secure-email' ) . '</option>';
							echo '</select>';
							$this->row_close();

							$this->checkbox_row(
								__( 'Certificate', 'maxsys-secure-email' ),
								'smtp_verify_certificate',
								__( 'Check the mail server\'s certificate (recommended)', 'maxsys-secure-email' ),
								$certificate_off
									? __( 'Certificate checks are OFF. Mail, and the mail password, can be intercepted on the way to the server. Leave this off only if your mail server uses a self-signed certificate.', 'maxsys-secure-email' )
									: __( 'Switch this off only if your mail server uses a self-signed certificate.', 'maxsys-secure-email' )
							);

							$this->input_row( __( 'Username', 'maxsys-secure-email' ), 'smtp_username', 'text', '', 'class="regular-text" autocomplete="username"' );
							$this->secret_row( __( 'Password', 'maxsys-secure-email' ), 'smtp_password', __( 'Leave blank to keep the current password.', 'maxsys-secure-email' ) );
							$this->input_row( __( 'From Email', 'maxsys-secure-email' ), 'smtp_from_email', 'email', '', 'class="regular-text"' );
							$this->input_row( __( 'From Name', 'maxsys-secure-email' ), 'smtp_from_name', 'text', '', 'class="regular-text"' );

							$this->row_open( __( 'Test SMTP', 'maxsys-secure-email' ) );
							echo '<input type="email" id="test-email" placeholder="' . esc_attr__( 'Enter test email address', 'maxsys-secure-email' ) . '" class="regular-text"> ';
							echo '<button type="button" id="test-smtp" class="button">' . esc_html__( 'Send Test Email', 'maxsys-secure-email' ) . '</button>';
							echo '<div id="smtp-test-result"></div>';
							$this->row_close();
							?>
						</table>
					</div>

					<div id="recaptcha" class="tab-content" style="display:none;">
						<h2><?php esc_html_e( 'reCAPTCHA v3 Configuration', 'maxsys-secure-email' ); ?></h2>
						<p class="description"><?php esc_html_e( 'When reCAPTCHA is on, each submission sends its reCAPTCHA token and the visitor\'s address to Google to be scored.', 'maxsys-secure-email' ); ?></p>
						<table class="form-table">
							<?php
							$this->checkbox_row( __( 'Enable reCAPTCHA', 'maxsys-secure-email' ), 'recaptcha_enabled', __( 'Enable reCAPTCHA v3 protection', 'maxsys-secure-email' ) );

							$this->row_open( __( 'Site Key', 'maxsys-secure-email' ) );
							echo '<input type="text" name="' . esc_attr( $this->field_name( 'recaptcha_site_key' ) ) . '" value="' . esc_attr( $this->options['recaptcha_site_key'] ) . '" class="regular-text">';
							echo '<p class="description">' . esc_html__( 'Get your keys from', 'maxsys-secure-email' ) . ' <a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener noreferrer">Google reCAPTCHA</a></p>';
							echo '</td></tr>';

							$this->secret_row( __( 'Secret Key', 'maxsys-secure-email' ), 'recaptcha_secret_key', __( 'Leave blank to keep the current secret key.', 'maxsys-secure-email' ) );
							$this->input_row( __( 'Minimum Score', 'maxsys-secure-email' ), 'recaptcha_min_score', 'number', __( 'Score threshold (0.0 - 1.0, higher is more restrictive)', 'maxsys-secure-email' ), 'min="0" max="1" step="0.1"' );
							?>
						</table>
					</div>

					<div id="security" class="tab-content" style="display:none;">
						<h2><?php esc_html_e( 'Security Settings', 'maxsys-secure-email' ); ?></h2>
						<h3><?php esc_html_e( 'Rate Limiting', 'maxsys-secure-email' ); ?></h3>
						<table class="form-table">
							<?php
							$this->checkbox_row( __( 'Enable Rate Limiting', 'maxsys-secure-email' ), 'rate_limit_enabled', __( 'Limit submission attempts per IP', 'maxsys-secure-email' ) );
							$this->input_row( __( 'Max Attempts', 'maxsys-secure-email' ), 'rate_limit_attempts', 'number', __( 'Maximum attempts per time window', 'maxsys-secure-email' ), 'min="1" max="100"' );
							$this->input_row( __( 'Time Window (seconds)', 'maxsys-secure-email' ), 'rate_limit_window', 'number', __( 'Time window for counting attempts', 'maxsys-secure-email' ), 'min="60" max="3600"' );
							$this->input_row( __( 'Block Duration (seconds)', 'maxsys-secure-email' ), 'rate_limit_block_duration', 'number', __( 'How long to block IP after exceeding limits', 'maxsys-secure-email' ), 'min="300" max="86400"' );

							$sources = array(
								'remote_addr' => __( 'The connection itself (no proxy in front of this site)', 'maxsys-secure-email' ),
								'cloudflare'  => __( 'Cloudflare (the CF-Connecting-IP header)', 'maxsys-secure-email' ),
								'forwarded'   => __( 'A reverse proxy (the first X-Forwarded-For address)', 'maxsys-secure-email' ),
							);
							if ( $legacy_ip_source ) {
								$sources['auto'] = __( 'Any of these headers, as before 3.6.0 (a caller can forge its address)', 'maxsys-secure-email' );
							}
							$this->row_open( __( 'Visitor address', 'maxsys-secure-email' ) );
							echo '<select name="' . esc_attr( $this->field_name( 'ip_source' ) ) . '">';
							foreach ( $sources as $value => $text ) {
								echo '<option value="' . esc_attr( $value ) . '" ' . selected( $this->options['ip_source'], $value, false ) . '>' . esc_html( $text ) . '</option>';
							}
							echo '</select>';
							$this->row_close( __( 'Where the visitor\'s address is read from. A header is believed only if you choose it here, because any caller can send one. Choose the proxy this site really sits behind.', 'maxsys-secure-email' ) );

							$this->row_open( __( 'Clear Rate Limits', 'maxsys-secure-email' ) );
							echo '<button type="button" id="clear-rate-limits" class="button">' . esc_html__( 'Clear All Rate Limits', 'maxsys-secure-email' ) . '</button>';
							$this->row_close( __( 'Remove all current rate limiting blocks', 'maxsys-secure-email' ) );
							?>
						</table>
						<h3><?php esc_html_e( 'Allowed Websites', 'maxsys-secure-email' ); ?></h3>
						<table class="form-table">
							<?php $this->textarea_row( __( 'Allowed Origins', 'maxsys-secure-email' ), 'allowed_origins', 5, __( 'One origin per line (e.g., https://yourdomain.com). A browser page on any other website is refused. This site itself is always allowed.', 'maxsys-secure-email' ) ); ?>
						</table>
						<h3><?php esc_html_e( 'Additional Protection', 'maxsys-secure-email' ); ?></h3>
						<table class="form-table">
							<?php
							$this->checkbox_row( __( 'Honeypot Field', 'maxsys-secure-email' ), 'honeypot_enabled', __( 'Enable honeypot spam protection', 'maxsys-secure-email' ) );
							$this->checkbox_row( __( 'Timestamp Validation', 'maxsys-secure-email' ), 'timestamp_validation', __( 'Validate form submission timing', 'maxsys-secure-email' ) );
							$this->input_row( __( 'Max Form Age (seconds)', 'maxsys-secure-email' ), 'timestamp_max_age', 'number', __( 'Maximum time between form load and submission', 'maxsys-secure-email' ), 'min="300" max="86400"' );
							?>
						</table>
					</div>

					<div id="email" class="tab-content" style="display:none;">
						<h2><?php esc_html_e( 'Email Configuration', 'maxsys-secure-email' ); ?></h2>
						<table class="form-table">
							<?php
							$this->input_row( __( 'Notification Email', 'maxsys-secure-email' ), 'notification_email', 'email', __( 'Email address to receive form submissions', 'maxsys-secure-email' ), 'class="regular-text"' );
							$this->textarea_row( __( 'Email Template', 'maxsys-secure-email' ), 'email_template', 10, __( 'Available variables: {name}, {email}, {phone}, {subject}, {message}, {ip_address}, {user_agent}, {submission_time}', 'maxsys-secure-email' ) );
							$this->checkbox_row( __( 'Enable Auto-Reply', 'maxsys-secure-email' ), 'auto_reply_enabled', __( 'Send automatic reply to form submitters', 'maxsys-secure-email' ) );
							$this->textarea_row( __( 'Auto-Reply Template', 'maxsys-secure-email' ), 'auto_reply_template', 8, __( 'Available variables: {name}, {email}, {site_name}', 'maxsys-secure-email' ) );
							?>
						</table>
					</div>

					<div id="validation" class="tab-content" style="display:none;">
						<h2><?php esc_html_e( 'Form Validation Rules', 'maxsys-secure-email' ); ?></h2>
						<table class="form-table">
							<?php
							$this->input_row( __( 'Name: minimum length', 'maxsys-secure-email' ), 'name_min_length', 'number', '', 'min="1" max="50" style="width: 80px;"' );
							$this->input_row( __( 'Name: maximum length', 'maxsys-secure-email' ), 'name_max_length', 'number', '', 'min="10" max="500" style="width: 80px;"' );
							$this->input_row( __( 'Message: minimum length', 'maxsys-secure-email' ), 'message_min_length', 'number', '', 'min="1" max="100" style="width: 80px;"' );
							$this->input_row( __( 'Message: maximum length', 'maxsys-secure-email' ), 'message_max_length', 'number', '', 'min="100" max="10000" style="width: 80px;"' );
							$this->input_row( __( 'Subject Max Length', 'maxsys-secure-email' ), 'subject_max_length', 'number', '', 'min="10" max="500"' );
							?>
						</table>
						<h3><?php esc_html_e( 'Spam Protection', 'maxsys-secure-email' ); ?></h3>
						<table class="form-table">
							<?php
							$this->textarea_row( __( 'Spam Keywords', 'maxsys-secure-email' ), 'spam_keywords', 5, __( 'One keyword per line (case insensitive)', 'maxsys-secure-email' ) );
							$this->checkbox_row( __( 'Block URLs', 'maxsys-secure-email' ), 'block_urls', __( 'Block messages containing URLs', 'maxsys-secure-email' ) );
							?>
						</table>
					</div>

					<div id="advanced" class="tab-content" style="display:none;">
						<h2><?php esc_html_e( 'Advanced Settings', 'maxsys-secure-email' ); ?></h2>
						<h3><?php esc_html_e( 'Logging', 'maxsys-secure-email' ); ?></h3>
						<table class="form-table">
							<?php
							$this->checkbox_row( __( 'Enable Logging', 'maxsys-secure-email' ), 'enable_logging', __( 'Enable system logging', 'maxsys-secure-email' ) );
							$this->checkbox_row( __( 'Successful submissions', 'maxsys-secure-email' ), 'log_successful_submissions', __( 'Log successful form submissions', 'maxsys-secure-email' ) );
							$this->checkbox_row( __( 'Failed attempts', 'maxsys-secure-email' ), 'log_failed_attempts', __( 'Log failed attempts and security violations', 'maxsys-secure-email' ) );
							?>
						</table>
						<h3><?php esc_html_e( 'Database Statistics', 'maxsys-secure-email' ); ?></h3>
						<table class="form-table">
							<?php
							// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own tables, shown live.
							$total   = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $wpdb->prefix . 'maxsys_form_submissions' ) );
							$blocked = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE blocked_until IS NOT NULL', $wpdb->prefix . 'maxsys_rate_limits' ) );
							// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
							$this->row_open( __( 'Total Submissions', 'maxsys-secure-email' ) );
							echo esc_html( (string) (int) $total );
							$this->row_close();
							$this->row_open( __( 'Blocked Attempts', 'maxsys-secure-email' ) );
							echo esc_html( (string) (int) $blocked );
							$this->row_close();
							?>
						</table>
					</div>
				</div>
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
	}

	public function submissions_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		global $wpdb;
		$table_name = $wpdb->prefix . 'maxsys_form_submissions';
		$per_page   = 20;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a page number for a read-only list.
		$current_page = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;
		$offset       = ( $current_page - 1 ) * $per_page;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table, shown live.
		$total_items = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table_name ) );
		$submissions = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d', $table_name, $per_page, $offset ) );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Form Submissions', 'maxsys-secure-email' ); ?></h1>
			<table class="wp-list-table widefat fixed striped">
				<thead><tr>
					<th><?php esc_html_e( 'ID', 'maxsys-secure-email' ); ?></th>
					<th><?php esc_html_e( 'Name', 'maxsys-secure-email' ); ?></th>
					<th><?php esc_html_e( 'Email', 'maxsys-secure-email' ); ?></th>
					<th><?php esc_html_e( 'Subject', 'maxsys-secure-email' ); ?></th>
					<th><?php esc_html_e( 'Date', 'maxsys-secure-email' ); ?></th>
					<th><?php esc_html_e( 'Status', 'maxsys-secure-email' ); ?></th>
				</tr></thead>
				<tbody>
					<?php if ( empty( $submissions ) ) : ?>
						<tr><td colspan="6"><?php esc_html_e( 'No submissions found.', 'maxsys-secure-email' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $submissions as $submission ) : ?>
							<tr>
								<td><?php echo esc_html( $submission->id ); ?></td>
								<td><?php echo esc_html( $submission->name ); ?></td>
								<td><?php echo esc_html( $submission->email ); ?></td>
								<td><?php echo esc_html( $submission->subject ? $submission->subject : __( 'No subject', 'maxsys-secure-email' ) ); ?></td>
								<td><?php echo esc_html( $submission->created_at ); ?></td>
								<td><?php echo esc_html( $submission->status ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
			<?php
			$total_pages = (int) ceil( $total_items / $per_page );
			if ( $total_pages > 1 ) {
				echo '<div class="tablenav"><div class="tablenav-pages">';
				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => add_query_arg( 'paged', '%#%' ),
							'format'    => '?paged=%#%',
							'prev_text' => '&laquo;',
							'next_text' => '&raquo;',
							'total'     => $total_pages,
							'current'   => $current_page,
						)
					)
				);
				echo '</div></div>';
			}
			?>
		</div>
		<?php
	}
}

register_activation_hook( __FILE__, array( 'MAXSYS_Secure_Email', 'activate' ) );

MAXSYS_Secure_Email::get_instance();
