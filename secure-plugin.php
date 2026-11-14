<?php
/**
 * Plugin Name: MAXSYS Secure Email System
 * Description: Secure email system with SMTP support and advanced security features
 * Version: 3.5.5
 * Author: MAXSYS Dev Team
 * Requires at least: 5.0
 * Tested up to: 6.6
 * Requires PHP: 7.4
 * Text Domain: maxsys-secure-email
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) exit;

define('MAXSYS_PLUGIN_VERSION', '3.5.5');
define('MAXSYS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MAXSYS_PLUGIN_PATH', plugin_dir_path(__FILE__));

class MAXSYS_Secure_Email {
    private static $instance = null;
    public $options;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->options = get_option('maxsys_secure_email_options', $this->get_default_options());
        $this->init_hooks();
    }
    
    private function init_hooks() {
        add_action('init', [$this, 'init_security']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'admin_scripts']);
        add_action('phpmailer_init', [$this, 'configure_smtp']);
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        add_action('wp_ajax_maxsys_test_smtp', [$this, 'test_smtp_connection']);
        add_action('wp_ajax_maxsys_clear_rate_limits', [$this, 'clear_rate_limits']);
        add_action('rest_pre_serve_request', [$this, 'setup_cors'], 10, 4);
        add_action('plugins_loaded', [$this, 'load_textdomain']);
    }
    
    public function load_textdomain() {
        load_plugin_textdomain('maxsys-secure-email', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }
    
    public function init_security() {
        $this->create_rate_limit_table();
        $this->create_submissions_table();
    }
    
    private function get_default_options() {
        return [
            'smtp_enabled' => false,
            'smtp_host' => 'smtp.gmail.com',
            'smtp_port' => 587,
            'smtp_username' => '',
            'smtp_password' => '',
            'smtp_secure' => 'tls',
            'smtp_from_email' => get_option('admin_email'),
            'smtp_from_name' => get_bloginfo('name'),
            'recaptcha_enabled' => true,
            'recaptcha_site_key' => '',
            'recaptcha_secret_key' => '',
            'recaptcha_min_score' => 0.7,
            'rate_limit_enabled' => true,
            'rate_limit_attempts' => 3,
            'rate_limit_window' => 300,
            'rate_limit_block_duration' => 3600,
            'allowed_origins' => "https://maxsys.org\nhttps://www.maxsys.org",
            'honeypot_enabled' => true,
            'timestamp_validation' => true,
            'timestamp_max_age' => 86400,
            'notification_email' => get_option('admin_email'),
            'email_template' => $this->get_default_email_template(),
            'auto_reply_enabled' => false,
            'auto_reply_template' => $this->get_default_auto_reply(),
            'name_min_length' => 2,
            'name_max_length' => 100,
            'message_min_length' => 10,
            'message_max_length' => 5000,
            'subject_max_length' => 200,
            'spam_keywords' => "viagra\ncasino\npoker\nloan\ndebt\nclick here\nbuy now\nact now",
            'block_urls' => true,
            'enable_logging' => true,
            'log_successful_submissions' => true,
            'log_failed_attempts' => true,
        ];
    }
    
    private function get_default_email_template() {
        return "New secure contact form submission:\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nSubject: {subject}\nIP Address: {ip_address}\nUser Agent: {user_agent}\nSubmitted: {submission_time}\n\nMessage:\n{message}";
    }
    
    private function get_default_auto_reply() {
        return "Dear {name},\n\nThank you for contacting us. We have received your message and will respond as soon as possible.\n\nBest regards,\n" . get_bloginfo('name');
    }
    
    public function create_rate_limit_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'maxsys_rate_limits';
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS $table_name ( id mediumint(9) NOT NULL AUTO_INCREMENT, ip_address varchar(45) NOT NULL, endpoint varchar(100) NOT NULL, attempts int(11) DEFAULT 0, last_attempt datetime DEFAULT CURRENT_TIMESTAMP, blocked_until datetime NULL, user_agent text, PRIMARY KEY (id), UNIQUE KEY ip_endpoint (ip_address, endpoint), KEY blocked_until (blocked_until), KEY last_attempt (last_attempt) ) $charset_collate;";
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    public function create_submissions_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'maxsys_form_submissions';
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS $table_name ( id mediumint(9) NOT NULL AUTO_INCREMENT, name varchar(100) NOT NULL, email varchar(254) NOT NULL, phone varchar(50), subject varchar(200), message text NOT NULL, ip_address varchar(45) NOT NULL, user_agent text, recaptcha_score decimal(3,2), status varchar(20) DEFAULT 'sent', created_at datetime DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id), KEY email (email), KEY ip_address (ip_address), KEY created_at (created_at), KEY status (status) ) $charset_collate;";
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    public function add_admin_menu() {
        add_options_page(__('MAXSYS Secure Email', 'maxsys-secure-email'), __('Secure Email', 'maxsys-secure-email'), 'manage_options', 'maxsys-secure-email', [$this, 'admin_page']);
        add_management_page(__('Form Submissions', 'maxsys-secure-email'), __('Form Submissions', 'maxsys-secure-email'), 'manage_options', 'maxsys-form-submissions', [$this, 'submissions_page']);
    }
    
    public function register_settings() {
        register_setting('maxsys_secure_email_options', 'maxsys_secure_email_options', ['sanitize_callback' => [$this, 'sanitize_options']]);
    }
    
    public function sanitize_options($input) {
        $sanitized = [];
        $current_options = $this->options;
        if (!is_array($input)) { return $current_options; }

        $sanitized['smtp_password'] = (!empty($input['smtp_password'])) ? sanitize_text_field($input['smtp_password']) : ($current_options['smtp_password'] ?? '');
        $sanitized['recaptcha_secret_key'] = (!empty($input['recaptcha_secret_key'])) ? sanitize_text_field($input['recaptcha_secret_key']) : ($current_options['recaptcha_secret_key'] ?? '');

        $sanitized['smtp_enabled'] = !empty($input['smtp_enabled']);
        $sanitized['smtp_host'] = sanitize_text_field($input['smtp_host'] ?? '');
        $sanitized['smtp_port'] = absint($input['smtp_port'] ?? 587);
        $sanitized['smtp_username'] = sanitize_text_field($input['smtp_username'] ?? '');
        $sanitized['smtp_secure'] = in_array($input['smtp_secure'] ?? 'tls', ['tls', 'ssl', 'none']) ? $input['smtp_secure'] : 'tls';
        $sanitized['smtp_from_email'] = sanitize_email($input['smtp_from_email'] ?? '');
        $sanitized['smtp_from_name'] = sanitize_text_field($input['smtp_from_name'] ?? '');
        $sanitized['recaptcha_enabled'] = !empty($input['recaptcha_enabled']);
        $sanitized['recaptcha_site_key'] = sanitize_text_field($input['recaptcha_site_key'] ?? '');
        $sanitized['recaptcha_min_score'] = max(0, min(1, floatval($input['recaptcha_min_score'] ?? 0.7)));
        $sanitized['rate_limit_enabled'] = !empty($input['rate_limit_enabled']);
        $sanitized['rate_limit_attempts'] = max(1, absint($input['rate_limit_attempts'] ?? 3));
        $sanitized['rate_limit_window'] = max(60, absint($input['rate_limit_window'] ?? 300));
        $sanitized['rate_limit_block_duration'] = max(300, absint($input['rate_limit_block_duration'] ?? 3600));
        $sanitized['allowed_origins'] = sanitize_textarea_field($input['allowed_origins'] ?? '');
        $sanitized['honeypot_enabled'] = !empty($input['honeypot_enabled']);
        $sanitized['timestamp_validation'] = !empty($input['timestamp_validation']);
        $sanitized['timestamp_max_age'] = max(300, absint($input['timestamp_max_age'] ?? 86400));
        $sanitized['notification_email'] = sanitize_email($input['notification_email'] ?? '');
        $sanitized['email_template'] = wp_kses_post($input['email_template'] ?? '');
        $sanitized['auto_reply_enabled'] = !empty($input['auto_reply_enabled']);
        $sanitized['auto_reply_template'] = wp_kses_post($input['auto_reply_template'] ?? '');
        $sanitized['name_min_length'] = max(1, absint($input['name_min_length'] ?? 2));
        $sanitized['name_max_length'] = max(10, absint($input['name_max_length'] ?? 100));
        $sanitized['message_min_length'] = max(1, absint($input['message_min_length'] ?? 10));
        $sanitized['message_max_length'] = max(100, absint($input['message_max_length'] ?? 5000));
        $sanitized['subject_max_length'] = max(10, absint($input['subject_max_length'] ?? 200));
        $sanitized['spam_keywords'] = sanitize_textarea_field($input['spam_keywords'] ?? '');
        $sanitized['block_urls'] = !empty($input['block_urls']);
        $sanitized['enable_logging'] = !empty($input['enable_logging']);
        $sanitized['log_successful_submissions'] = !empty($input['log_successful_submissions']);
        $sanitized['log_failed_attempts'] = !empty($input['log_failed_attempts']);
        return $sanitized;
    }
    
    public function admin_scripts($hook) {
        if ($hook !== 'settings_page_maxsys-secure-email' && $hook !== 'tools_page_maxsys-form-submissions') {
            return;
        }
        wp_enqueue_script('maxsys-admin', MAXSYS_PLUGIN_URL . 'assets/admin.js', ['jquery'], MAXSYS_PLUGIN_VERSION, true);
        wp_enqueue_style('maxsys-admin', MAXSYS_PLUGIN_URL . 'assets/admin.css', [], MAXSYS_PLUGIN_VERSION);
        wp_localize_script('maxsys-admin', 'maxsysAjax', [ 'ajaxurl' => admin_url('admin-ajax.php'), 'nonce' => wp_create_nonce('maxsys_admin_nonce'), 'strings' => [ 'testing' => __('Testing...', 'maxsys-secure-email'), 'success' => __('Success!', 'maxsys-secure-email'), 'error' => __('Error:', 'maxsys-secure-email'), 'confirm_clear' => __('Are you sure you want to clear all rate limits?', 'maxsys-secure-email'), ] ]);
    }
    
    public function configure_smtp($phpmailer) {
        if (!$this->options['smtp_enabled']) { return; }
        $phpmailer->isSMTP();
        $phpmailer->Host = $this->options['smtp_host'];
        $phpmailer->SMTPAuth = !empty($this->options['smtp_username']);
        $phpmailer->Port = (int)$this->options['smtp_port'];
        $phpmailer->Username = $this->options['smtp_username'];
        $phpmailer->Password = $this->options['smtp_password'];
        if ($this->options['smtp_secure'] !== 'none') { $phpmailer->SMTPSecure = $this->options['smtp_secure']; }
        $phpmailer->From = $this->options['smtp_from_email'];
        $phpmailer->FromName = $this->options['smtp_from_name'];
        $phpmailer->SMTPOptions = ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]];
        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            $phpmailer->SMTPDebug = 2;
            $phpmailer->Debugoutput = function($str, $level) { if (stripos($str, 'pass') === false && stripos($str, 'auth') === false) { error_log("SMTP Debug Level $level: $str"); } };
        }
    }
    
    public function setup_cors() {
        remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
        add_filter('rest_pre_serve_request', [$this, 'send_cors_headers']);
    }
    
    public function send_cors_headers($value) {
        $origin = get_http_origin();
        $allowed_origins = array_filter(array_map('trim', explode("\n", $this->options['allowed_origins'])));
        if (defined('WP_DEBUG') && WP_DEBUG) { $allowed_origins = array_merge($allowed_origins, ['http://localhost:3000', 'http://localhost:4321', 'http://localhost:8080']); }
        if ($origin && in_array($origin, $allowed_origins, true)) { header('Access-Control-Allow-Origin: ' . esc_url_raw($origin)); }
        header('Access-Control-Allow-Methods: POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-WP-Nonce, X-API-Secret');
        header('Access-Control-Max-Age: 86400');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { status_header(200); exit(); }
        return $value;
    }
    
    public function register_rest_routes() {
        register_rest_route('maxsys-contact/v1', '/submit', ['methods' => 'POST', 'callback' => [$this, 'handle_secure_contact'], 'permission_callback' => '__return_true']);
        register_rest_route('maxsys-contact/v1', '/config', ['methods' => 'GET', 'callback' => [$this, 'get_public_config'], 'permission_callback' => '__return_true']);
    }
    
    public function get_public_config() {
        return rest_ensure_response(['recaptcha_enabled' => $this->options['recaptcha_enabled'], 'recaptcha_site_key' => $this->options['recaptcha_site_key'], 'honeypot_enabled' => $this->options['honeypot_enabled'], 'timestamp_validation' => $this->options['timestamp_validation'], 'validation_rules' => ['name_min_length' => $this->options['name_min_length'], 'name_max_length' => $this->options['name_max_length'], 'message_min_length' => $this->options['message_min_length'], 'message_max_length' => $this->options['message_max_length'], 'subject_max_length' => $this->options['subject_max_length']]]);
    }
    
    public function check_rate_limit($ip, $endpoint) {
        if (!$this->options['rate_limit_enabled']) return true;
        global $wpdb; $table_name = $wpdb->prefix . 'maxsys_rate_limits'; $current_time = current_time('mysql');
        $window_start = date('Y-m-d H:i:s', strtotime("-{$this->options['rate_limit_window']} seconds"));
        $wpdb->delete($table_name, ['last_attempt' => ['<', $window_start]]);
        $blocked = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table_name WHERE ip_address = %s AND endpoint = %s AND blocked_until > %s", $ip, $endpoint, $current_time));
        if ($blocked > 0) return false;
        $current_attempts = $wpdb->get_var($wpdb->prepare("SELECT attempts FROM $table_name WHERE ip_address = %s AND endpoint = %s AND last_attempt > %s", $ip, $endpoint, $window_start));
        $attempts = intval($current_attempts) + 1;
        if ($attempts > $this->options['rate_limit_attempts']) {
            $blocked_until = date('Y-m-d H:i:s', strtotime("+{$this->options['rate_limit_block_duration']} seconds"));
            $wpdb->replace($table_name, ['ip_address' => $ip, 'endpoint' => $endpoint, 'attempts' => $attempts, 'last_attempt' => $current_time, 'blocked_until' => $blocked_until, 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '']);
            return false;
        }
        $wpdb->replace($table_name, ['ip_address' => $ip, 'endpoint' => $endpoint, 'attempts' => $attempts, 'last_attempt' => $current_time, 'blocked_until' => null, 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '']);
        return true;
    }
    
    public function verify_recaptcha($token, $action = 'contact') {
        if (!$this->options['recaptcha_enabled'] || empty($this->options['recaptcha_secret_key'])) return true;
        if (empty($token)) return false;
        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', ['body' => ['secret' => $this->options['recaptcha_secret_key'], 'response' => $token, 'remoteip' => $this->get_real_ip()], 'timeout' => 10, 'sslverify' => true]);
        if (is_wp_error($response)) { $this->log_error('reCAPTCHA API error: ' . $response->get_error_message()); return false; }
        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!isset($data['success']) || !$data['success'] || (isset($data['action']) && $data['action'] !== $action)) { $this->log_error('reCAPTCHA verification failed: ' . wp_json_encode($data)); return false; }
        if (isset($data['score']) && $data['score'] < $this->options['recaptcha_min_score']) { $this->log_error("reCAPTCHA score too low: {$data['score']}"); return false; }
        return $data['score'] ?? 1.0;
    }
    
public function get_real_ip() {
    // In a Cloudflare environment, 'HTTP_CF_CONNECTING_IP' is the most reliable source for the user's IP.
    // We prioritize it above all others.
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }

    // Fallback for non-Cloudflare proxies. Takes the first IP in the list.
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }

    // Final fallback to the direct connection IP.
    if (!empty($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
        return $_SERVER['REMOTE_ADDR'];
    }

    return '0.0.0.0'; // Return a default if no valid IP is found
}
    
    public function validate_contact_input($data) {
        $errors = [];
        if (empty($data['name']) || !is_string($data['name'])) { $errors[] = __('Name is required', 'maxsys-secure-email'); } elseif (strlen($data['name']) < $this->options['name_min_length'] || strlen($data['name']) > $this->options['name_max_length']) { $errors[] = sprintf(__('Name must be between %d and %d characters', 'maxsys-secure-email'), $this->options['name_min_length'], $this->options['name_max_length']); } elseif (!preg_match('/^[a-zA-Z\s\-\'\.]+$/u', $data['name'])) { $errors[] = __('Name contains invalid characters', 'maxsys-secure-email'); }
        if (empty($data['email']) || !is_email($data['email'])) { $errors[] = __('Valid email address is required', 'maxsys-secure-email'); } elseif (strlen($data['email']) > 254) { $errors[] = __('Email address is too long', 'maxsys-secure-email'); }
        if (!empty($data['phone']) && !preg_match('/^[\+]?[\d\s\-\(\)]{10,}$/', $data['phone'])) { $errors[] = __('Invalid phone number format', 'maxsys-secure-email'); }
        if (empty($data['message']) || !is_string($data['message'])) { $errors[] = __('Message is required', 'maxsys-secure-email'); } elseif (strlen($data['message']) < $this->options['message_min_length'] || strlen($data['message']) > $this->options['message_max_length']) { $errors[] = sprintf(__('Message must be between %d and %d characters', 'maxsys-secure-email'), $this->options['message_min_length'], $this->options['message_max_length']); }
        if (!empty($data['subject']) && strlen($data['subject']) > $this->options['subject_max_length']) { $errors[] = sprintf(__('Subject must be less than %d characters', 'maxsys-secure-email'), $this->options['subject_max_length']); }
        if ($this->is_spam($data)) { $errors[] = __('Message contains prohibited content', 'maxsys-secure-email'); }
        return $errors;
    }
    
    private function is_spam($data) {
        $spam_keywords = array_filter(array_map('trim', explode("\n", strtolower($this->options['spam_keywords']))));
        $content = strtolower($data['message'] . ' ' . $data['name'] . ' ' . ($data['subject'] ?? ''));
        foreach ($spam_keywords as $keyword) { if (strpos($content, $keyword) !== false) return true; }
        if ($this->options['block_urls'] && preg_match('/(http:\/\/|https:\/\/|www\.)/i', $content)) return true;
        return false;
    }
    
    public function handle_secure_contact(WP_REST_Request $request) {
        $ip = $this->get_real_ip(); $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        if (!$this->check_rate_limit($ip, 'contact_submit')) { $this->log_error("Rate limit exceeded for IP: $ip"); return new WP_Error('rate_limited', __('Too many requests. Please try again later.', 'maxsys-secure-email'), ['status' => 429]); }
        $params = $request->get_json_params();
        if (empty($params)) return new WP_Error('no_data', __('No form data received', 'maxsys-secure-email'), ['status' => 400]);
        if ($this->options['honeypot_enabled'] && !empty($params['website'])) { $this->log_error("Honeypot triggered from IP: $ip"); return new WP_Error('spam_detected', __('Spam detected', 'maxsys-secure-email'), ['status' => 400]); }
        if ($this->options['timestamp_validation'] && isset($params['timestamp'])) { $submission_time = intval($params['timestamp']) / 1000; $age = time() - $submission_time; if ($age > $this->options['timestamp_max_age'] || $age < 0) return new WP_Error('invalid_timestamp', __('Form submission expired', 'maxsys-secure-email'), ['status' => 400]); }
        $data = ['name' => sanitize_text_field($params['name'] ?? ''), 'email' => sanitize_email($params['email'] ?? ''), 'phone' => sanitize_text_field($params['phone'] ?? ''), 'message' => sanitize_textarea_field($params['message'] ?? ''), 'subject' => sanitize_text_field($params['subject'] ?? ''), 'recaptcha_token' => sanitize_text_field($params['recaptcha_token'] ?? '')];
        $validation_errors = $this->validate_contact_input($data);
        if (!empty($validation_errors)) return new WP_Error('validation_error', implode(' | ', $validation_errors), ['status' => 400]);
        $recaptcha_score = $this->verify_recaptcha($data['recaptcha_token']);
        if ($recaptcha_score === false) return new WP_Error('recaptcha_failed', __('Security verification failed', 'maxsys-secure-email'), ['status' => 400]);
        $submission_id = $this->store_submission($data, $ip, $user_agent, $recaptcha_score);
        $email_sent = $this->send_notification_email($data, $ip, $user_agent);
        if ($this->options['auto_reply_enabled'] && $email_sent) $this->send_auto_reply($data);
        if (!$email_sent) { $this->log_error("Failed to send email notification"); return new WP_Error('mail_failed', __('Message could not be sent. Please try again.', 'maxsys-secure-email'), ['status' => 500]); }
        $this->log_success("Secure email sent successfully from $ip");
        return rest_ensure_response(['status' => 'success', 'message' => __('Thank you! Your message has been sent successfully.', 'maxsys-secure-email'), 'timestamp' => current_time('mysql'), 'submission_id' => $submission_id]);
    }
    
    private function store_submission($data, $ip, $user_agent, $recaptcha_score) {
        global $wpdb; $table_name = $wpdb->prefix . 'maxsys_form_submissions';
        $result = $wpdb->insert($table_name, ['name' => $data['name'], 'email' => $data['email'], 'phone' => $data['phone'], 'subject' => $data['subject'], 'message' => $data['message'], 'ip_address' => $ip, 'user_agent' => $user_agent, 'recaptcha_score' => $recaptcha_score, 'status' => 'sent', 'created_at' => current_time('mysql')]);
        return $result ? $wpdb->insert_id : false;
    }
    
    private function send_notification_email($data, $ip, $user_agent) {
        $to = $this->options['notification_email'];
        $subject = !empty($data['subject']) ? "[" . get_bloginfo('name') . "] " . $data['subject'] : "[" . get_bloginfo('name') . "] " . __('Message from', 'maxsys-secure-email') . " " . $data['name'];
        $template_vars = ['{name}' => $data['name'], '{email}' => $data['email'], '{phone}' => $data['phone'] ?: __('Not provided', 'maxsys-secure-email'), '{subject}' => $data['subject'] ?: __('No subject', 'maxsys-secure-email'), '{message}' => $data['message'], '{ip_address}' => $ip, '{user_agent}' => $user_agent, '{submission_time}' => current_time('mysql')];
        $body = str_replace(array_keys($template_vars), array_values($template_vars), $this->options['email_template']);
        $headers = ['Reply-To: ' . $data['name'] . " <" . $data['email'] . ">", 'Content-Type: text/plain; charset=UTF-8'];
        return wp_mail($to, $subject, $body, $headers);
    }
    
    private function send_auto_reply($data) {
        $template_vars = ['{name}' => $data['name'], '{email}' => $data['email'], '{site_name}' => get_bloginfo('name')];
        $body = str_replace(array_keys($template_vars), array_values($template_vars), $this->options['auto_reply_template']);
        $subject = sprintf(__('Thank you for contacting %s', 'maxsys-secure-email'), get_bloginfo('name'));
        $headers = ['From: ' . $this->options['smtp_from_name'] . " <" . $this->options['smtp_from_email'] . ">", 'Content-Type: text/plain; charset=UTF-8'];
        return wp_mail($data['email'], $subject, $body, $headers);
    }
    
    private function log_error($message) { if ($this->options['enable_logging'] && $this->options['log_failed_attempts']) error_log("MAXSYS Secure Email: $message"); }
    private function log_success($message) { if ($this->options['enable_logging'] && $this->options['log_successful_submissions']) error_log("MAXSYS Secure Email: $message"); }
    
    public function test_smtp_connection() {
        check_ajax_referer('maxsys_admin_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error(__('Unauthorized', 'maxsys-secure-email'), 403);
        $test_email = sanitize_email($_POST['test_email'] ?? '');
        if (empty($test_email)) wp_send_json_error(__('Test email address is required', 'maxsys-secure-email'), 400);
        $subject = __('MAXSYS SMTP Test', 'maxsys-secure-email');
        $message = __('This is a test email to verify SMTP configuration.', 'maxsys-secure-email');
        if (wp_mail($test_email, $subject, $message)) wp_send_json_success(__('Test email sent successfully!', 'maxsys-secure-email'));
        else wp_send_json_error(__('Failed to send test email. Check your SMTP settings.', 'maxsys-secure-email'), 500);
    }
    
    public function clear_rate_limits() {
        check_ajax_referer('maxsys_admin_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error(__('Unauthorized', 'maxsys-secure-email'), 403);
        global $wpdb; $table_name = $wpdb->prefix . 'maxsys_rate_limits';
        if ($wpdb->query("TRUNCATE TABLE $table_name") !== false) wp_send_json_success(__('Rate limits cleared successfully!', 'maxsys-secure-email'));
        else wp_send_json_error(__('Failed to clear rate limits.', 'maxsys-secure-email'), 500);
    }
    
    public function admin_page() {
        ?>
        <div class="wrap">
            <h1><?php _e('MAXSYS Secure Email Settings', 'maxsys-secure-email'); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields('maxsys_secure_email_options'); ?>
                <div class="maxsys-admin-tabs">
                    <nav class="nav-tab-wrapper">
                        <a href="#smtp" class="nav-tab nav-tab-active"><?php _e('SMTP Settings', 'maxsys-secure-email'); ?></a>
                        <a href="#recaptcha" class="nav-tab"><?php _e('reCAPTCHA', 'maxsys-secure-email'); ?></a>
                        <a href="#security" class="nav-tab"><?php _e('Security', 'maxsys-secure-email'); ?></a>
                        <a href="#email" class="nav-tab"><?php _e('Email Templates', 'maxsys-secure-email'); ?></a>
                        <a href="#validation" class="nav-tab"><?php _e('Validation', 'maxsys-secure-email'); ?></a>
                        <a href="#advanced" class="nav-tab"><?php _e('Advanced', 'maxsys-secure-email'); ?></a>
                    </nav>
                    <div id="smtp" class="tab-content">
                        <h2><?php _e('SMTP Configuration', 'maxsys-secure-email'); ?></h2>
                        <table class="form-table">
                            <tr><th><?php _e('Enable SMTP', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[smtp_enabled]" value="1" <?php checked($this->options['smtp_enabled']); ?>> <?php _e('Use custom SMTP settings', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('SMTP Host', 'maxsys-secure-email'); ?></th><td><input type="text" name="maxsys_secure_email_options[smtp_host]" value="<?php echo esc_attr($this->options['smtp_host']); ?>" class="regular-text"><p class="description"><?php _e('e.g., smtp.gmail.com', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('SMTP Port', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[smtp_port]" value="<?php echo esc_attr($this->options['smtp_port']); ?>" min="1" max="65535"><p class="description"><?php _e('Common ports: 587 (TLS), 465 (SSL)', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Encryption', 'maxsys-secure-email'); ?></th><td><select name="maxsys_secure_email_options[smtp_secure]"><option value="tls" <?php selected($this->options['smtp_secure'], 'tls'); ?>>TLS</option><option value="ssl" <?php selected($this->options['smtp_secure'], 'ssl'); ?>>SSL</option><option value="none" <?php selected($this->options['smtp_secure'], 'none'); ?>><?php _e('None', 'maxsys-secure-email'); ?></option></select></td></tr>
                            <tr><th><?php _e('Username', 'maxsys-secure-email'); ?></th><td><input type="text" name="maxsys_secure_email_options[smtp_username]" value="<?php echo esc_attr($this->options['smtp_username']); ?>" class="regular-text" autocomplete="username"></td></tr>
                            <tr><th><?php _e('Password', 'maxsys-secure-email'); ?></th><td><input type="password" name="maxsys_secure_email_options[smtp_password]" value="" class="regular-text" autocomplete="new-password" placeholder="<?php echo !empty($this->options['smtp_password']) ? 'â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢' : ''; ?>"><p class="description"><?php _e('Leave blank to keep the current password.', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('From Email', 'maxsys-secure-email'); ?></th><td><input type="email" name="maxsys_secure_email_options[smtp_from_email]" value="<?php echo esc_attr($this->options['smtp_from_email']); ?>" class="regular-text"></td></tr>
                            <tr><th><?php _e('From Name', 'maxsys-secure-email'); ?></th><td><input type="text" name="maxsys_secure_email_options[smtp_from_name]" value="<?php echo esc_attr($this->options['smtp_from_name']); ?>" class="regular-text"></td></tr>
                            <tr><th><?php _e('Test SMTP', 'maxsys-secure-email'); ?></th><td><input type="email" id="test-email" placeholder="<?php _e('Enter test email address', 'maxsys-secure-email'); ?>" class="regular-text"><button type="button" id="test-smtp" class="button"><?php _e('Send Test Email', 'maxsys-secure-email'); ?></button><div id="smtp-test-result"></div></td></tr>
                        </table>
                    </div>
                    <div id="recaptcha" class="tab-content" style="display:none;">
                        <h2><?php _e('reCAPTCHA v3 Configuration', 'maxsys-secure-email'); ?></h2>
                        <table class="form-table">
                            <tr><th><?php _e('Enable reCAPTCHA', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[recaptcha_enabled]" value="1" <?php checked($this->options['recaptcha_enabled']); ?>> <?php _e('Enable reCAPTCHA v3 protection', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('Site Key', 'maxsys-secure-email'); ?></th><td><input type="text" name="maxsys_secure_email_options[recaptcha_site_key]" value="<?php echo esc_attr($this->options['recaptcha_site_key']); ?>" class="regular-text"><p class="description"><?php _e('Get your keys from', 'maxsys-secure-email'); ?> <a href="https://www.google.com/recaptcha/admin" target="_blank">Google reCAPTCHA</a></p></td></tr>
                            <tr><th><?php _e('Secret Key', 'maxsys-secure-email'); ?></th><td><input type="password" name="maxsys_secure_email_options[recaptcha_secret_key]" value="" class="regular-text" autocomplete="off" placeholder="<?php echo !empty($this->options['recaptcha_secret_key']) ? 'â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢' : ''; ?>"><p class="description"><?php _e('Leave blank to keep the current secret key.', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Minimum Score', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[recaptcha_min_score]" value="<?php echo esc_attr($this->options['recaptcha_min_score']); ?>" min="0" max="1" step="0.1"><p class="description"><?php _e('Score threshold (0.0 - 1.0, higher is more restrictive)', 'maxsys-secure-email'); ?></p></td></tr>
                        </table>
                    </div>
                    <div id="security" class="tab-content" style="display:none;">
                        <h2><?php _e('Security Settings', 'maxsys-secure-email'); ?></h2>
                        <h3><?php _e('Rate Limiting', 'maxsys-secure-email'); ?></h3>
                        <table class="form-table">
                            <tr><th><?php _e('Enable Rate Limiting', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[rate_limit_enabled]" value="1" <?php checked($this->options['rate_limit_enabled']); ?>> <?php _e('Limit submission attempts per IP', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('Max Attempts', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[rate_limit_attempts]" value="<?php echo esc_attr($this->options['rate_limit_attempts']); ?>" min="1" max="100"><p class="description"><?php _e('Maximum attempts per time window', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Time Window (seconds)', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[rate_limit_window]" value="<?php echo esc_attr($this->options['rate_limit_window']); ?>" min="60" max="3600"><p class="description"><?php _e('Time window for counting attempts', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Block Duration (seconds)', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[rate_limit_block_duration]" value="<?php echo esc_attr($this->options['rate_limit_block_duration']); ?>" min="300" max="86400"><p class="description"><?php _e('How long to block IP after exceeding limits', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Clear Rate Limits', 'maxsys-secure-email'); ?></th><td><button type="button" id="clear-rate-limits" class="button"><?php _e('Clear All Rate Limits', 'maxsys-secure-email'); ?></button><p class="description"><?php _e('Remove all current rate limiting blocks', 'maxsys-secure-email'); ?></p></td></tr>
                        </table>
                        <h3><?php _e('CORS Settings', 'maxsys-secure-email'); ?></h3>
                        <table class="form-table">
                            <tr><th><?php _e('Allowed Origins', 'maxsys-secure-email'); ?></th><td><textarea name="maxsys_secure_email_options[allowed_origins]" rows="5" class="large-text"><?php echo esc_textarea($this->options['allowed_origins']); ?></textarea><p class="description"><?php _e('One origin per line (e.g., https://yourdomain.com)', 'maxsys-secure-email'); ?></p></td></tr>
                        </table>
                        <h3><?php _e('Additional Protection', 'maxsys-secure-email'); ?></h3>
                        <table class="form-table">
                            <tr><th><?php _e('Honeypot Field', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[honeypot_enabled]" value="1" <?php checked($this->options['honeypot_enabled']); ?>> <?php _e('Enable honeypot spam protection', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('Timestamp Validation', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[timestamp_validation]" value="1" <?php checked($this->options['timestamp_validation']); ?>> <?php _e('Validate form submission timing', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('Max Form Age (seconds)', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[timestamp_max_age]" value="<?php echo esc_attr($this->options['timestamp_max_age']); ?>" min="300" max="86400"><p class="description"><?php _e('Maximum time between form load and submission', 'maxsys-secure-email'); ?></p></td></tr>
                        </table>
                    </div>
                    <div id="email" class="tab-content" style="display:none;">
                        <h2><?php _e('Email Configuration', 'maxsys-secure-email'); ?></h2>
                        <table class="form-table">
                            <tr><th><?php _e('Notification Email', 'maxsys-secure-email'); ?></th><td><input type="email" name="maxsys_secure_email_options[notification_email]" value="<?php echo esc_attr($this->options['notification_email']); ?>" class="regular-text"><p class="description"><?php _e('Email address to receive form submissions', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Email Template', 'maxsys-secure-email'); ?></th><td><textarea name="maxsys_secure_email_options[email_template]" rows="10" class="large-text"><?php echo esc_textarea($this->options['email_template']); ?></textarea><p class="description"><?php _e('Available variables: {name}, {email}, {phone}, {subject}, {message}, {ip_address}, {user_agent}, {submission_time}', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Enable Auto-Reply', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[auto_reply_enabled]" value="1" <?php checked($this->options['auto_reply_enabled']); ?>> <?php _e('Send automatic reply to form submitters', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('Auto-Reply Template', 'maxsys-secure-email'); ?></th><td><textarea name="maxsys_secure_email_options[auto_reply_template]" rows="8" class="large-text"><?php echo esc_textarea($this->options['auto_reply_template']); ?></textarea><p class="description"><?php _e('Available variables: {name}, {email}, {site_name}', 'maxsys-secure-email'); ?></p></td></tr>
                        </table>
                    </div>
                    <div id="validation" class="tab-content" style="display:none;">
                        <h2><?php _e('Form Validation Rules', 'maxsys-secure-email'); ?></h2>
                        <table class="form-table">
                            <tr><th><?php _e('Name Length', 'maxsys-secure-email'); ?></th><td><?php _e('Min:', 'maxsys-secure-email'); ?> <input type="number" name="maxsys_secure_email_options[name_min_length]" value="<?php echo esc_attr($this->options['name_min_length']); ?>" min="1" max="50" style="width: 80px;"><?php _e('Max:', 'maxsys-secure-email'); ?> <input type="number" name="maxsys_secure_email_options[name_max_length]" value="<?php echo esc_attr($this->options['name_max_length']); ?>" min="10" max="500" style="width: 80px;"></td></tr>
                            <tr><th><?php _e('Message Length', 'maxsys-secure-email'); ?></th><td><?php _e('Min:', 'maxsys-secure-email'); ?> <input type="number" name="maxsys_secure_email_options[message_min_length]" value="<?php echo esc_attr($this->options['message_min_length']); ?>" min="1" max="100" style="width: 80px;"><?php _e('Max:', 'maxsys-secure-email'); ?> <input type="number" name="maxsys_secure_email_options[message_max_length]" value="<?php echo esc_attr($this->options['message_max_length']); ?>" min="100" max="10000" style="width: 80px;"></td></tr>
                            <tr><th><?php _e('Subject Max Length', 'maxsys-secure-email'); ?></th><td><input type="number" name="maxsys_secure_email_options[subject_max_length]" value="<?php echo esc_attr($this->options['subject_max_length']); ?>" min="10" max="500"></td></tr>
                        </table>
                        <h3><?php _e('Spam Protection', 'maxsys-secure-email'); ?></h3>
                        <table class="form-table">
                            <tr><th><?php _e('Spam Keywords', 'maxsys-secure-email'); ?></th><td><textarea name="maxsys_secure_email_options[spam_keywords]" rows="5" class="large-text"><?php echo esc_textarea($this->options['spam_keywords']); ?></textarea><p class="description"><?php _e('One keyword per line (case insensitive)', 'maxsys-secure-email'); ?></p></td></tr>
                            <tr><th><?php _e('Block URLs', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[block_urls]" value="1" <?php checked($this->options['block_urls']); ?>> <?php _e('Block messages containing URLs', 'maxsys-secure-email'); ?></label></td></tr>
                        </table>
                    </div>
                    <div id="advanced" class="tab-content" style="display:none;">
                        <h2><?php _e('Advanced Settings', 'maxsys-secure-email'); ?></h2>
                        <h3><?php _e('Logging', 'maxsys-secure-email'); ?></h3>
                        <table class="form-table">
                            <tr><th><?php _e('Enable Logging', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[enable_logging]" value="1" <?php checked($this->options['enable_logging']); ?>> <?php _e('Enable system logging', 'maxsys-secure-email'); ?></label></td></tr>
                            <tr><th><?php _e('Logging Levels', 'maxsys-secure-email'); ?></th><td><label><input type="checkbox" name="maxsys_secure_email_options[log_successful_submissions]" value="1" <?php checked($this->options['log_successful_submissions']); ?>> <?php _e('Log successful form submissions', 'maxsys-secure-email'); ?></label><br><label><input type="checkbox" name="maxsys_secure_email_options[log_failed_attempts]" value="1" <?php checked($this->options['log_failed_attempts']); ?>> <?php _e('Log failed attempts and security violations', 'maxsys-secure-email'); ?></label></td></tr>
                        </table>
                        <h3><?php _e('Database Statistics', 'maxsys-secure-email'); ?></h3>
                        <table class="form-table">
                            <tr><th><?php _e('Total Submissions', 'maxsys-secure-email'); ?></th><td><?php global $wpdb; $count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}maxsys_form_submissions"); echo esc_html($count); ?></td></tr>
                            <tr><th><?php _e('Blocked Attempts', 'maxsys-secure-email'); ?></th><td><?php global $wpdb; $count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}maxsys_rate_limits WHERE blocked_until IS NOT NULL"); echo esc_html($count); ?></td></tr>
                        </table>
                    </div>
                </div>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
    
    public function submissions_page() {
        global $wpdb; $table_name = $wpdb->prefix . 'maxsys_form_submissions'; $per_page = 20;
        $current_page = isset($_GET['paged']) ? max(1, absint($_GET['paged'])) : 1;
        $offset = ($current_page - 1) * $per_page;
        $total_items = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
        $submissions = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name ORDER BY created_at DESC LIMIT %d OFFSET %d", $per_page, $offset));
        ?>
        <div class="wrap">
            <h1><?php _e('Form Submissions', 'maxsys-secure-email'); ?></h1>
            <table class="wp-list-table widefat fixed striped">
                <thead><tr><th><?php _e('ID', 'maxsys-secure-email'); ?></th><th><?php _e('Name', 'maxsys-secure-email'); ?></th><th><?php _e('Email', 'maxsys-secure-email'); ?></th><th><?php _e('Subject', 'maxsys-secure-email'); ?></th><th><?php _e('Date', 'maxsys-secure-email'); ?></th><th><?php _e('Status', 'maxsys-secure-email'); ?></th></tr></thead>
                <tbody>
                    <?php if (empty($submissions)) : ?>
                        <tr><td colspan="6"><?php _e('No submissions found.', 'maxsys-secure-email'); ?></td></tr>
                    <?php else: foreach ($submissions as $submission) : ?>
                        <tr><td><?php echo esc_html($submission->id); ?></td><td><?php echo esc_html($submission->name); ?></td><td><?php echo esc_html($submission->email); ?></td><td><?php echo esc_html($submission->subject ?: __('No subject', 'maxsys-secure-email')); ?></td><td><?php echo esc_html($submission->created_at); ?></td><td><?php echo esc_html($submission->status); ?></td></tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
            <?php
            $total_pages = ceil($total_items / $per_page);
            if ($total_pages > 1) {
                echo '<div class="tablenav"><div class="tablenav-pages">';
                echo paginate_links(['base' => add_query_arg('paged', '%#%'), 'format' => '?paged=%#%', 'prev_text' => __('Â«'), 'next_text' => __('Â»'), 'total' => $total_pages, 'current' => $current_page]);
                echo '</div></div>';
            }
            ?>
        </div>
        <?php
    }
}

MAXSYS_Secure_Email::get_instance();