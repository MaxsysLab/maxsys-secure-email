<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 *
 * Removes everything the plugin stored: its settings, the stored form submissions,
 * and the rate-limit records. Deleting the plugin is the site owner saying this
 * data is no longer wanted.
 *
 * @package MaxsysSecureEmail
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'maxsys_secure_email_options' );
delete_option( 'maxsys_secure_email_db_version' );

global $wpdb;
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- removing the plugin's own tables.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'maxsys_form_submissions' ) );
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'maxsys_rate_limits' ) );
// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
