<?php
/**
 * Structured error-contract fields for WP_Error responses.
 *
 * The plugin reports facts; the MCP Worker interprets them. Every WP_Error
 * the plugin returns carries these fields in its data array so the Worker
 * never has to guess (or probe) what happened:
 *
 * - cause:         why the operation failed (enum below)
 * - retry_ok:      whether retrying the SAME call unchanged can ever succeed
 * - user_is_admin: whether the authenticated user has manage_options
 *
 * Cause enum:
 * - capability_role         user genuinely lacks a role capability
 * - capability_cpt_mapping  a custom post type's capability mapping denied the
 *                           check (fails even Administrators)
 * - meta_protected          protected meta key (underscore/auth callback)
 * - not_supported           outside the supported surface by design (allowlist)
 * - security_gate           blocked by an anti-injection/sandbox rule
 * - approval_flow           needs human approval/confirmation, then retryable
 * - invalid_input           malformed or missing caller input
 * - not_found               the referenced resource does not exist
 * - wp_core                 WordPress core refused the operation
 * - filesystem              file read/write/copy failed
 * - host_environment        hosting configuration blocks it (DISALLOW_FILE_*,
 *                           disabled functions, chroot, permissions)
 * - auth_not_received       nobody authenticated and core's 401 carried no
 *                           contract (WPVibe_Auth_Diagnostics adds it)
 *
 * @package WPVibe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPVibe_Error_Contract {

	/** @var bool|null Last application_password_is_api_request verdict core received; null until core asks. */
	private static $api_request = null;

	/**
	 * Build a WP_Error data array carrying the structured contract fields.
	 *
	 * @param string $cause    One of the cause enum values above.
	 * @param bool   $retry_ok Whether retrying the same call unchanged can succeed.
	 * @param array  $extra    Existing data fields (status, capability, ...). Kept as-is.
	 * @return array
	 */
	public static function data( $cause, $retry_ok, array $extra = array() ) {
		return array_merge(
			$extra,
			array(
				'cause'         => $cause,
				'retry_ok'      => (bool) $retry_ok,
				'user_is_admin' => is_user_logged_in() && current_user_can( 'manage_options' ),
			),
			self::auth_diagnostics()
		);
	}

	/**
	 * Why authentication produced no user, as facts rather than inference.
	 *
	 * WordPress emits the same 401 codes whether the server stripped the
	 * Authorization header, Application Passwords are unavailable (they need
	 * SSL, so a proxy that does not set HTTP_X_FORWARDED_PROTO silently
	 * disables them), or a security plugin short-circuited the auth filters.
	 * The remedies are different and mutually useless, and none of it is
	 * distinguishable from outside the site, so report it instead.
	 *
	 * Attached only when nobody authenticated; on an ordinary 403 the caller is
	 * logged in and these would be noise.
	 *
	 * @return array
	 */
	public static function auth_diagnostics() {
		if ( is_user_logged_in() ) {
			return array();
		}
		return array(
			// Constants are set in vibe-ai.php before anything can rewrite
			// $_SERVER, so these describe what the server delivered.
			'auth_header_seen'         => defined( 'WPVIBE_AUTH_HEADER_SEEN' ) ? (bool) WPVIBE_AUTH_HEADER_SEEN : null,
			'auth_fallback_seen'       => defined( 'WPVIBE_AUTH_FALLBACK_SEEN' ) ? (bool) WPVIBE_AUTH_FALLBACK_SEEN : null,
			'auth_fallback_applied'    => defined( 'WPVIBE_AUTH_FALLBACK_APPLIED' ) ? (bool) WPVIBE_AUTH_FALLBACK_APPLIED : null,
			'app_passwords_available'  => function_exists( 'wp_is_application_passwords_available' ) ? (bool) wp_is_application_passwords_available() : null,
			'app_passwords_in_use'     => self::app_passwords_in_use(),
			'is_ssl'                   => is_ssl(),
			// Core's silent exits in wp_validate_application_password(), as booleans only (never the values).
			'php_auth_user_set'        => isset( $_SERVER['PHP_AUTH_USER'] ),
			'php_auth_pw_set'          => isset( $_SERVER['PHP_AUTH_PW'] ),
			'app_password_api_request' => self::$api_request,
			'app_password_auth_hooked' => false !== has_filter( 'determine_current_user', 'wp_validate_application_password' ),
		);
	}

	/**
	 * Remember the final application_password_is_api_request verdict (hooked last),
	 * so a 401 reports the value core acted on rather than a recomputed one.
	 *
	 * @param mixed $is_api_request Filtered value.
	 * @return mixed Unchanged.
	 */
	public static function record_api_request( $is_api_request ) {
		self::$api_request = (bool) $is_api_request;
		return $is_api_request;
	}

	/**
	 * Where a PHP error came from, for administrators only: the message, the
	 * site-relative file:line and the plugin or theme that owns that file.
	 *
	 * @param string $message PHP error message.
	 * @param string $file    Absolute file path.
	 * @param int    $line    Line number.
	 * @param array  $trace   Backtrace, used to name the caller when the error sits in WordPress core.
	 * @return string Empty for non-administrators.
	 */
	public static function php_error_location( $message, $file, $line, array $trace = array() ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return '';
		}
		$owner = self::is_own_file( $file ) ? 'WPVibe itself' : self::code_owner( $file );
		if ( 'WordPress core' === $owner ) {
			// Name the plugin or theme that called into core; WPVibe is always on the stack in content/edit, so it never counts.
			foreach ( $trace as $frame ) {
				if ( ! isset( $frame['file'] ) || self::is_own_file( $frame['file'] ) ) {
					continue;
				}
				$caller = self::code_owner( $frame['file'] );
				if ( '' !== $caller && 'WordPress core' !== $caller ) {
					$owner = sprintf( 'WordPress core, called from %s', $caller );
					break;
				}
			}
		}
		$where = WPVibe_Draft_Theme::site_relative( sprintf( '%s in %s:%d', $message, $file, (int) $line ) );
		return '' === $owner ? $where : sprintf( '%s (%s)', $where, $owner );
	}

	/**
	 * Whether a file is part of this plugin, whatever its folder is called.
	 *
	 * @param string $file Absolute path.
	 * @return bool
	 */
	public static function is_own_file( $file ) {
		if ( ! defined( 'WPVIBE_PLUGIN_DIR' ) || '' === (string) $file ) {
			return false;
		}
		$dir = wp_normalize_path( WPVIBE_PLUGIN_DIR );
		return 0 === strpos( wp_normalize_path( (string) $file ), trailingslashit( $dir ) );
	}

	/**
	 * The plugin, theme or core area a file belongs to, by its place under the site root.
	 *
	 * @param string $file Absolute or site-relative path.
	 * @return string Empty when the file is outside the known folders.
	 */
	public static function code_owner( $file ) {
		$rel = WPVibe_Draft_Theme::site_relative( (string) $file );
		if ( preg_match( '#^wp-content/(plugins|mu-plugins|themes)/([^/]+)#', $rel, $m ) ) {
			$labels = array( 'plugins' => 'plugin', 'mu-plugins' => 'must-use plugin', 'themes' => 'theme' );
			return $labels[ $m[1] ] . ' ' . preg_replace( '/\.php$/', '', $m[2] );
		}
		if ( preg_match( '#^wp-(includes|admin)/#', $rel ) ) {
			return 'WordPress core';
		}
		return '';
	}

	/**
	 * Detail for WordPress's own fatal-error message (wp_php_error_message), so an
	 * uncatchable fatal (memory, time limit) names its cause for administrators.
	 *
	 * @param string $message Core's message.
	 * @param mixed  $error   error_get_last() array.
	 * @param string $label   What was running, e.g. "Beaver save fatal".
	 * @param string $advice  Optional recovery line appended after the detail.
	 * @return string
	 */
	public static function fatal_message( $message, $error, $label, $advice = '' ) {
		if ( ! is_array( $error ) ) {
			return $message;
		}
		$where = self::php_error_location( $error['message'] ?? '', $error['file'] ?? '', (int) ( $error['line'] ?? 0 ) );
		if ( '' === $where ) {
			return $message;
		}
		return $message . ' ' . esc_html( trim( sprintf( '%s: %s %s', $label, $where, $advice ) ) );
	}

	/**
	 * Whether the site has ever kept an Application Password (core's
	 * using_application_passwords flag). While it is false, core skips
	 * Application Password auth entirely, so every credential answers a bare
	 * 401 with no reject code. One site-wide boolean: nothing is enumerated.
	 *
	 * @return bool|null Null on WordPress without WP_Application_Passwords::is_in_use().
	 */
	public static function app_passwords_in_use() {
		if ( ! class_exists( 'WP_Application_Passwords' ) || ! method_exists( 'WP_Application_Passwords', 'is_in_use' ) ) {
			return null;
		}
		return (bool) WP_Application_Passwords::is_in_use();
	}
}
