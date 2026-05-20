"""
Maps HackerOne weakness class slugs to generic security categories.
Used by fetch.py (path construction) and index.py (grouping).

Category slugs (filesystem-safe):
  xss, sqli, rce, ssrf, xxe, lfi, http_injection, injection,
  deserialization, idor, csrf, open_redirect, clickjacking, cors,
  authn, privesc, crypto, secrets, tls, info_disclosure, memory,
  dos, race_condition, business_logic, supply_chain, file_upload,
  llm, misc
"""

_MAP: dict[str, str] = {
    # ── XSS ──────────────────────────────────────────────────────────────────
    "cross_site_scripting_xss": "xss",
    "cross_site_scripting_xss_dom": "xss",
    "cross_site_scripting_xss_generic": "xss",
    "cross_site_scripting_xss_reflected": "xss",
    "cross_site_scripting_xss_stored": "xss",
    "reflected_xss": "xss",
    "improper_neutralization_of_script_related_html_tags_in_a_web": "xss",
    "improper_neutralization_of_http_headers_for_scripting_syntax": "xss",
    "failure_to_sanitize_special_elements_into_a_different_plane_": "xss",
    "improper_neutralization_of_escape_meta_or_control_sequences": "xss",

    # ── SQLi ─────────────────────────────────────────────────────────────────
    "sql_injection": "sqli",
    "blind_sql_injection": "sqli",

    # ── RCE / Code Injection (includes SSTI) ─────────────────────────────────
    "os_command_injection": "rce",
    "command_injection_generic": "rce",
    "code_injection": "rce",
    "use_of_externally_controlled_format_string": "rce",

    # ── SSRF ─────────────────────────────────────────────────────────────────
    "server_side_request_forgery": "ssrf",
    "server_side_request_forgery_ssrf": "ssrf",

    # ── XXE ──────────────────────────────────────────────────────────────────
    "xml_external_entities_xxe": "xxe",
    "xml_entity_expansion": "xxe",
    "xml_injection": "xxe",

    # ── LFI / Path Traversal ─────────────────────────────────────────────────
    "path_traversal": "lfi",
    "path_traversal_dir_filename": "lfi",
    "relative_path_traversal": "lfi",
    "php_local_file_inclusion": "lfi",
    "external_control_of_file_name_or_path": "lfi",
    "improper_link_resolution_before_file_access_link_following": "lfi",
    "file_content_injection": "lfi",
    "remote_file_inclusion": "lfi",
    "externally_controlled_reference_to_a_resource_in_another_sph": "lfi",

    # ── HTTP Injection ────────────────────────────────────────────────────────
    "http_request_smuggling": "http_injection",
    "http_response_splitting": "http_injection",
    "crlf_injection": "http_injection",
    "cache_poisoning": "http_injection",

    # ── Injection (other) ─────────────────────────────────────────────────────
    "ldap_injection": "injection",
    "resource_injection": "injection",
    "improper_neutralization_of_formula_elements_in_a_csv_file": "injection",
    "improper_neutralization_of_whitespace": "injection",
    "improper_neutralization_of_value_delimiters": "injection",

    # ── Deserialization ───────────────────────────────────────────────────────
    "deserialization_of_untrusted_data": "deserialization",

    # ── IDOR / Broken Access Control ─────────────────────────────────────────
    "insecure_direct_object_reference_idor": "idor",
    "improper_authorization": "idor",
    "missing_authorization": "idor",
    "incorrect_authorization": "idor",
    "improper_access_control_generic": "idor",
    "forced_browsing": "idor",
    "client_side_enforcement_of_server_side_security": "idor",
    "exposed_dangerous_method_or_function": "idor",
    "external_control_of_critical_state_data": "idor",
    "reliance_on_untrusted_inputs_in_a_security_decision": "idor",

    # ── CSRF ──────────────────────────────────────────────────────────────────
    "cross_site_request_forgery_csrf": "csrf",

    # ── Open Redirect ─────────────────────────────────────────────────────────
    "open_redirect": "open_redirect",

    # ── Clickjacking / UI ─────────────────────────────────────────────────────
    "ui_redressing_clickjacking": "clickjacking",
    "content_spoofing": "clickjacking",
    "user_interface_ui_misrepresentation_of_critical_information": "clickjacking",

    # ── CORS / Origin Validation ──────────────────────────────────────────────
    "origin_validation_error": "cors",
    "exposure_of_sensitive_information_due_to_incompatible_polici": "cors",

    # ── Authentication & Session ──────────────────────────────────────────────
    "authentication_bypass": "authn",
    "authentication_bypass_by_primary_weakness": "authn",
    "authentication_bypass_using_an_alternate_path_or_channel": "authn",
    "improper_authentication_generic": "authn",
    "missing_authentication_for_critical_function": "authn",
    "missing_critical_step_in_authentication": "authn",
    "session_fixation": "authn",
    "insufficient_session_expiration": "authn",
    "reusing_session_ids_aka_session_replay": "authn",
    "unverified_password_change": "authn",
    "weak_password_recovery_mechanism_for_forgotten_password": "authn",
    "weak_password_requirements": "authn",
    "brute_force": "authn",
    "improper_restriction_of_authentication_attempts": "authn",
    "reliance_on_cookies_without_validation_and_integrity_checkin": "authn",
    "insufficient_verification_of_data_authenticity": "authn",
    "use_of_default_credentials": "authn",
    "exposure_of_data_element_to_wrong_session": "authn",

    # ── Privilege Escalation ──────────────────────────────────────────────────
    "privilege_escalation": "privesc",
    "execution_with_unnecessary_privileges": "privesc",
    "improper_privilege_management": "privesc",
    "incorrect_privilege_assignment": "privesc",
    "incorrect_permission_assignment_for_critical_resource": "privesc",
    "improper_handling_of_insufficient_permissions_or_privileges": "privesc",
    "improper_export_of_android_application_components": "privesc",

    # ── Cryptography ──────────────────────────────────────────────────────────
    "cryptographic_issues_generic": "crypto",
    "use_of_a_broken_or_risky_cryptographic_algorithm": "crypto",
    "inadequate_encryption_strength": "crypto",
    "use_of_cryptographically_weak_pseudo_random_number_generator": "crypto",
    "use_of_insufficiently_random_values": "crypto",
    "reusing_a_nonce_key_pair_in_encryption": "crypto",
    "reversible_one_way_hash": "crypto",
    "key_exchange_without_entity_authentication": "crypto",
    "weak_cryptography_for_passwords": "crypto",
    "use_of_a_key_past_its_expiration_date": "crypto",
    "improper_verification_of_cryptographic_signature": "crypto",
    "missing_required_cryptographic_step": "crypto",
    "use_of_insufficiently_random_values": "crypto",

    # ── Secrets / Hardcoded Credentials ──────────────────────────────────────
    "use_of_hard_coded_credentials": "secrets",
    "use_of_hard_coded_password": "secrets",
    "use_of_hard_coded_cryptographic_key": "secrets",
    "password_in_configuration_file": "secrets",
    "plaintext_storage_of_a_password": "secrets",
    "storing_passwords_in_a_recoverable_format": "secrets",
    "insufficiently_protected_credentials": "secrets",
    "cleartext_storage_of_sensitive_information": "secrets",
    "cleartext_storage_in_a_file_or_on_disk": "secrets",
    "cleartext_transmission_of_sensitive_information": "secrets",
    "missing_encryption_of_sensitive_data": "secrets",
    "insecure_storage_of_sensitive_information": "secrets",
    "unprotected_transport_of_credentials": "secrets",
    "insertion_of_sensitive_information_into_log_file": "secrets",
    "inclusion_of_sensitive_information_in_an_include_file": "secrets",
    "insecure_temporary_file": "secrets",

    # ── TLS / Certificate ─────────────────────────────────────────────────────
    "improper_certificate_validation": "tls",
    "improper_check_for_certificate_revocation": "tls",
    "improper_following_of_a_certificate_s_chain_of_trust": "tls",
    "improper_validation_of_certificate_with_host_mismatch": "tls",
    "man_in_the_middle": "tls",

    # ── Information Disclosure ────────────────────────────────────────────────
    "information_disclosure": "info_disclosure",
    "information_exposure_through_an_error_message": "info_disclosure",
    "information_exposure_through_debug_information": "info_disclosure",
    "information_exposure_through_directory_listing": "info_disclosure",
    "information_exposure_through_sent_data": "info_disclosure",
    "information_exposure_through_timing_discrepancy": "info_disclosure",
    "file_and_directory_information_exposure": "info_disclosure",
    "privacy_violation": "info_disclosure",
    "leftover_debug_code_backdoor": "info_disclosure",
    "use_of_cache_containing_sensitive_information": "info_disclosure",

    # ── Memory Corruption ─────────────────────────────────────────────────────
    "classic_buffer_overflow": "memory",
    "heap_overflow": "memory",
    "stack_overflow": "memory",
    "buffer_over_read": "memory",
    "buffer_under_read": "memory",
    "buffer_underflow": "memory",
    "use_after_free": "memory",
    "double_free": "memory",
    "null_pointer_dereference": "memory",
    "out_of_bounds_read": "memory",
    "memory_corruption_generic": "memory",
    "write_what_where_condition": "memory",
    "type_confusion": "memory",
    "integer_overflow": "memory",
    "integer_overflow_to_buffer_overflow": "memory",
    "integer_underflow": "memory",
    "off_by_one_error": "memory",
    "wrap_around_error": "memory",
    "array_index_underflow": "memory",
    "incorrect_calculation_of_buffer_size": "memory",
    "free_of_memory_not_on_the_heap": "memory",
    "missing_release_of_memory_after_effective_lifetime": "memory",
    "improper_null_termination": "memory",
    "improper_initialization": "memory",
    "reachable_assertion": "memory",

    # ── DoS / Resource Exhaustion ─────────────────────────────────────────────
    "uncontrolled_resource_consumption": "dos",
    "allocation_of_resources_without_limits_or_throttling": "dos",
    "uncontrolled_recursion": "dos",
    "loop_with_unreachable_exit_condition_infinite_loop": "dos",
    "improper_handling_of_highly_compressed_data_data_amplificati": "dos",

    # ── Race Conditions ───────────────────────────────────────────────────────
    "leveraging_race_conditions": "race_condition",
    "time_of_check_time_of_use_toctou_race_condition": "race_condition",
    "concurrent_execution_using_shared_resource_with_improper_syn": "race_condition",
    "improper_synchronization": "race_condition",

    # ── Business Logic ────────────────────────────────────────────────────────
    "business_logic_errors": "business_logic",
    "expected_behavior_violation": "business_logic",
    "inconsistency_between_implementation_and_documented_design": "business_logic",
    "modification_of_assumed_immutable_data_maid": "business_logic",
    "incorrect_comparison": "business_logic",

    # ── Supply Chain ──────────────────────────────────────────────────────────
    "using_components_with_known_vulnerabilities": "supply_chain",
    "download_of_code_without_integrity_check": "supply_chain",
    "inclusion_of_functionality_from_untrusted_control_sphere": "supply_chain",
    "untrusted_search_path": "supply_chain",
    "malware": "supply_chain",
    "embedded_malicious_code": "supply_chain",

    # ── File Upload ───────────────────────────────────────────────────────────
    "unrestricted_upload_of_file_with_dangerous_type": "file_upload",
    "file_manipulation": "file_upload",

    # ── LLM / AI ─────────────────────────────────────────────────────────────
    "llm01_prompt_injection": "llm",
    "llm04_model_denial_of_service": "llm",
    "llm05_supply_chain_vulnerabilities": "llm",
    "llm06_sensitive_information_disclosure": "llm",

    # ── Misc / catch-all ──────────────────────────────────────────────────────
    "improper_input_validation": "misc",
    "acceptance_of_extraneous_untrusted_data_with_trusted_data": "misc",
    "misinterpretation_of_input": "misc",
    "improper_validation_of_syntactic_correctness_of_input": "misc",
    "improper_handling_of_unexpected_data_type": "misc",
    "improper_handling_of_url_encoding_hex_encoding": "misc",
    "encoding_error": "misc",
    "violation_of_secure_design_principles": "misc",
    "security_through_obscurity": "misc",
    "use_of_inherently_dangerous_function": "misc",
    "use_of_incorrectly_resolved_name_or_reference": "misc",
    "asi05_unexpected_code_execution_rce": "misc",
}

# Human-readable labels for display
CATEGORY_LABELS: dict[str, str] = {
    "xss": "XSS",
    "sqli": "SQL Injection",
    "rce": "RCE / Command Injection",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "lfi": "LFI / Path Traversal",
    "http_injection": "HTTP Injection",
    "injection": "Injection (Other)",
    "deserialization": "Deserialization",
    "idor": "IDOR / Broken Access Control",
    "csrf": "CSRF",
    "open_redirect": "Open Redirect",
    "clickjacking": "Clickjacking / UI Redressing",
    "cors": "CORS / Origin Validation",
    "authn": "Authentication & Session",
    "privesc": "Privilege Escalation",
    "crypto": "Cryptography",
    "secrets": "Secrets & Hardcoded Credentials",
    "tls": "TLS / Certificate Validation",
    "info_disclosure": "Information Disclosure",
    "memory": "Memory Corruption",
    "dos": "Denial of Service",
    "race_condition": "Race Conditions",
    "business_logic": "Business Logic",
    "supply_chain": "Supply Chain",
    "file_upload": "File Upload",
    "llm": "LLM / AI",
    "misc": "Miscellaneous",
}


def get_category(class_slug: str) -> str:
    return _MAP.get(class_slug, "misc")
