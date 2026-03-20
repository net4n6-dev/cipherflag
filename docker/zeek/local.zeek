@load policy/tuning/json-logs
@load policy/protocols/ssl/extract-certs-pem
redef Log::default_rotation_interval = 1 hr;
redef SSL::extract_certs_pem = ALL_HOSTS;
