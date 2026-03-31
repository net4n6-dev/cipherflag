package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/net4n6-dev/cipherflag/internal/analysis"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

type intSpec struct {
	cn, org, country string
	rootIdx          int // index into roots
	keyAlg           model.KeyAlgorithm
	keyBits          int
	sigAlg           model.SignatureAlgorithm
}

func seedData(ctx context.Context, st store.CertStore) error {
	rng := rand.New(rand.NewSource(42)) // deterministic for reproducibility
	now := time.Now()
	var allCerts []*model.Certificate

	// ════════════════════════════════════════════════════════════════════════
	// ROOT CAs — 20 real-world root CAs from around the globe
	// ════════════════════════════════════════════════════════════════════════

	roots := []certSpec{
		// ── US / Western ────────────────────────────────────────────────
		{cn: "DigiCert Global Root G2", org: "DigiCert Inc", country: "US",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "ISRG Root X1", org: "Internet Security Research Group", country: "US",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "ISRG Root X2", org: "Internet Security Research Group", country: "US",
			keyAlg: model.KeyECDSA, keyBits: 384, sigAlg: model.SigECDSAWithSHA384},
		{cn: "GlobalSign Root CA - R3", org: "GlobalSign nv-sa", country: "BE",
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA},
		{cn: "GlobalSign Root CA - R6", org: "GlobalSign nv-sa", country: "BE",
			keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256},
		{cn: "USERTrust RSA Certification Authority", org: "The USERTRUST Network", country: "US",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA384WithRSA},
		{cn: "Baltimore CyberTrust Root", org: "Baltimore", country: "IE",
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA},
		{cn: "Amazon Root CA 1", org: "Amazon", country: "US",
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA},
		{cn: "Amazon Root CA 4", org: "Amazon", country: "US",
			keyAlg: model.KeyECDSA, keyBits: 384, sigAlg: model.SigECDSAWithSHA384},
		{cn: "Starfield Root Certificate Authority - G2", org: "Starfield Technologies, Inc.", country: "US",
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA},
		{cn: "Microsoft RSA Root Certificate Authority 2017", org: "Microsoft Corporation", country: "US",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "Google Trust Services Root R1", org: "Google Trust Services LLC", country: "US",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "Entrust Root Certification Authority - G4", org: "Entrust, Inc.", country: "US",
			keyAlg: model.KeyECDSA, keyBits: 384, sigAlg: model.SigECDSAWithSHA384},
		// ── International / Unusual ─────────────────────────────────────
		{cn: "CFCA EV ROOT", org: "China Financial Certification Authority", country: "CN",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1", org: "Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK", country: "TR",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "emSign Root CA - G1", org: "eMudhra Technologies Limited", country: "IN",
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA},
		{cn: "AC Raiz Certicamara S.A.", org: "Certicamara S.A.", country: "CO",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "IdenTrust Commercial Root CA 1", org: "IdenTrust", country: "US",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA256WithRSA},
		{cn: "NAVER Global Root Certification Authority", org: "NAVER BUSINESS PLATFORM Corp.", country: "KR",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA384WithRSA},
		{cn: "Certum Trusted Root CA", org: "Asseco Data Systems S.A.", country: "PL",
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA512WithRSA},
	}

	for i := range roots {
		roots[i].isCA = true
		roots[i].selfSigned = true
		roots[i].issuerCN = roots[i].cn
		roots[i].issuerOrg = roots[i].org
		roots[i].notBefore = now.AddDate(-10-rng.Intn(8), 0, 0)
		roots[i].notAfter = now.AddDate(10+rng.Intn(10), 0, 0)
		roots[i].keyUsage = []string{"Certificate Sign", "CRL Sign"}
		allCerts = append(allCerts, makeCert(roots[i]))
	}

	// ════════════════════════════════════════════════════════════════════════
	// INTERMEDIATE CAs — 35 intermediates chaining to roots above
	// ════════════════════════════════════════════════════════════════════════

	intermediates := []intSpec{
		// DigiCert family
		{"DigiCert SHA2 Extended Validation Server CA", "DigiCert Inc", "US", 0, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"DigiCert TLS RSA SHA256 2020 CA1", "DigiCert Inc", "US", 0, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"DigiCert Global G2 TLS RSA SHA256 2020 CA1", "DigiCert Inc", "US", 0, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"DigiCert TLS Hybrid ECC SHA384 2020 CA1", "DigiCert Inc", "US", 0, model.KeyECDSA, 384, model.SigECDSAWithSHA384},
		// Let's Encrypt family
		{"R3", "Let's Encrypt", "US", 1, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"R4", "Let's Encrypt", "US", 1, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"E5", "Let's Encrypt", "US", 2, model.KeyECDSA, 384, model.SigECDSAWithSHA384},
		{"E6", "Let's Encrypt", "US", 2, model.KeyECDSA, 384, model.SigECDSAWithSHA384},
		// GlobalSign family
		{"GlobalSign GCC R3 DV TLS CA 2020", "GlobalSign nv-sa", "BE", 3, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"GlobalSign Atlas R3 DV TLS CA 2024 Q1", "GlobalSign nv-sa", "BE", 3, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"GlobalSign GCC R6 AlphaSSL CA 2023", "GlobalSign nv-sa", "BE", 4, model.KeyECDSA, 256, model.SigECDSAWithSHA256},
		// Sectigo / Comodo
		{"Sectigo ECC Domain Validation Secure Server CA", "Sectigo Limited", "GB", 5, model.KeyECDSA, 256, model.SigECDSAWithSHA256},
		{"Sectigo RSA Domain Validation Secure Server CA", "Sectigo Limited", "GB", 5, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"Sectigo RSA Organization Validation Secure Server CA", "Sectigo Limited", "GB", 5, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// Amazon
		{"Amazon RSA 2048 M02", "Amazon", "US", 7, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"Amazon ECDSA 256 M01", "Amazon", "US", 8, model.KeyECDSA, 256, model.SigECDSAWithSHA256},
		// Microsoft / Azure
		{"Microsoft Azure RSA TLS Issuing CA 04", "Microsoft Corporation", "US", 10, model.KeyRSA, 4096, model.SigSHA384WithRSA},
		{"Microsoft Azure ECC TLS Issuing CA 06", "Microsoft Corporation", "US", 10, model.KeyECDSA, 384, model.SigECDSAWithSHA384},
		// Google
		{"GTS CA 1D4", "Google Trust Services LLC", "US", 11, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"GTS CA 1P5", "Google Trust Services LLC", "US", 11, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// Starfield / GoDaddy
		{"Starfield Secure Certificate Authority - G2", "Starfield Technologies, Inc.", "US", 9, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// Entrust
		{"Entrust Certification Authority - L1M", "Entrust, Inc.", "US", 12, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// International
		{"CFCA OV OCA", "China Financial Certification Authority", "CN", 13, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"TUBITAK Kamu SM SSL Sertifika Hizmet Saglayicisi", "TUBITAK", "TR", 14, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"emSign CS CA - G1", "eMudhra Technologies Limited", "IN", 15, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"Certicamara Servidor Seguro", "Certicamara S.A.", "CO", 16, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"IdenTrust TrustID Server CA A52", "IdenTrust", "US", 17, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// NAVER
		{"NAVER Cloud Sub CA Class 1", "NAVER CLOUD Corp.", "KR", 18, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// Certum
		{"Certum Domain Validation CA SHA2", "Asseco Data Systems S.A.", "PL", 19, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		// Internal enterprise CAs
		{"ACME Corp Internal CA G2", "ACME Corp", "US", 0, model.KeyRSA, 4096, model.SigSHA256WithRSA},
		{"Meridian Health Systems PKI CA", "Meridian Health Systems", "US", 7, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"Kensington Financial Services Issuing CA", "Kensington Financial", "GB", 6, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"NovaTech Manufacturing CA", "NovaTech Industries", "DE", 3, model.KeyRSA, 2048, model.SigSHA256WithRSA},
		{"PacificEdge Telecom Infrastructure CA", "PacificEdge Telecom", "AU", 5, model.KeyECDSA, 256, model.SigECDSAWithSHA256},
		{"Shanghai Logistics Platform CA", "Shanghai Port Authority", "CN", 13, model.KeyRSA, 2048, model.SigSHA256WithRSA},
	}

	var intCerts []*model.Certificate
	for _, spec := range intermediates {
		root := roots[spec.rootIdx]
		c := makeCert(certSpec{
			cn: spec.cn, org: spec.org, country: spec.country,
			issuerCN: root.cn, issuerOrg: root.org,
			notBefore: now.AddDate(-5-rng.Intn(3), 0, 0),
			notAfter:  now.AddDate(2+rng.Intn(6), 0, 0),
			keyAlg: spec.keyAlg, keyBits: spec.keyBits, sigAlg: spec.sigAlg,
			isCA: true,
			keyUsage: []string{"Certificate Sign", "CRL Sign"},
			ocsp:     []string{fmt.Sprintf("http://ocsp.%s.example", sanitizeForURL(spec.org))},
		})
		intCerts = append(intCerts, c)
		allCerts = append(allCerts, c)
	}

	// ════════════════════════════════════════════════════════════════════════
	// END-ENTITY CERTIFICATES — ~1450 leaf certs in realistic categories
	// ════════════════════════════════════════════════════════════════════════

	// Helper to pick a random intermediate
	pickInt := func(indices ...int) *intSpec {
		return &intermediates[indices[rng.Intn(len(indices))]]
	}

	// ── Category 1: Major SaaS / public services (50 certs) ─────────────
	saasServices := []struct{ cn, org, country string; sans []string }{
		{"slack.com", "Slack Technologies", "US", []string{"slack.com", "*.slack.com", "api.slack.com"}},
		{"app.slack.com", "Slack Technologies", "US", []string{"app.slack.com"}},
		{"zoom.us", "Zoom Video Communications", "US", []string{"zoom.us", "*.zoom.us"}},
		{"teams.microsoft.com", "Microsoft Corporation", "US", []string{"teams.microsoft.com", "*.teams.microsoft.com"}},
		{"outlook.office365.com", "Microsoft Corporation", "US", []string{"outlook.office365.com", "*.outlook.com"}},
		{"login.microsoftonline.com", "Microsoft Corporation", "US", []string{"login.microsoftonline.com"}},
		{"portal.azure.com", "Microsoft Corporation", "US", []string{"portal.azure.com", "*.portal.azure.com"}},
		{"console.aws.amazon.com", "Amazon.com, Inc.", "US", []string{"console.aws.amazon.com", "*.console.aws.amazon.com"}},
		{"s3.amazonaws.com", "Amazon.com, Inc.", "US", []string{"s3.amazonaws.com", "*.s3.amazonaws.com"}},
		{"console.cloud.google.com", "Google LLC", "US", []string{"console.cloud.google.com", "*.cloud.google.com"}},
		{"storage.googleapis.com", "Google LLC", "US", []string{"storage.googleapis.com", "*.googleapis.com"}},
		{"salesforce.com", "Salesforce, Inc.", "US", []string{"salesforce.com", "*.salesforce.com", "*.force.com"}},
		{"login.salesforce.com", "Salesforce, Inc.", "US", []string{"login.salesforce.com"}},
		{"app.hubspot.com", "HubSpot, Inc.", "US", []string{"app.hubspot.com", "*.hubspot.com"}},
		{"api.stripe.com", "Stripe, Inc.", "US", []string{"api.stripe.com", "*.stripe.com"}},
		{"dashboard.stripe.com", "Stripe, Inc.", "US", []string{"dashboard.stripe.com"}},
		{"sentry.io", "Functional Software, Inc.", "US", []string{"sentry.io", "*.sentry.io"}},
		{"app.datadoghq.com", "Datadog, Inc.", "US", []string{"app.datadoghq.com", "*.datadoghq.com"}},
		{"grafana.net", "Grafana Labs", "US", []string{"grafana.net", "*.grafana.net"}},
		{"pagerduty.com", "PagerDuty, Inc.", "US", []string{"pagerduty.com", "*.pagerduty.com"}},
		{"atlassian.net", "Atlassian Pty Ltd", "AU", []string{"atlassian.net", "*.atlassian.net"}},
		{"bitbucket.org", "Atlassian Pty Ltd", "AU", []string{"bitbucket.org", "*.bitbucket.org"}},
		{"github.com", "GitHub, Inc.", "US", []string{"github.com", "*.github.com"}},
		{"gitlab.com", "GitLab Inc.", "US", []string{"gitlab.com", "*.gitlab.com"}},
		{"npmjs.com", "GitHub, Inc.", "US", []string{"npmjs.com", "*.npmjs.com", "registry.npmjs.org"}},
		{"docker.io", "Docker Inc.", "US", []string{"docker.io", "*.docker.io", "registry-1.docker.io"}},
		{"cloudflare.com", "Cloudflare, Inc.", "US", []string{"cloudflare.com", "*.cloudflare.com"}},
		{"fastly.com", "Fastly, Inc.", "US", []string{"fastly.com", "*.fastly.com", "*.fastly.net"}},
		{"akamai.com", "Akamai Technologies", "US", []string{"akamai.com", "*.akamai.com", "*.akamaized.net"}},
		{"vercel.com", "Vercel, Inc.", "US", []string{"vercel.com", "*.vercel.app", "*.vercel.com"}},
		{"netlify.app", "Netlify, Inc.", "US", []string{"netlify.app", "*.netlify.app"}},
		{"twilio.com", "Twilio Inc.", "US", []string{"twilio.com", "*.twilio.com", "api.twilio.com"}},
		{"sendgrid.net", "Twilio Inc.", "US", []string{"sendgrid.net", "*.sendgrid.net"}},
		{"auth0.com", "Okta, Inc.", "US", []string{"auth0.com", "*.auth0.com"}},
		{"okta.com", "Okta, Inc.", "US", []string{"okta.com", "*.okta.com"}},
		{"1password.com", "1Password", "CA", []string{"1password.com", "*.1password.com"}},
		{"hashicorp.com", "HashiCorp, Inc.", "US", []string{"hashicorp.com", "app.terraform.io"}},
		{"elastic.co", "Elasticsearch B.V.", "NL", []string{"elastic.co", "*.elastic.co", "cloud.elastic.co"}},
		{"mongodb.com", "MongoDB, Inc.", "US", []string{"mongodb.com", "*.mongodb.com", "cloud.mongodb.com"}},
		{"snowflake.com", "Snowflake Inc.", "US", []string{"snowflake.com", "*.snowflakecomputing.com"}},
		{"splunk.com", "Splunk Inc.", "US", []string{"splunk.com", "*.splunk.com", "*.splunkcloud.com"}},
		{"crowdstrike.com", "CrowdStrike, Inc.", "US", []string{"crowdstrike.com", "falcon.crowdstrike.com"}},
		{"zscaler.com", "Zscaler, Inc.", "US", []string{"zscaler.com", "*.zscaler.com", "*.zscaler.net"}},
		{"paloaltonetworks.com", "Palo Alto Networks", "US", []string{"paloaltonetworks.com", "*.paloaltonetworks.com"}},
		{"fortinet.com", "Fortinet, Inc.", "US", []string{"fortinet.com", "*.fortinet.com", "*.forticloud.com"}},
		{"qualys.com", "Qualys, Inc.", "US", []string{"qualys.com", "*.qualys.com"}},
		{"rapid7.com", "Rapid7, Inc.", "US", []string{"rapid7.com", "*.rapid7.com"}},
		{"servicenow.com", "ServiceNow, Inc.", "US", []string{"servicenow.com", "*.service-now.com"}},
		{"workday.com", "Workday, Inc.", "US", []string{"workday.com", "*.workday.com"}},
		{"zendesk.com", "Zendesk, Inc.", "US", []string{"zendesk.com", "*.zendesk.com"}},
	}

	for _, svc := range saasServices {
		issuer := pickInt(0, 1, 2, 4, 8, 14, 18, 19) // DigiCert, LE R3/R4, GlobalSign, Amazon, GTS
		leafHealthy(rng, now, &allCerts, svc.cn, svc.org, svc.country, svc.sans, issuer)
	}

	// ── Category 2: Internal corporate services — ACME Corp (120 certs) ─
	acmeDomains := []string{
		"portal", "intranet", "wiki", "jira", "confluence", "bamboo", "bitbucket",
		"jenkins", "gitlab", "sonarqube", "artifactory", "nexus", "vault",
		"consul", "nomad", "grafana", "prometheus", "alertmanager", "kibana",
		"elasticsearch", "logstash", "redis-admin", "rabbitmq-mgmt", "kafka-ui",
		"pgadmin", "phpmyadmin", "minio", "harbor", "argocd", "rancher",
		"keycloak", "sso", "ldap-proxy", "radius", "vpn-gateway", "vpn-portal",
		"mail", "webmail", "smtp-relay", "exchange", "sharepoint", "onedrive-proxy",
		"erp", "crm", "hr-portal", "payroll", "benefits", "timesheet",
		"helpdesk", "ticketing", "cmdb", "asset-mgmt", "inventory",
		"devops-dashboard", "ci-runner-01", "ci-runner-02", "ci-runner-03",
		"staging-api", "staging-web", "staging-admin", "staging-worker",
		"prod-api-01", "prod-api-02", "prod-api-03", "prod-web-01", "prod-web-02",
		"prod-worker-01", "prod-worker-02", "prod-scheduler", "prod-cache",
		"db-primary", "db-replica-01", "db-replica-02", "db-analytics",
		"backup-server", "nfs-01", "nas-storage", "tape-library",
		"monitoring", "nagios", "zabbix", "prtg", "solarwinds",
		"dns-primary", "dns-secondary", "dhcp-server", "ntp-server",
		"print-server", "scan-server", "fax-gateway",
		"video-conf", "voip-gateway", "pbx", "sip-proxy",
		"wifi-controller", "captive-portal", "guest-wifi",
		"building-mgmt", "hvac-controller", "access-control", "camera-nvr",
		"badge-reader-01", "badge-reader-02", "elevator-ctrl",
		"lab-equip-01", "lab-equip-02", "microscope-ctrl",
		"3d-printer", "cnc-controller", "plc-gateway",
		"scada-hmi", "scada-historian", "ot-firewall",
		"patch-mgmt", "wsus", "sccm", "intune-proxy",
		"code-signing", "timestamp-server", "ocsp-responder",
		"ca-admin", "certificate-portal", "key-escrow",
		"data-warehouse", "etl-server", "tableau", "powerbi-gateway",
		"ml-platform", "jupyter-hub", "gpu-cluster-01", "gpu-cluster-02",
		"api-gateway", "rate-limiter", "waf-admin", "load-balancer-mgmt",
	}

	for _, domain := range acmeDomains {
		cn := domain + ".acmecorp.internal"
		sans := []string{cn}
		if rng.Float64() < 0.3 {
			sans = append(sans, domain+".acmecorp.com")
		}
		issuer := &intermediates[29] // ACME Corp Internal CA G2
		spec := certSpec{
			cn: cn, org: "ACME Corp", country: "US",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(12), 0),
			notAfter:  now.AddDate(0, 3+rng.Intn(21), 0),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: sans, eku: []string{"Server Authentication"},
			ocsp: []string{"http://ocsp.acmecorp.internal"},
			scts: []string{"Google Argon2025"},
			source: model.SourceZeekPassive,
		}
		// Some use ECDSA
		if rng.Float64() < 0.3 {
			spec.keyAlg = model.KeyECDSA
			spec.keyBits = 256
			spec.sigAlg = model.SigECDSAWithSHA256
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 3: Meridian Health Systems (80 certs) ───────────────────
	meridianDomains := []string{
		"ehr", "emr", "pacs", "dicom-gateway", "hl7-broker", "fhir-api",
		"patient-portal", "provider-portal", "billing", "claims", "pharmacy",
		"lab-orders", "lab-results", "radiology", "pathology", "telehealth",
		"nurse-station-01", "nurse-station-02", "nurse-station-03",
		"nurse-station-04", "nurse-station-05", "nurse-station-06",
		"med-dispenser-01", "med-dispenser-02", "med-dispenser-03",
		"infusion-pump-gw-01", "infusion-pump-gw-02", "vitals-monitor-gw",
		"cardiac-monitor", "ventilator-mgmt", "anesthesia-records",
		"surgical-scheduling", "or-camera-01", "or-camera-02",
		"blood-bank", "transfusion-mgmt", "organ-tracking",
		"ambulance-dispatch", "ems-gateway", "trauma-alert",
		"staff-scheduling", "credentialing", "compliance",
		"hipaa-audit", "security-ops", "incident-mgmt",
		"dr-site-primary", "dr-site-failover", "dr-replication",
		"vpn-clinic-01", "vpn-clinic-02", "vpn-clinic-03",
		"vpn-clinic-04", "vpn-clinic-05", "vpn-satellite-01",
		"remote-desktop", "citrix-gateway", "vmware-horizon",
		"ad-dc-01", "ad-dc-02", "ad-dc-03", "radius-auth",
		"wifi-clinical", "wifi-guest", "wifi-iot-medical",
		"printer-pharmacy", "printer-nursing", "printer-admin",
		"building-automation", "medical-gas-monitor", "power-monitor",
		"biomedical-inventory", "device-calibration", "sterilization",
		"research-portal", "clinical-trials", "irb-submission",
		"patient-survey", "satisfaction-analytics", "quality-metrics",
		"supply-chain", "inventory-mgmt", "procurement",
	}

	for _, domain := range meridianDomains {
		cn := domain + ".meridianhealth.internal"
		issuer := &intermediates[30] // Meridian Health Systems PKI CA
		spec := certSpec{
			cn: cn, org: "Meridian Health Systems", country: "US",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(18), 0),
			notAfter:  now.AddDate(0, 6+rng.Intn(18), 0),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: []string{cn}, eku: []string{"Server Authentication"},
			ocsp: []string{"http://ocsp.meridianhealth.internal"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 4: Kensington Financial (70 certs) ─────────────────────
	kensingtonDomains := []string{
		"trading-platform", "order-mgmt", "fix-gateway-01", "fix-gateway-02",
		"market-data-feed", "risk-engine", "compliance-monitor", "aml-screening",
		"kyc-portal", "fraud-detection", "transaction-monitor",
		"internet-banking", "mobile-api", "corporate-banking", "wealth-mgmt",
		"payments-gateway", "swift-connector", "ach-processor", "wire-transfer",
		"card-processing", "atm-controller", "pos-gateway",
		"loan-origination", "underwriting", "credit-scoring", "collateral-mgmt",
		"treasury-mgmt", "liquidity-monitor", "forex-engine",
		"portfolio-analytics", "reporting-engine", "regulatory-filing",
		"customer-portal", "advisor-portal", "branch-network",
		"branch-london-01", "branch-london-02", "branch-london-03",
		"branch-nyc-01", "branch-nyc-02", "branch-frankfurt",
		"branch-singapore", "branch-hk", "branch-tokyo", "branch-sydney",
		"hsm-primary", "hsm-backup", "key-mgmt", "pin-translation",
		"token-vault", "encryption-gateway", "ssl-offload",
		"siem", "dlp-gateway", "endpoint-protection", "email-gateway",
		"proxy-dmz", "waf-external", "ddos-mitigation",
		"ad-primary", "ad-secondary", "pki-admin", "smartcard-enrollment",
		"video-surveillance", "access-control", "mantrap-controller",
		"dc-london-mgmt", "dc-nyc-mgmt", "dc-frankfurt-mgmt",
		"backup-vault", "archive-storage", "tape-offsite",
		"disaster-recovery", "business-continuity", "incident-response",
	}

	for _, domain := range kensingtonDomains {
		cn := domain + ".kensington.internal"
		issuer := &intermediates[31] // Kensington Financial Services Issuing CA
		spec := certSpec{
			cn: cn, org: "Kensington Financial", country: "GB",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(12), 0),
			notAfter:  now.AddDate(0, 6+rng.Intn(12), 0),
			keyAlg: model.KeyRSA, keyBits: 4096, sigAlg: model.SigSHA384WithRSA,
			sans: []string{cn}, eku: []string{"Server Authentication"},
			ocsp: []string{"http://ocsp.kensington.internal"},
			source: model.SourceZeekPassive,
		}
		if rng.Float64() < 0.4 {
			spec.keyAlg = model.KeyECDSA
			spec.keyBits = 384
			spec.sigAlg = model.SigECDSAWithSHA384
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 5: NovaTech Manufacturing / OT (60 certs) ──────────────
	novatechDomains := []string{
		"mes-server", "erp-connector", "quality-system", "sap-gateway",
		"scada-master-01", "scada-master-02", "scada-backup",
		"hmi-line-01", "hmi-line-02", "hmi-line-03", "hmi-line-04",
		"plc-gw-painting", "plc-gw-welding", "plc-gw-assembly", "plc-gw-pressing",
		"robot-ctrl-01", "robot-ctrl-02", "robot-ctrl-03", "robot-ctrl-04",
		"agv-fleet-mgr", "conveyor-ctrl", "warehouse-automation",
		"barcode-gateway", "rfid-reader-gw", "vision-system-01", "vision-system-02",
		"cmm-machine", "laser-scanner", "thermal-camera-gw",
		"energy-monitor", "compressed-air", "chiller-plant", "boiler-ctrl",
		"dust-collector", "fume-extractor", "water-treatment",
		"fire-alarm-panel", "sprinkler-ctrl", "gas-detection",
		"crane-01", "crane-02", "forklift-tracker",
		"tool-crib", "calibration-lab", "metrology",
		"shift-mgmt", "production-planning", "demand-forecast",
		"supplier-portal", "vendor-audit", "inbound-logistics",
		"shipping-dock-01", "shipping-dock-02", "customs-broker",
		"plant-wifi", "ot-dmz-firewall", "it-ot-gateway",
		"historian-primary", "historian-archive", "pi-connector",
		"opc-ua-server", "modbus-gateway", "profinet-proxy",
	}

	for _, domain := range novatechDomains {
		cn := domain + ".novatech.mfg"
		issuer := &intermediates[32] // NovaTech Manufacturing CA
		spec := certSpec{
			cn: cn, org: "NovaTech Industries", country: "DE",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(-1, -rng.Intn(24), 0),
			notAfter:  now.AddDate(0, 12+rng.Intn(36), 0), // OT often long-lived
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: []string{cn}, eku: []string{"Server Authentication"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 6: PacificEdge Telecom (50 certs) ──────────────────────
	pacificDomains := []string{
		"nms-core", "nms-transport", "nms-access", "nms-wireless",
		"oss-platform", "bss-platform", "billing-engine", "charging-gw",
		"subscriber-mgmt", "aaa-server-01", "aaa-server-02",
		"dns-resolver-01", "dns-resolver-02", "dhcp-pool-mgr",
		"edge-router-mgmt-01", "edge-router-mgmt-02", "core-router-mgmt",
		"mpls-controller", "sdwan-orchestrator", "sd-access",
		"5g-core-amf", "5g-core-smf", "5g-core-upf", "5g-core-nrf",
		"ims-cscf", "ims-hss", "voip-sbc-01", "voip-sbc-02",
		"media-gateway", "conference-bridge", "voicemail",
		"cdn-origin", "cdn-edge-syd", "cdn-edge-mel", "cdn-edge-bne",
		"iptv-head-end", "vod-server", "epg-service",
		"noc-dashboard", "alarm-correlator", "trouble-ticket",
		"field-service", "dispatch-system", "inventory-nms",
		"tower-monitor-01", "tower-monitor-02", "tower-monitor-03",
		"microwave-link-01", "microwave-link-02", "fiber-monitor",
		"customer-portal", "self-service", "speed-test",
	}

	for _, domain := range pacificDomains {
		cn := domain + ".pacificedge.net.au"
		issuer := &intermediates[33] // PacificEdge Telecom Infrastructure CA
		spec := certSpec{
			cn: cn, org: "PacificEdge Telecom", country: "AU",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(12), 0),
			notAfter:  now.AddDate(0, 6+rng.Intn(18), 0),
			keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
			sans: []string{cn}, eku: []string{"Server Authentication"},
			ocsp: []string{"http://ocsp.pacificedge.net.au"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 7: Shanghai Logistics (40 certs) ───────────────────────
	shanghaiDomains := []string{
		"port-ops", "berth-allocation", "crane-scheduler", "vessel-tracking",
		"container-tracking", "customs-declare", "manifest-system", "edocs",
		"yard-management", "gate-automation-01", "gate-automation-02",
		"reefer-monitoring", "dangerous-goods", "hazmat-tracking",
		"freight-booking", "rate-engine", "demurrage-calc", "invoice-system",
		"warehouse-wms", "cross-dock", "bonded-warehouse", "cold-storage",
		"truck-dispatch", "gps-tracking", "driver-portal", "weigh-bridge",
		"rail-interface", "intermodal-planner", "barge-scheduler",
		"cctv-controller", "access-gate-01", "access-gate-02", "perimeter-alarm",
		"it-helpdesk", "email-server", "file-server", "backup-server",
		"erp-sap", "finance-system", "hr-system", "procurement",
	}

	for _, domain := range shanghaiDomains {
		cn := domain + ".shport.logistics.cn"
		issuer := &intermediates[34] // Shanghai Logistics Platform CA
		spec := certSpec{
			cn: cn, org: "Shanghai Port Authority", country: "CN",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(12), 0),
			notAfter:  now.AddDate(0, 6+rng.Intn(24), 0),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: []string{cn}, eku: []string{"Server Authentication"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 8: International websites via unusual CAs (60 certs) ───
	intlSites := []struct {
		cn, org, country string
		issuerIdx        int
		sans             []string
	}{
		// Turkish sites via TUBITAK
		{"e-devlet.gov.tr", "T.C. Cumhurbaskanligi", "TR", 23, []string{"e-devlet.gov.tr", "www.turkiye.gov.tr"}},
		{"ibb.istanbul", "Istanbul Buyuksehir Belediyesi", "TR", 23, []string{"ibb.istanbul", "www.ibb.istanbul"}},
		{"thy.com", "Turk Hava Yollari A.O.", "TR", 23, []string{"thy.com", "www.thy.com"}},
		{"garanti.com.tr", "Garanti BBVA", "TR", 23, []string{"garanti.com.tr", "*.garanti.com.tr"}},
		{"akbank.com", "Akbank T.A.S.", "TR", 23, []string{"akbank.com", "www.akbank.com"}},
		// Indian sites via emSign
		{"irctc.co.in", "Indian Railway Catering and Tourism Corporation", "IN", 24, []string{"irctc.co.in", "www.irctc.co.in"}},
		{"onlinesbi.sbi", "State Bank of India", "IN", 24, []string{"onlinesbi.sbi", "www.onlinesbi.sbi"}},
		{"incometax.gov.in", "Income Tax Department", "IN", 24, []string{"incometax.gov.in", "www.incometax.gov.in"}},
		{"hdfcbank.com", "HDFC Bank Ltd", "IN", 24, []string{"hdfcbank.com", "netbanking.hdfcbank.com"}},
		{"infosys.com", "Infosys Limited", "IN", 24, []string{"infosys.com", "www.infosys.com"}},
		// Colombian sites via Certicamara
		{"registraduria.gov.co", "Registraduria Nacional del Estado Civil", "CO", 25, []string{"registraduria.gov.co"}},
		{"dian.gov.co", "DIAN", "CO", 25, []string{"dian.gov.co", "www.dian.gov.co"}},
		{"bancolombia.com", "Bancolombia S.A.", "CO", 25, []string{"bancolombia.com", "www.bancolombia.com"}},
		// Chinese sites via CFCA
		{"icbc.com.cn", "Industrial and Commercial Bank of China", "CN", 22, []string{"icbc.com.cn", "www.icbc.com.cn"}},
		{"ccb.com", "China Construction Bank", "CN", 22, []string{"ccb.com", "www.ccb.com"}},
		{"boc.cn", "Bank of China", "CN", 22, []string{"boc.cn", "www.boc.cn"}},
		{"alipay.com", "Alipay.com Co., Ltd.", "CN", 22, []string{"alipay.com", "*.alipay.com"}},
		{"unionpay.com", "China UnionPay Co., Ltd.", "CN", 22, []string{"unionpay.com", "*.unionpay.com"}},
		// Korean sites via NAVER
		{"naver.com", "NAVER Corp.", "KR", 27, []string{"naver.com", "www.naver.com", "*.naver.com"}},
		{"line.me", "LINE Corporation", "KR", 27, []string{"line.me", "*.line.me"}},
		{"kakao.com", "Kakao Corp.", "KR", 27, []string{"kakao.com", "*.kakao.com"}},
		{"samsung.com", "Samsung Electronics Co., Ltd.", "KR", 27, []string{"samsung.com", "www.samsung.com"}},
		// Polish sites via Certum
		{"gov.pl", "Centrum Projektow Polska Cyfrowa", "PL", 28, []string{"gov.pl", "www.gov.pl"}},
		{"mbank.pl", "mBank S.A.", "PL", 28, []string{"mbank.pl", "online.mbank.pl"}},
		{"allegro.pl", "Allegro.pl sp. z o.o.", "PL", 28, []string{"allegro.pl", "www.allegro.pl"}},
		// IdenTrust
		{"treasury.gov", "U.S. Department of the Treasury", "US", 26, []string{"treasury.gov", "www.treasury.gov"}},
		{"irs.gov", "Internal Revenue Service", "US", 26, []string{"irs.gov", "www.irs.gov"}},
		// More international via various
		{"rakuten.co.jp", "Rakuten Group, Inc.", "JP", 8, []string{"rakuten.co.jp", "www.rakuten.co.jp"}},
		{"mercadolibre.com", "MercadoLibre S.R.L.", "AR", 12, []string{"mercadolibre.com", "*.mercadolibre.com"}},
		{"grab.com", "Grab Holdings Limited", "SG", 14, []string{"grab.com", "*.grab.com"}},
		{"gojek.com", "PT GoTo Gojek Tokopedia", "ID", 14, []string{"gojek.com", "*.gojek.com"}},
		{"flipkart.com", "Flipkart Internet Pvt Ltd", "IN", 14, []string{"flipkart.com", "*.flipkart.com"}},
		{"shopee.com", "Sea Limited", "SG", 14, []string{"shopee.com", "*.shopee.com"}},
		{"olx.com", "OLX Global B.V.", "NL", 12, []string{"olx.com", "*.olx.com"}},
		{"booking.com", "Booking.com B.V.", "NL", 0, []string{"booking.com", "*.booking.com"}},
		{"transferwise.com", "Wise Payments Limited", "GB", 12, []string{"transferwise.com", "wise.com"}},
		{"revolut.com", "Revolut Ltd", "GB", 12, []string{"revolut.com", "*.revolut.com"}},
		{"n26.com", "N26 GmbH", "DE", 12, []string{"n26.com", "app.n26.com"}},
		{"spotify.com", "Spotify AB", "SE", 0, []string{"spotify.com", "*.spotify.com"}},
		{"klarna.com", "Klarna Bank AB", "SE", 0, []string{"klarna.com", "*.klarna.com"}},
		// Extra international variety
		{"yandex.ru", "Yandex LLC", "RU", 8, []string{"yandex.ru", "*.yandex.ru"}},
		{"tinkoff.ru", "TCS Group", "RU", 8, []string{"tinkoff.ru", "*.tinkoff.ru"}},
		{"paytm.com", "One97 Communications Ltd", "IN", 14, []string{"paytm.com", "*.paytm.com"}},
		{"rappi.com", "Rappi Inc.", "CO", 14, []string{"rappi.com", "*.rappi.com"}},
		{"nubank.com.br", "Nu Pagamentos S.A.", "BR", 14, []string{"nubank.com.br", "*.nubank.com.br"}},
		{"wechat.com", "Tencent Holdings Limited", "CN", 22, []string{"wechat.com", "weixin.qq.com"}},
		{"alibaba.com", "Alibaba Group Holding Limited", "CN", 22, []string{"alibaba.com", "*.alibaba.com"}},
		{"taobao.com", "Zhejiang Taobao Network Co., Ltd.", "CN", 22, []string{"taobao.com", "*.taobao.com"}},
		{"jd.com", "Beijing Jingdong 360 Co., Ltd.", "CN", 22, []string{"jd.com", "*.jd.com"}},
		{"baidu.com", "Baidu, Inc.", "CN", 22, []string{"baidu.com", "*.baidu.com"}},
	}

	for _, site := range intlSites {
		issuer := &intermediates[site.issuerIdx]
		spec := certSpec{
			cn: site.cn, org: site.org, country: site.country,
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(9), 0),
			notAfter:  now.AddDate(0, 3+rng.Intn(12), 0),
			keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
			sans: site.sans, eku: []string{"Server Authentication", "Client Authentication"},
			ocsp: []string{fmt.Sprintf("http://ocsp.%s.example", sanitizeForURL(issuer.org))},
			scts: []string{"Google Argon2025", "Cloudflare Nimbus2025"},
			source: model.SourceZeekPassive,
		}
		if rng.Float64() < 0.35 {
			spec.keyAlg = model.KeyRSA
			spec.keyBits = 2048
			spec.sigAlg = model.SigSHA256WithRSA
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 9: Problematic / failing certs (100 certs) ─────────────

	// Expired certs
	expiredHosts := []string{
		"old-app.legacy.local", "deprecated-api.corp.net", "test-2024.staging.io",
		"dev-sandbox.internal", "poc-demo.lab.local", "migration-temp.old.corp",
		"decommissioned-web.prod", "retired-service.api.local", "eol-platform.corp",
		"sunset-portal.legacy.net", "v1-api.old.service.com", "archive-web.corp.net",
		"legacy-billing.finance.local", "old-crm.sales.internal",
		"retired-vpn.remote.local", "deprecated-mail.corp.net",
		"obsolete-ftp.storage.local", "old-wiki.docs.internal",
		"legacy-dns.infra.local", "decomm-proxy.dmz.corp",
	}
	for i, host := range expiredHosts {
		daysExpired := 5 + rng.Intn(180)
		issuer := pickInt(4, 12, 20, 29) // Various issuers
		spec := certSpec{
			cn: host, org: fmt.Sprintf("Legacy Division %d", i%5), country: "US",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(-2, 0, 0), notAfter: now.AddDate(0, 0, -daysExpired),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: []string{host}, eku: []string{"Server Authentication"},
			ocsp: []string{"http://ocsp.legacy.internal"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// Expiring soon (within 30 days)
	expiringSoonHosts := []string{
		"checkout.store.example.com", "api-v2.payments.io", "cdn-origin.media.net",
		"auth.identity.corp.com", "search.index.internal", "cache-redis.data.local",
		"queue-broker.msg.internal", "stream-ingest.video.com", "webhook.notify.io",
		"gateway.partner-api.com", "sync.mobile-backend.io", "upload.assets.cdn.com",
		"reports.analytics.corp.com", "export.datawarehouse.io", "alerts.monitor.internal",
		"cron-scheduler.jobs.local", "email-relay.comms.internal", "sms-gateway.notify.io",
		"push-server.mobile.corp", "feed-aggregator.content.io",
	}
	for _, host := range expiringSoonHosts {
		daysLeft := 1 + rng.Intn(28)
		issuer := pickInt(4, 8, 14, 18)
		spec := certSpec{
			cn: host, org: "Various Corp",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -11, 0), notAfter: now.AddDate(0, 0, daysLeft),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: []string{host}, eku: []string{"Server Authentication"},
			ocsp: []string{"http://ocsp.example.com"},
			scts: []string{"Google Argon2025"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// Weak keys (RSA 1024)
	weakKeyHosts := []string{
		"old-vpn.remote.corp", "legacy-ssh.mgmt.local", "printer-web.office.local",
		"kvm-console.dc.local", "ups-mgmt.power.local", "pdu-ctrl.dc.local",
		"switch-mgmt-old.net.local", "ap-controller-v1.wifi.local",
		"ip-phone-admin.voice.local", "camera-dvr.security.local",
		"badge-reader.physical.local", "thermostat-ctrl.building.local",
		"elevator-diagnostic.building.local", "parking-gate.facility.local",
		"vending-mgmt.services.local", "digital-signage.lobby.local",
	}
	for _, host := range weakKeyHosts {
		issuer := pickInt(29, 30, 32) // Internal CAs
		spec := certSpec{
			cn: host, org: "Legacy Equipment",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(-3, 0, 0), notAfter: now.AddDate(2, 0, 0),
			keyAlg: model.KeyRSA, keyBits: 1024, sigAlg: model.SigSHA256WithRSA,
			sans: []string{host}, eku: []string{"Server Authentication"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// SHA-1 signed
	sha1Hosts := []string{
		"sha1-legacy.compliance.local", "old-webserver.dmz.corp",
		"ancient-appliance.net.local", "embedded-ctrl.ot.factory",
		"scada-legacy.plant.local", "firmware-update.device.local",
		"management-card.server.local", "bmc-controller.hw.local",
		"ilo-console.hp.local", "idrac-old.dell.local",
	}
	for _, host := range sha1Hosts {
		issuer := pickInt(29, 30, 32)
		spec := certSpec{
			cn: host, org: "Legacy Infrastructure",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(-4, 0, 0), notAfter: now.AddDate(1, 0, 0),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA1WithRSA,
			sans: []string{host}, eku: []string{"Server Authentication"},
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// Self-signed (dev / test / shadow IT)
	selfSignedHosts := []string{
		"dev.localhost", "test-server.local", "staging.local", "demo.local",
		"raspberry-pi.home", "nas.home.local", "plex.home.local",
		"homeassistant.local", "pihole.local", "unifi.local",
		"gitlab-runner.dev", "docker-registry.dev", "nexus.dev.local",
		"jupyter.ml-lab.local", "tensorboard.ml.local", "mlflow.data.local",
		"dev-db.postgres.local", "dev-redis.cache.local", "dev-mongo.nosql.local",
		"test-kafka.stream.local", "test-elastic.search.local",
		"shadow-it-crm.sales", "rogue-wiki.engineering", "unauthorized-vpn.remote",
		"personal-nas.employee", "unapproved-app.dept",
	}
	for _, host := range selfSignedHosts {
		spec := certSpec{
			cn: host, org: "Self-Signed",
			issuerCN: host, issuerOrg: "Self-Signed",
			selfSigned: true,
			notBefore: now.AddDate(0, -rng.Intn(12), 0),
			notAfter:  now.AddDate(0, 6+rng.Intn(48), 0),
			keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
			sans: []string{host, "localhost", "127.0.0.1"}, eku: []string{"Server Authentication"},
			source: model.SourceZeekPassive,
		}
		if rng.Float64() < 0.4 {
			spec.keyAlg = model.KeyRSA
			spec.keyBits = 2048
			spec.sigAlg = model.SigSHA256WithRSA
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// No revocation info
	noRevocationHosts := []string{
		"internal-tool-01.corp", "internal-tool-02.corp", "internal-tool-03.corp",
		"quick-deploy.staging", "temp-service.testing", "hackathon-app.dev",
		"mvp-prototype.lab", "experiment-alpha.research", "poc-blockchain.innovation",
	}
	for _, host := range noRevocationHosts {
		issuer := pickInt(4, 29)
		spec := certSpec{
			cn: host, org: "Rapid Deployment",
			issuerCN: issuer.cn, issuerOrg: issuer.org,
			notBefore: now.AddDate(0, -rng.Intn(6), 0),
			notAfter:  now.AddDate(0, 3+rng.Intn(9), 0),
			keyAlg: model.KeyRSA, keyBits: 2048, sigAlg: model.SigSHA256WithRSA,
			sans: []string{host}, eku: []string{"Server Authentication"},
			// deliberately no OCSP, CRL, or SCTs
			source: model.SourceZeekPassive,
		}
		allCerts = append(allCerts, makeCert(spec))
	}

	// ── Category 10: Cloud / K8s / microservices (150 certs) ────────────
	microserviceNames := []string{
		"user-service", "auth-service", "profile-service", "notification-service",
		"email-service", "sms-service", "push-service", "webhook-service",
		"payment-service", "billing-service", "invoice-service", "subscription-service",
		"order-service", "cart-service", "checkout-service", "inventory-service",
		"product-service", "catalog-service", "search-service", "recommendation-service",
		"review-service", "rating-service", "comment-service", "moderation-service",
		"media-service", "image-service", "video-service", "transcoding-service",
		"storage-service", "upload-service", "download-service", "cdn-service",
		"analytics-service", "tracking-service", "metrics-service", "logging-service",
		"audit-service", "compliance-service", "reporting-service", "export-service",
		"gateway-service", "routing-service", "discovery-service", "config-service",
		"secret-service", "vault-service", "key-service", "token-service",
		"cache-service", "session-service",
	}
	environments := []string{"prod", "staging", "dev"}
	clusters := []string{"us-east-1", "us-west-2", "eu-west-1"}

	for _, svc := range microserviceNames {
		for _, env := range environments {
			cluster := clusters[rng.Intn(len(clusters))]
			cn := fmt.Sprintf("%s.%s.%s.k8s.acmecorp.com", svc, env, cluster)
			issuer := pickInt(4, 6, 14, 29) // LE R3, E5, Amazon, internal
			spec := certSpec{
				cn: cn, org: "ACME Corp",
				issuerCN: issuer.cn, issuerOrg: issuer.org,
				notBefore: now.AddDate(0, -rng.Intn(3), 0),
				notAfter:  now.AddDate(0, 1+rng.Intn(3), 0), // short-lived
				keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
				sans: []string{cn, fmt.Sprintf("%s.%s.svc.cluster.local", svc, env)},
				eku:  []string{"Server Authentication", "Client Authentication"},
				scts: []string{"Google Argon2025"},
				source: model.SourceZeekPassive,
			}
			allCerts = append(allCerts, makeCert(spec))
		}
	}

	// ── Category 11: IoT / embedded devices (80 certs, often long-lived) ─
	iotDevices := []struct{ prefix, org string; count int }{
		{"sensor-temp", "SmartBuilding IoT", 10},
		{"sensor-humidity", "SmartBuilding IoT", 8},
		{"sensor-co2", "SmartBuilding IoT", 5},
		{"smart-meter", "GridTech Energy", 12},
		{"ev-charger", "ChargePoint Systems", 8},
		{"traffic-cam", "CityNet Infrastructure", 10},
		{"parking-sensor", "CityNet Infrastructure", 8},
		{"air-quality", "CityNet Infrastructure", 5},
		{"water-level", "AquaMonitor Systems", 6},
		{"weather-station", "MeteoTech Corp", 8},
	}

	for _, dev := range iotDevices {
		for i := 0; i < dev.count; i++ {
			cn := fmt.Sprintf("%s-%03d.iot.local", dev.prefix, i+1)
			issuer := pickInt(29, 32) // Internal CAs
			spec := certSpec{
				cn: cn, org: dev.org,
				issuerCN: issuer.cn, issuerOrg: issuer.org,
				notBefore: now.AddDate(-2, -rng.Intn(12), 0),
				notAfter:  now.AddDate(3+rng.Intn(7), 0, 0), // IoT: very long lived
				keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
				sans: []string{cn}, eku: []string{"Server Authentication", "Client Authentication"},
				source: model.SourceZeekPassive,
			}
			// Some old IoT uses RSA-1024
			if rng.Float64() < 0.15 {
				spec.keyAlg = model.KeyRSA
				spec.keyBits = 1024
				spec.sigAlg = model.SigSHA256WithRSA
			}
			allCerts = append(allCerts, makeCert(spec))
		}
	}

	// ── Category 12: Additional healthy public sites (bulk fill to ~1500) ─
	bulkDomains := []struct{ cn, org string }{
		{"api.example.com", "Example Inc"}, {"cdn.example.com", "Example Inc"},
		{"mail.example.com", "Example Inc"}, {"shop.example.com", "Example Inc"},
		{"blog.example.com", "Example Inc"}, {"docs.example.com", "Example Inc"},
		{"status.example.com", "Example Inc"}, {"support.example.com", "Example Inc"},
		{"dev.example.com", "Example Inc"}, {"beta.example.com", "Example Inc"},
		{"staging.example.com", "Example Inc"}, {"preview.example.com", "Example Inc"},
		{"download.example.com", "Example Inc"}, {"updates.example.com", "Example Inc"},
		{"telemetry.example.com", "Example Inc"}, {"feedback.example.com", "Example Inc"},
		{"careers.example.com", "Example Inc"}, {"investor.example.com", "Example Inc"},
		{"press.example.com", "Example Inc"}, {"legal.example.com", "Example Inc"},
	}
	// Generate 10 variations per domain using subdomains
	for _, d := range bulkDomains {
		for j := 1; j <= 10; j++ {
			cn := fmt.Sprintf("%s-%d.%s", "node", j, d.cn)
			issuer := pickInt(0, 1, 2, 4, 8, 12, 14, 18, 19)
			spec := certSpec{
				cn: cn, org: d.org,
				issuerCN: issuer.cn, issuerOrg: issuer.org,
				notBefore: now.AddDate(0, -rng.Intn(10), 0),
				notAfter:  now.AddDate(0, 3+rng.Intn(12), 0),
				keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
				sans: []string{cn, d.cn}, eku: []string{"Server Authentication"},
				ocsp: []string{fmt.Sprintf("http://ocsp.%s.example", sanitizeForURL(issuer.org))},
				scts: []string{"Google Argon2025", "Cloudflare Nimbus2025"},
				source: model.SourceZeekPassive,
			}
			if rng.Float64() < 0.3 {
				spec.keyAlg = model.KeyRSA
				spec.keyBits = chooseRSABits(rng)
				spec.sigAlg = model.SigSHA256WithRSA
			}
			allCerts = append(allCerts, makeCert(spec))
		}
	}

	// ════════════════════════════════════════════════════════════════════════
	// UPSERT ALL CERTIFICATES + SCORE
	// ════════════════════════════════════════════════════════════════════════

	log.Info().Int("total", len(allCerts)).Msg("seeding certificates...")

	for i, c := range allCerts {
		if err := st.UpsertCertificate(ctx, c); err != nil {
			return fmt.Errorf("upsert cert %d (%s): %w", i, c.Subject.CommonName, err)
		}
		if (i+1)%100 == 0 {
			log.Info().Int("progress", i+1).Int("total", len(allCerts)).Msg("certificates upserted")
		}
	}
	log.Info().Int("count", len(allCerts)).Msg("all certificates upserted")

	// Score all
	for i, c := range allCerts {
		report := analysis.ScoreCertificate(c)
		if err := st.SaveHealthReport(ctx, report); err != nil {
			return fmt.Errorf("save health report %d: %w", i, err)
		}
		if (i+1)%100 == 0 {
			log.Info().Int("progress", i+1).Msg("health reports saved")
		}
	}
	log.Info().Msg("all health reports scored")

	// ════════════════════════════════════════════════════════════════════════
	// OBSERVATIONS — varying TLS versions and cipher suites
	// ════════════════════════════════════════════════════════════════════════

	type cipherProfile struct {
		version  model.TLSVersion
		cipher   string
		strength model.CipherStrength
	}

	cipherProfiles := []cipherProfile{
		// TLS 1.3 — Best
		{model.TLSVersion13, "TLS_AES_128_GCM_SHA256", model.StrengthBest},
		{model.TLSVersion13, "TLS_AES_256_GCM_SHA384", model.StrengthBest},
		{model.TLSVersion13, "TLS_CHACHA20_POLY1305_SHA256", model.StrengthBest},
		// TLS 1.2 ECDHE+AEAD — Strong
		{model.TLSVersion12, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", model.StrengthStrong},
		{model.TLSVersion12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", model.StrengthStrong},
		{model.TLSVersion12, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", model.StrengthStrong},
		{model.TLSVersion12, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", model.StrengthStrong},
		{model.TLSVersion12, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", model.StrengthStrong},
		// TLS 1.2 CBC — Acceptable
		{model.TLSVersion12, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", model.StrengthAcceptable},
		{model.TLSVersion12, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", model.StrengthAcceptable},
		{model.TLSVersion12, "TLS_RSA_WITH_AES_256_GCM_SHA384", model.StrengthAcceptable},
		// TLS 1.1 — Weak
		{model.TLSVersion11, "TLS_RSA_WITH_AES_128_CBC_SHA", model.StrengthWeak},
		{model.TLSVersion11, "TLS_RSA_WITH_AES_256_CBC_SHA", model.StrengthWeak},
		// TLS 1.0 — Weak
		{model.TLSVersion10, "TLS_RSA_WITH_AES_128_CBC_SHA", model.StrengthWeak},
		// Insecure
		{model.TLSVersion12, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", model.StrengthInsecure},
		{model.TLSVersion12, "TLS_RSA_WITH_RC4_128_SHA", model.StrengthInsecure},
		{model.TLSVersionSSL30, "SSL_RSA_WITH_3DES_EDE_CBC_SHA", model.StrengthInsecure},
	}

	obsCount := 0
	ipOctet := 0
	for _, c := range allCerts {
		if c.IsCA {
			continue // Skip CA certs for observations
		}

		// Each leaf gets 1-8 observations
		numObs := 1 + rng.Intn(8)

		// Pick cipher profile based on cert health
		var profile cipherProfile
		report, _ := st.GetHealthReport(ctx, c.FingerprintSHA256)
		if report != nil && report.Score >= 85 {
			profile = cipherProfiles[rng.Intn(8)] // TLS 1.3 or strong 1.2
		} else if report != nil && report.Score >= 50 {
			profile = cipherProfiles[3+rng.Intn(8)] // TLS 1.2 various
		} else {
			profile = cipherProfiles[8+rng.Intn(len(cipherProfiles)-8)] // Weak/insecure
		}

		ipOctet++
		serverIP := fmt.Sprintf("10.%d.%d.%d", (ipOctet/65536)%256, (ipOctet/256)%256, ipOctet%256)
		port := 443
		if rng.Float64() < 0.1 {
			port = 8443
		}

		for j := 0; j < numObs; j++ {
			obs := &model.CertificateObservation{
				CertFingerprint:   c.FingerprintSHA256,
				ServerIP:          serverIP,
				ServerPort:        port,
				ServerName:        c.Subject.CommonName,
				NegotiatedVersion: profile.version,
				NegotiatedCipher:  profile.cipher,
				CipherStrength:    profile.strength,
				Source:            model.SourceZeekPassive,
				ObservedAt:        now.Add(-time.Duration(j*rng.Intn(24)) * time.Hour),
			}
			if err := st.RecordObservation(ctx, obs); err != nil {
				return fmt.Errorf("record observation: %w", err)
			}
			obsCount++
		}

		// Endpoint profile
		ep := &model.EndpointProfile{
			ServerIP:               serverIP,
			ServerPort:             port,
			ServerName:             c.Subject.CommonName,
			CertFingerprint:        c.FingerprintSHA256,
			MinTLSVersion:          profile.version,
			MaxTLSVersion:          profile.version,
			CipherSuites:           []string{profile.cipher},
			SupportsForwardSecrecy: profile.strength == model.StrengthBest || profile.strength == model.StrengthStrong,
			SupportsAEAD:           profile.strength == model.StrengthBest || profile.strength == model.StrengthStrong,
			HasWeakCiphers:         profile.strength == model.StrengthWeak || profile.strength == model.StrengthInsecure,
			ObservationCount:       numObs,
			FirstSeen:              now.AddDate(0, -3, 0),
			LastSeen:               now,
		}
		if err := st.UpsertEndpointProfile(ctx, ep); err != nil {
			return fmt.Errorf("upsert endpoint: %w", err)
		}

		if obsCount%500 == 0 {
			log.Info().Int("observations", obsCount).Msg("seeding observations...")
		}
	}

	log.Info().
		Int("certificates", len(allCerts)).
		Int("observations", obsCount).
		Msg("seed complete")

	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func leafHealthy(rng *rand.Rand, now time.Time, allCerts *[]*model.Certificate,
	cn, org, country string, sans []string, issuer *intSpec) {
	spec := certSpec{
		cn: cn, org: org, country: country,
		issuerCN: issuer.cn, issuerOrg: issuer.org,
		notBefore: now.AddDate(0, -rng.Intn(9), 0),
		notAfter:  now.AddDate(0, 3+rng.Intn(12), 0),
		keyAlg: model.KeyECDSA, keyBits: 256, sigAlg: model.SigECDSAWithSHA256,
		sans: sans, eku: []string{"Server Authentication", "Client Authentication"},
		ocsp: []string{fmt.Sprintf("http://ocsp.%s.example", sanitizeForURL(issuer.org))},
		scts: []string{"Google Argon2025", "Cloudflare Nimbus2025"},
		source: model.SourceZeekPassive,
	}
	if rng.Float64() < 0.3 {
		spec.keyAlg = model.KeyRSA
		spec.keyBits = chooseRSABits(rng)
		spec.sigAlg = model.SigSHA256WithRSA
	}
	*allCerts = append(*allCerts, makeCert(spec))
}

func chooseRSABits(rng *rand.Rand) int {
	if rng.Float64() < 0.4 {
		return 4096
	}
	return 2048
}

func sanitizeForURL(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			out = append(out, byte(c))
		}
	}
	return string(out)
}

// ── Certificate builder ─────────────────────────────────────────────────────

type certSpec struct {
	cn, org, ou, country, state, locality string
	issuerCN, issuerOrg                  string
	notBefore, notAfter                  time.Time
	keyAlg                               model.KeyAlgorithm
	keyBits                              int
	sigAlg                               model.SignatureAlgorithm
	isCA, selfSigned                     bool
	sans                                 []string
	keyUsage                             []string
	eku                                  []string
	ocsp                                 []string
	crl                                  []string
	scts                                 []string
	source                               model.DiscoverySource
}

func makeCert(s certSpec) *model.Certificate {
	subjectFull := fmt.Sprintf("CN=%s, O=%s, C=%s", s.cn, s.org, s.country)
	issuerFull := fmt.Sprintf("CN=%s, O=%s", s.issuerCN, s.issuerOrg)

	hash := sha256.Sum256([]byte(s.cn + "|" + s.org + "|" + s.issuerCN))
	fp := fmt.Sprintf("%x", hash)
	serial := fmt.Sprintf("%X", hash[:8])

	if s.sans == nil { s.sans = []string{} }
	if s.keyUsage == nil { s.keyUsage = []string{} }
	if s.eku == nil { s.eku = []string{} }
	if s.ocsp == nil { s.ocsp = []string{} }
	if s.crl == nil { s.crl = []string{} }
	if s.scts == nil { s.scts = []string{} }

	src := s.source
	if src == "" {
		src = model.SourceZeekPassive
	}

	return &model.Certificate{
		FingerprintSHA256: fp,
		Subject: model.DistinguishedName{
			CommonName: s.cn, Organization: s.org, Country: s.country, Full: subjectFull,
		},
		Issuer: model.DistinguishedName{
			CommonName: s.issuerCN, Organization: s.issuerOrg, Full: issuerFull,
		},
		SerialNumber:          serial,
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		KeyAlgorithm:          s.keyAlg,
		KeySizeBits:           s.keyBits,
		SignatureAlgorithm:    s.sigAlg,
		SubjectAltNames:       s.sans,
		IsCA:                  s.isCA,
		KeyUsage:              s.keyUsage,
		ExtendedKeyUsage:      s.eku,
		OCSPResponderURLs:     s.ocsp,
		CRLDistributionPoints: s.crl,
		SCTs:                  s.scts,
		SourceDiscovery:       src,
		FirstSeen:             s.notBefore,
		LastSeen:              time.Now(),
	}
}
