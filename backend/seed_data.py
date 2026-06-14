"""
TrustGraph Production Seed Dataset Generator
Generates hyper-realistic multi-stage supply chain breach dataset
tracking an explicit 7-point attack narrative across enterprise infrastructure.

Attack Narrative:
  Stage 1: VendorX credentials compromised (external intrusion)
  Stage 2: Suspicious web ingress API calls hit primary API Gateway  
  Stage 3: Host lateral movement via authenticated transport protocols
  Stage 4: Privilege escalation against internal containers
  Stage 5: Unauthorized database access — Customer PII exfiltration
  Stage 6: CARAG background discovery hunts execute
  Stage 7: Target isolation and runtime boundary containment
"""
import csv
import json
import math
import os
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# Seed for reproducibility
random.seed(42)

OUTPUT_DIR = Path("./seed_data")
OUTPUT_DIR.mkdir(exist_ok=True)

# ─── Attack Timeline ───────────────────────────────────────────────────────────
BREACH_START = datetime(2024, 1, 15, 6, 0, 0)  # 6:00 AM UTC

def ts(minutes_offset: float, jitter_seconds: float = 0) -> str:
    """Generate ISO timestamp with optional jitter."""
    t = BREACH_START + timedelta(minutes=minutes_offset) + timedelta(seconds=random.uniform(-jitter_seconds, jitter_seconds))
    return t.isoformat() + "Z"


# ─── 1. VENDORS CSV ───────────────────────────────────────────────────────────

def generate_vendors():
    vendors = [
        # Primary threat actor: VendorX — fully compromised
        {"vendor_id":"vendor_vendorx","vendor_name":"VendorX API Solutions","category":"API Integration","country":"United States","contact_email":"security@vendorx.com","contract_tier":"enterprise","risk_score":91.2,"privilege_level":4,"api_key_rotations":2,"api_key_last_rotation":"2023-11-01T00:00:00Z","cryptographic_standard":"TLS1.2/RC4","data_access_volume_gb":2340.5,"anomaly_count":47,"compliance_soc2":"non_compliant","compliance_iso27001":"non_compliant","compliance_gdpr":"partial","ip_address":"203.0.113.45","gat_compromise_score":0.89,"historical_trust_score":0.11,"risk_state":"compromised","graph_dependency_depth":6,"stage_of_breach":1,"breach_notes":"Initial external credential compromise via phishing. API key reuse across 4 distinct IPs detected."},
        
        # Secondary threat: PayStream — suspicious API volume
        {"vendor_id":"vendor_paystream","vendor_name":"PayStream Financial","category":"Payment Processing","country":"Singapore","contact_email":"security@paystream.sg","contract_tier":"enterprise","risk_score":78.9,"privilege_level":4,"api_key_rotations":4,"api_key_last_rotation":"2023-12-15T00:00:00Z","cryptographic_standard":"TLS1.3/AES256","data_access_volume_gb":1205.3,"anomaly_count":21,"compliance_soc2":"partial","compliance_iso27001":"compliant","compliance_gdpr":"under_review","ip_address":"198.51.100.55","gat_compromise_score":0.71,"historical_trust_score":0.29,"risk_state":"at_risk","graph_dependency_depth":4,"stage_of_breach":0,"breach_notes":"Anomalous API volume 75x above baseline. Token rotation bypass detected."},
        
        # Cloud provider: Acme — container privilege escalation vector
        {"vendor_id":"vendor_acme","vendor_name":"Acme Cloud Services","category":"Cloud Infrastructure","country":"Germany","contact_email":"security@acme-cloud.de","contract_tier":"enterprise","risk_score":62.4,"privilege_level":3,"api_key_rotations":12,"api_key_last_rotation":"2024-01-01T00:00:00Z","cryptographic_standard":"TLS1.3/AES256","data_access_volume_gb":890.2,"anomaly_count":8,"compliance_soc2":"compliant","compliance_iso27001":"partial","compliance_gdpr":"compliant","ip_address":"198.51.100.20","gat_compromise_score":0.41,"historical_trust_score":0.60,"risk_state":"at_risk","graph_dependency_depth":3,"stage_of_breach":0,"breach_notes":"Container cluster svc-cluster-7 shows unauthorized EXEC operations."},
        
        # Safe vendor: DataBridge
        {"vendor_id":"vendor_databridge","vendor_name":"DataBridge Analytics","category":"Data Analytics","country":"United Kingdom","contact_email":"security@databridge.co.uk","contract_tier":"standard","risk_score":44.1,"privilege_level":2,"api_key_rotations":24,"api_key_last_rotation":"2024-01-10T00:00:00Z","cryptographic_standard":"TLS1.3/AES256","data_access_volume_gb":445.8,"anomaly_count":3,"compliance_soc2":"compliant","compliance_iso27001":"compliant","compliance_gdpr":"compliant","ip_address":"192.0.2.88","gat_compromise_score":0.22,"historical_trust_score":0.81,"risk_state":"safe","graph_dependency_depth":2,"stage_of_breach":0,"breach_notes":"No anomalies detected. Compliant vendor."},
        
        # Safe vendor: SecureAuth
        {"vendor_id":"vendor_secureauth","vendor_name":"SecureAuth Identity","category":"Identity & Access","country":"Netherlands","contact_email":"security@secureauth.nl","contract_tier":"enterprise","risk_score":28.3,"privilege_level":5,"api_key_rotations":36,"api_key_last_rotation":"2024-01-12T00:00:00Z","cryptographic_standard":"TLS1.3/ChaCha20","data_access_volume_gb":122.9,"anomaly_count":1,"compliance_soc2":"compliant","compliance_iso27001":"compliant","compliance_gdpr":"compliant","ip_address":"198.51.100.71","gat_compromise_score":0.09,"historical_trust_score":0.94,"risk_state":"safe","graph_dependency_depth":1,"stage_of_breach":0,"breach_notes":"Highest trust tier. Identity provider — critical infrastructure."},
        
        # Medium risk: Logistix
        {"vendor_id":"vendor_logistix","vendor_name":"Logistix Supply Chain","category":"Logistics & Supply","country":"Japan","contact_email":"security@logistix.co.jp","contract_tier":"standard","risk_score":55.7,"privilege_level":2,"api_key_rotations":8,"api_key_last_rotation":"2023-10-01T00:00:00Z","cryptographic_standard":"TLS1.3/AES256","data_access_volume_gb":678.4,"anomaly_count":12,"compliance_soc2":"compliant","compliance_iso27001":"partial","compliance_gdpr":"under_review","ip_address":"203.0.113.102","gat_compromise_score":0.35,"historical_trust_score":0.68,"risk_state":"at_risk","graph_dependency_depth":2,"stage_of_breach":0,"breach_notes":"API key overdue for rotation (>90 days). Compliance partially expired."},
    ]
    
    fieldnames = list(vendors[0].keys())
    with open(OUTPUT_DIR / "vendors.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(vendors)
    
    print(f"* vendors.csv: {len(vendors)} records")
    return vendors


# ─── 2. SERVICES CSV ──────────────────────────────────────────────────────────

def generate_services():
    services = [
        # Stage 2: API Gateway — initial ingress point
        {"service_id":"node_api_gw","service_name":"VendorX API Gateway","service_type":"Service","vendor_id":"vendor_vendorx","ip_address":"203.0.113.45","port":443,"protocol":"HTTPS","service_tier":"external","privilege_level":3,"iam_role":"vendorx_api_invoker","gat_compromise_score":0.89,"anomaly_count":47,"historical_trust_score":0.11,"risk_state":"compromised","is_internet_facing":True,"breach_stage":2,"breach_notes":"47 anomalous auth attempts. Session token reuse across 4 IPs. Initial ingress point."},
        
        # Stage 3: Web host — lateral movement target
        {"service_id":"node_host_01","service_name":"web-prod-01","service_type":"Host","vendor_id":"vendor_acme","ip_address":"10.0.1.10","port":22,"protocol":"SSH","service_tier":"dmz","privilege_level":2,"iam_role":"ec2_instance_profile","gat_compromise_score":0.74,"anomaly_count":21,"historical_trust_score":0.28,"risk_state":"compromised","is_internet_facing":False,"breach_stage":3,"breach_notes":"SSH lateral movement detected. 21 suspicious auth events from vendor API gateway IP."},
        
        # Stage 3: App host
        {"service_id":"node_host_02","service_name":"app-prod-02","service_type":"Host","vendor_id":"vendor_acme","ip_address":"10.0.1.11","port":8080,"protocol":"HTTP","service_tier":"application","privilege_level":2,"iam_role":"ec2_app_profile","gat_compromise_score":0.55,"anomaly_count":8,"historical_trust_score":0.52,"risk_state":"at_risk","is_internet_facing":False,"breach_stage":3,"breach_notes":"Suspicious process spawning detected. Potential pivot from web-prod-01."},
        
        # Stage 4: Container — privilege escalation
        {"service_id":"node_container_7","service_name":"svc-cluster-7","service_type":"Container","vendor_id":"vendor_acme","ip_address":"172.16.7.7","port":6443,"protocol":"K8S","service_tier":"compute","privilege_level":3,"iam_role":"k8s_service_account","gat_compromise_score":0.68,"anomaly_count":15,"historical_trust_score":0.35,"risk_state":"at_risk","is_internet_facing":False,"breach_stage":4,"breach_notes":"EXEC commands detected outside IAM boundary. Host path mount attempted (container escape indicator)."},
        
        # Stage 5: Customer PII database — primary target
        {"service_id":"node_db_customer","service_name":"customer_pii","service_type":"Database","vendor_id":"vendor_databridge","ip_address":"10.0.2.50","port":5432,"protocol":"PostgreSQL","service_tier":"data","privilege_level":4,"iam_role":"rds_db_reader_elevated","gat_compromise_score":0.91,"anomaly_count":53,"historical_trust_score":0.09,"risk_state":"compromised","is_internet_facing":False,"breach_stage":5,"breach_notes":"47,000 SELECT queries against users table in 3h. 280x above baseline. PII exfiltration confirmed."},
        
        # Stage 5: Prod database — secondary target
        {"service_id":"node_db_prod01","service_name":"prod-db-01","service_type":"Database","vendor_id":"vendor_databridge","ip_address":"10.0.2.51","port":5432,"protocol":"PostgreSQL","service_tier":"data","privilege_level":4,"iam_role":"rds_superuser","gat_compromise_score":0.82,"anomaly_count":34,"historical_trust_score":0.18,"risk_state":"compromised","is_internet_facing":False,"breach_stage":5,"breach_notes":"Session token from VendorX API gateway authenticating against prod-db-01 — scope violation."},
        
        # User account — privilege chain
        {"service_id":"node_user_svc7","service_name":"svc_account_7","service_type":"User","vendor_id":"vendor_vendorx","ip_address":"10.0.1.45","port":0,"protocol":"IAM","service_tier":"identity","privilege_level":4,"iam_role":"svc_account_elevated_all","gat_compromise_score":0.77,"anomaly_count":28,"historical_trust_score":0.23,"risk_state":"compromised","is_internet_facing":False,"breach_stage":4,"breach_notes":"Service account with overly-broad IAM permissions used as pivot credential."},
        
        # DB reader role
        {"service_id":"node_role_dbreader","service_name":"db_reader","service_type":"Role","vendor_id":"vendor_databridge","ip_address":"N/A","port":0,"protocol":"IAM","service_tier":"identity","privilege_level":3,"iam_role":"rds_reader_role","gat_compromise_score":0.61,"anomaly_count":12,"historical_trust_score":0.40,"risk_state":"at_risk","is_internet_facing":False,"breach_stage":5,"breach_notes":"Role assumed by svc_account_7 to access customer_pii table."},
        
        # PayStream API
        {"service_id":"node_api_paystream","service_name":"PayStream API","service_type":"Service","vendor_id":"vendor_paystream","ip_address":"198.51.100.55","port":443,"protocol":"HTTPS","service_tier":"external","privilege_level":2,"iam_role":"paystream_api_invoker","gat_compromise_score":0.42,"anomaly_count":7,"historical_trust_score":0.61,"risk_state":"at_risk","is_internet_facing":True,"breach_stage":2,"breach_notes":"Anomalous API volume — 75x baseline. Rate limiting bypass via token rotation."},
        
        # Payment proxy host
        {"service_id":"node_host_04","service_name":"pay-proxy-01","service_type":"Host","vendor_id":"vendor_paystream","ip_address":"10.0.1.22","port":443,"protocol":"HTTPS","service_tier":"dmz","privilege_level":1,"iam_role":"ec2_basic_profile","gat_compromise_score":0.28,"anomaly_count":3,"historical_trust_score":0.75,"risk_state":"safe","is_internet_facing":False,"breach_stage":0,"breach_notes":"No active compromise. Monitoring in place."},
    ]
    
    fieldnames = list(services[0].keys())
    with open(OUTPUT_DIR / "services.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(services)
    
    print(f"* services.csv: {len(services)} records")
    return services


# ─── 3. CONNECTIONS CSV ───────────────────────────────────────────────────────

def generate_connections():
    connections = [
        # Breach path: API Gateway → Host (CALLS — lateral movement)
        {"connection_id":"conn_001","source_id":"node_api_gw","target_id":"node_host_01","relationship":"CALLS","weight":0.89,"anomaly_flagged":True,"attack_stage":3,"timestamp":ts(125.3,30),"bytes_transferred":284520,"protocol":"HTTPS","dest_port":443,"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":"Compromised API gateway initiates lateral call to web-prod-01 using stolen session token."},
        
        # Host → Container (DEPLOYS — privilege escalation entry)
        {"connection_id":"conn_002","source_id":"node_host_01","target_id":"node_container_7","relationship":"DEPLOYS","weight":0.74,"anomaly_flagged":True,"attack_stage":4,"timestamp":ts(157.8,45),"bytes_transferred":12048,"protocol":"K8S_API","dest_port":6443,"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":"web-prod-01 deploys unauthorized workload to svc-cluster-7 using overprivileged k8s service account."},
        
        # Container → User (AUTHENTICATES — credential theft)
        {"connection_id":"conn_003","source_id":"node_container_7","target_id":"node_user_svc7","relationship":"AUTHENTICATES","weight":0.68,"anomaly_flagged":True,"attack_stage":4,"timestamp":ts(179.2,60),"bytes_transferred":4096,"protocol":"OAuth2","dest_port":443,"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":"Container assumes svc_account_7 IAM identity via OIDC token exchange with elevated scope."},
        
        # User → Customer DB (ACCESSES — PII exfiltration)
        {"connection_id":"conn_004","source_id":"node_user_svc7","target_id":"node_db_customer","relationship":"ACCESSES","weight":0.91,"anomaly_flagged":True,"attack_stage":5,"timestamp":ts(195.0,30),"bytes_transferred":1073741824,"protocol":"PostgreSQL","dest_port":5432,"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":"svc_account_7 executes 47,000 SELECT queries against customer_pii.users table. 1GB data staged."},
        
        # User → Prod DB (ACCESSES — secondary target)
        {"connection_id":"conn_005","source_id":"node_user_svc7","target_id":"node_db_prod01","relationship":"ACCESSES","weight":0.82,"anomaly_flagged":True,"attack_stage":5,"timestamp":ts(203.5,45),"bytes_transferred":524288000,"protocol":"PostgreSQL","dest_port":5432,"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":"Session token scope violation — VendorX API gateway token authenticates against prod-db-01."},
        
        # App host → Container (CONNECTS — normal lateral)
        {"connection_id":"conn_006","source_id":"node_host_02","target_id":"node_container_7","relationship":"CONNECTS","weight":0.55,"anomaly_flagged":False,"attack_stage":0,"timestamp":ts(90.0,120),"bytes_transferred":8192,"protocol":"gRPC","dest_port":8080,"session_id":str(uuid.uuid4()),"is_breach_path":False,"description":"Normal application connectivity between app-prod-02 and compute cluster."},
        
        # DB Reader Role → Customer DB (ACCESSES)
        {"connection_id":"conn_007","source_id":"node_role_dbreader","target_id":"node_db_customer","relationship":"ACCESSES","weight":0.61,"anomaly_flagged":True,"attack_stage":5,"timestamp":ts(198.3,20),"bytes_transferred":209715200,"protocol":"PostgreSQL","dest_port":5432,"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":"db_reader role used via svc_account_7 for elevated READ access across customer tables."},
        
        # API Gateway → App Host (CALLS — normal traffic)
        {"connection_id":"conn_008","source_id":"node_api_gw","target_id":"node_host_02","relationship":"CALLS","weight":0.45,"anomaly_flagged":False,"attack_stage":0,"timestamp":ts(60.0,180),"bytes_transferred":1048576,"protocol":"HTTPS","dest_port":8080,"session_id":str(uuid.uuid4()),"is_breach_path":False,"description":"Normal API gateway routing to application layer."},
        
        # PayStream API → Pay Proxy (CALLS)
        {"connection_id":"conn_009","source_id":"node_api_paystream","target_id":"node_host_04","relationship":"CALLS","weight":0.42,"anomaly_flagged":False,"attack_stage":2,"timestamp":ts(78.5,60),"bytes_transferred":2097152,"protocol":"HTTPS","dest_port":443,"session_id":str(uuid.uuid4()),"is_breach_path":False,"description":"PayStream API routing — elevated volume but no confirmed breach."},
        
        # Pay Proxy → Customer DB (CONNECTS — unauthorized)
        {"connection_id":"conn_010","source_id":"node_host_04","target_id":"node_db_customer","relationship":"CONNECTS","weight":0.28,"anomaly_flagged":False,"attack_stage":0,"timestamp":ts(85.2,120),"bytes_transferred":131072,"protocol":"PostgreSQL","dest_port":5432,"session_id":str(uuid.uuid4()),"is_breach_path":False,"description":"Payment proxy → database read queries. Normal operational traffic."},
        
        # Additional telemetry records for richer dataset
        *[
            {"connection_id":f"conn_{i+11:03d}","source_id":random.choice(["node_api_gw","node_host_01","node_container_7","node_user_svc7"]),"target_id":random.choice(["node_db_customer","node_db_prod01","node_host_02"]),"relationship":random.choice(["CALLS","CONNECTS","ACCESSES"]),"weight":round(random.uniform(0.2,0.95),3),"anomaly_flagged":random.random()>0.4,"attack_stage":random.choice([3,4,5]),"timestamp":ts(random.uniform(100,240),90),"bytes_transferred":random.randint(4096,2147483648),"protocol":random.choice(["PostgreSQL","HTTPS","SSH","gRPC"]),"dest_port":random.choice([443,5432,22,8080]),"session_id":str(uuid.uuid4()),"is_breach_path":True,"description":f"Telemetry record {i+11}: Automated log from SIEM correlation engine."}
            for i in range(40)
        ],
    ]
    
    fieldnames = list(connections[0].keys())
    with open(OUTPUT_DIR / "connections.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(connections)
    
    print(f"* connections.csv: {len(connections)} records")
    return connections


# ─── 4. THREATS CSV ───────────────────────────────────────────────────────────

def generate_threats():
    threats = [
        # Stage 1: Initial credential compromise
        {"threat_id":"threat_001","title":"VendorX External Credential Compromise","severity":"critical","attack_stage":1,"affected_vendor_id":"vendor_vendorx","affected_node_ids":"node_api_gw","ioc_type":"CREDENTIAL","ioc_value":"vendorx_svc@api.vendorx.com","ioc_confidence":0.96,"source_feed":"Crowdstrike Falcon Intel","mitre_technique_id":"T1078.001","blast_radius_score":0.89,"financial_impact_usd":4200000,"detected_at":ts(118.4,20),"contained_at":"","status":"active","carag_hunt_id":"","description":"VendorX service account credentials exfiltrated via phishing. Evidence of credential stuffing against 4 geographically dispersed IP blocks."},
        
        # Stage 2: API gateway exploitation
        {"threat_id":"threat_002","title":"API Gateway Session Token Reuse — Lateral Movement Init","severity":"critical","attack_stage":2,"affected_vendor_id":"vendor_vendorx","affected_node_ids":"node_api_gw,node_host_01","ioc_type":"SESSION_TOKEN","ioc_value":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.REDACTED","ioc_confidence":0.99,"source_feed":"OAuth2 Token Introspection","mitre_technique_id":"T1550.001","blast_radius_score":0.92,"financial_impact_usd":6500000,"detected_at":ts(123.7,15),"contained_at":"","status":"active","carag_hunt_id":"carag_001","description":"Session token issued to VendorX API gateway reused across 4 IP addresses. Token scope violation detected authenticating against internal database clusters."},
        
        # Stage 3: Lateral movement
        {"threat_id":"threat_003","title":"Host Lateral Movement — web-prod-01 SSH Anomalies","severity":"high","attack_stage":3,"affected_vendor_id":"vendor_vendorx","affected_node_ids":"node_host_01,node_host_02","ioc_type":"IP","ioc_value":"203.0.113.45","ioc_confidence":0.91,"source_feed":"SIEM Correlation","mitre_technique_id":"T1021.004","blast_radius_score":0.74,"financial_impact_usd":850000,"detected_at":ts(128.9,30),"contained_at":"","status":"active","carag_hunt_id":"carag_001","description":"21 suspicious SSH authentication events originating from VendorX API gateway IP block against web-prod-01. Credential relay pattern confirmed."},
        
        # Stage 4: Privilege escalation
        {"threat_id":"threat_004","title":"Container Privilege Escalation — svc-cluster-7","severity":"critical","attack_stage":4,"affected_vendor_id":"vendor_acme","affected_node_ids":"node_container_7,node_user_svc7","ioc_type":"PROCESS","ioc_value":"nsenter --target 1 --mount --uts --ipc --net --pid","ioc_confidence":0.97,"source_feed":"Falco Runtime Security","mitre_technique_id":"T1611","blast_radius_score":0.68,"financial_impact_usd":1800000,"detected_at":ts(159.3,20),"contained_at":"","status":"active","carag_hunt_id":"carag_002","description":"Unauthorized EXEC executed inside svc-cluster-7. Host path mount attempted — container escape confirmed. IAM boundary violation by svc_account_7."},
        
        # Stage 5: Database breach
        {"threat_id":"threat_005","title":"Unauthorized PII Database Access — Mass Exfiltration","severity":"critical","attack_stage":5,"affected_vendor_id":"vendor_vendorx","affected_node_ids":"node_db_customer,node_db_prod01,node_user_svc7","ioc_type":"QUERY_PATTERN","ioc_value":"SELECT * FROM users LIMIT 10000 (47000x repetition)","ioc_confidence":0.99,"source_feed":"DataDog Database Monitoring","mitre_technique_id":"T1530","blast_radius_score":0.95,"financial_impact_usd":7800000,"detected_at":ts(197.5,10),"contained_at":"","status":"active","carag_hunt_id":"carag_003","description":"47,000 SELECT queries against customer_pii.users table in 3-hour window. 280x above baseline. 1GB data volume staged for egress. Potential GDPR breach requiring regulatory notification."},
        
        # Stage 6: CARAG hunt active
        {"threat_id":"threat_006","title":"CARAG Active Discovery Hunt — Database Auth Schema","severity":"high","attack_stage":6,"affected_vendor_id":"vendor_vendorx","affected_node_ids":"node_db_customer,node_db_prod01","ioc_type":"BEHAVIORAL","ioc_value":"DATABASE_AUTH_ANOMALY_PATTERN","ioc_confidence":0.87,"source_feed":"TrustGraph CARAG Engine","mitre_technique_id":"T1213","blast_radius_score":0.82,"financial_impact_usd":0,"detected_at":ts(215.0,5),"contained_at":"","status":"investigating","carag_hunt_id":"carag_003","description":"CARAG pipeline iteration 3 — SPL query reformulated to target session-token lateral movement on database authentication schemas. Confidence score: 0.87. Blast radius locked to 4 nodes."},
        
        # Stage 7: Containment applied
        {"threat_id":"threat_007","title":"VendorX API Key Revoked — Blast Radius Contained","severity":"medium","attack_stage":7,"affected_vendor_id":"vendor_vendorx","affected_node_ids":"node_api_gw","ioc_type":"CONTAINMENT","ioc_value":"API_KEY_REVOCATION_APPLIED","ioc_confidence":1.0,"source_feed":"TrustGraph Mitigator Agent","mitre_technique_id":"M1017","blast_radius_score":0.12,"financial_impact_usd":0,"detected_at":ts(248.3,5),"contained_at":ts(248.5,0),"status":"contained","carag_hunt_id":"carag_003","description":"IAM role svc_account_7 suspended. VendorX API key revoked. customer_pii and prod-db-01 placed under network isolation policy. Egress blocked from 4 compromised nodes. CARAG investigation complete — final confidence: 0.91."},
        
        # Additional synthetic threats
        *[
            {"threat_id":f"threat_{i+8:03d}","title":f"Threat Intel Alert #{i+8} — Anomalous Activity Detected","severity":random.choice(["high","medium","low"]),"attack_stage":random.choice([2,3,4,5]),"affected_vendor_id":random.choice(["vendor_vendorx","vendor_paystream","vendor_acme"]),"affected_node_ids":random.choice(["node_api_gw","node_host_01","node_container_7"]),"ioc_type":random.choice(["IP","HASH","BEHAVIORAL","SESSION_TOKEN"]),"ioc_value":f"IOC_VALUE_{uuid.uuid4().hex[:16].upper()}","ioc_confidence":round(random.uniform(0.6,0.97),3),"source_feed":random.choice(["Crowdstrike","Splunk Enterprise","DataDog","Falco","SIEM"]),"mitre_technique_id":random.choice(["T1190","T1021","T1078","T1530","T1548"]),"blast_radius_score":round(random.uniform(0.2,0.85),3),"financial_impact_usd":random.randint(50000,2000000),"detected_at":ts(random.uniform(100,240),60),"contained_at":"","status":random.choice(["active","investigating","active","active"]),"carag_hunt_id":f"carag_00{random.randint(1,3)}","description":f"Automated SIEM correlation trigger #{i+8}. Pattern matched against threat intel database."}
            for i in range(25)
        ],
    ]
    
    fieldnames = list(threats[0].keys())
    with open(OUTPUT_DIR / "threats.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(threats)
    
    print(f"* threats.csv: {len(threats)} records")
    return threats


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("TrustGraph Seed Dataset Generator")
    print("Multi-Stage Supply Chain Breach Simulation")
    print("="*60 + "\n")
    
    vendors = generate_vendors()
    services = generate_services()
    connections = generate_connections()
    threats = generate_threats()
    
    # Generate summary manifest
    manifest = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "attack_narrative": "7-stage supply chain breach via VendorX credential compromise",
        "breach_start": BREACH_START.isoformat() + "Z",
        "breach_end": (BREACH_START + timedelta(hours=4, minutes=8)).isoformat() + "Z",
        "total_financial_exposure_usd": 21150000,
        "records": {
            "vendors": len(vendors),
            "services": len(services),
            "connections": len(connections),
            "threats": len(threats),
        },
        "attack_stages": {
            "stage_1": "VendorX credentials compromised via phishing (06:00 UTC)",
            "stage_2": "Suspicious API gateway calls — session token abuse (08:00 UTC)",
            "stage_3": "SSH lateral movement to web-prod-01 (08:47 UTC)",
            "stage_4": "Container escape and privilege escalation (09:37 UTC)",
            "stage_5": "Unauthorized PII database exfiltration — 1GB (10:15 UTC)",
            "stage_6": "CARAG hunt loops executing — 3 iterations (10:55 UTC)",
            "stage_7": "Isolation applied — blast radius contained (10:08 UTC)",
        },
        "blast_radius_nodes": ["node_api_gw","node_host_01","node_container_7","node_user_svc7","node_db_customer","node_db_prod01"],
    }
    
    with open(OUTPUT_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\n* manifest.json written")
    print(f"\n{'='*60}")
    print(f"Dataset generation complete.")
    print(f"Output directory: {OUTPUT_DIR.absolute()}")
    print(f"Total records: {sum(manifest['records'].values())}")
    print(f"Financial exposure modeled: ${manifest['total_financial_exposure_usd']:,}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
