import argparse
import json
import signal
import ssl
import subprocess
import sys
import time

import boto3
import psycopg2


SUPPORTED_ENGINES = {
    "postgres": {"default_port": 5432, "label": "Postgres"},
    "mysql": {"default_port": 3306, "label": "MySQL"},
}

# -------------------------------
# ARGUMENTS
# -------------------------------
parser = argparse.ArgumentParser(
    description="Open SSM tunnel to a Postgres or MySQL RDS instance via bastion."
)
parser.add_argument("--region", default="eu-west-2", help="AWS region (default: eu-west-2)")
parser.add_argument(
    "--engine",
    choices=SUPPORTED_ENGINES.keys(),
    default="postgres",
    help="Target database engine (default: postgres)",
)
parser.add_argument(
    "--db-name",
    help="Database name (default: postgres for Postgres, mysql for MySQL)",
)
parser.add_argument(
    "--writer",
    action="store_true",
    help="Use writer endpoint for Aurora Postgres clusters (default: reader endpoint)",
)
parser.add_argument(
    "--local-port",
    type=int,
    help="Local port for the tunnel (default: match the remote port for the selected engine)",
)
args = parser.parse_args()

REGION = args.region
ENGINE = args.engine
DB_NAME = args.db_name or ("postgres" if ENGINE == "postgres" else "mysql")
WRITER = args.writer
DB_USER = "db_iam_user"
REMOTE_PORT = SUPPORTED_ENGINES[ENGINE]["default_port"]
LOCAL_PORT_OVERRIDE = args.local_port is not None
LOCAL_PORT = args.local_port or SUPPORTED_ENGINES[ENGINE]["default_port"]


def get_bastion_instance_id():
    ec2 = boto3.client("ec2", region_name=REGION)
    response = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": ["*-ec2-bastion"]},
            {"Name": "instance-state-name", "Values": ["running"]},
        ]
    )
    for res in response.get("Reservations", []):
        for inst in res.get("Instances", []):
            return inst["InstanceId"]
    raise RuntimeError("No running bastion instance found.")


def get_target_database():
    rds = boto3.client("rds", region_name=REGION)
    if ENGINE == "postgres":
        clusters = rds.describe_db_clusters().get("DBClusters", [])
        aurora = [c for c in clusters if c.get("Engine") == "aurora-postgresql"]
        if aurora:
            if len(aurora) > 1:
                raise RuntimeError("Multiple Aurora Postgres clusters found, refine selection.")
            return {"type": "cluster", "resource": aurora[0]}

        instances = rds.describe_db_instances().get("DBInstances", [])
        postgres_instances = [
            i for i in instances if i.get("Engine", "").lower().startswith("postgres")
        ]
        if not postgres_instances:
            raise RuntimeError("No Aurora cluster or Postgres RDS instance found.")
        if len(postgres_instances) > 1:
            raise RuntimeError("Multiple Postgres RDS instances found, refine selection.")
        return {"type": "instance", "resource": postgres_instances[0]}

    instances = rds.describe_db_instances().get("DBInstances", [])
    mysql_instances = [
        i for i in instances if i.get("Engine", "").lower().startswith("mysql") and i.get("DBInstanceIdentifier").lower() == "aw-ttf-euw2-prd-rds-matomo"
    ]
    if not mysql_instances:
        raise RuntimeError("No MySQL RDS instance found.")
    if len(mysql_instances) > 1:
        raise RuntimeError("Multiple MySQL RDS instances found, refine selection.")
    return {"type": "instance", "resource": mysql_instances[0]}


def get_endpoint(target):
    resource = target["resource"]
    if target["type"] == "cluster":
        endpoint = resource.get("Endpoint") if WRITER else resource.get("ReaderEndpoint")
        if not endpoint:
            verb = "writer" if WRITER else "reader"
            raise RuntimeError(f"Selected Aurora cluster has no {verb} endpoint.")
        return endpoint
    endpoint_info = resource.get("Endpoint", {})
    if not endpoint_info.get("Address"):
        raise RuntimeError("Selected RDS instance has no endpoint address.")
    return endpoint_info["Address"]


def get_target_port(target):
    resource = target["resource"]
    if target["type"] == "cluster":
        return resource.get("Port") or REMOTE_PORT
    return resource.get("Endpoint", {}).get("Port") or REMOTE_PORT


def get_db_secret(target):
    resource = target["resource"]
    secret_arn = resource.get("MasterUserSecret", {}).get("SecretArn")
    if not secret_arn:
        raise RuntimeError("Selected database has no MasterUserSecret.")
    sm = boto3.client("secretsmanager", region_name=REGION)
    secret_val = sm.get_secret_value(SecretId=secret_arn)
    return json.loads(secret_val["SecretString"])


def start_port_forwarding(instance_id, remote_host):
    command = [
        "aws",
        "ssm",
        "start-session",
        "--target",
        instance_id,
        "--document-name",
        "AWS-StartPortForwardingSessionToRemoteHost",
        "--parameters",
        f"host={remote_host},portNumber={REMOTE_PORT},localPortNumber={LOCAL_PORT}",
        "--region",
        REGION,
    ]
    return subprocess.Popen(command)


def generate_rds_auth_token(hostname):
    rds_client = boto3.client("rds", region_name=REGION)
    return rds_client.generate_db_auth_token(
        DBHostname=hostname,
        Port=REMOTE_PORT,
        DBUsername=DB_USER,
        Region=REGION,
    )


def connect_to_database(user, password, hostname):
    if ENGINE == "postgres":
        return psycopg2.connect(
            host=hostname,  # used for IAM token & TLS cert validation
            hostaddr="127.0.0.1",  # actual TCP connection (tunnel endpoint)
            port=LOCAL_PORT,
            user=user,
            password=password,
            database=DB_NAME,
            sslmode="require",
        )

    try:
        import pymysql
    except ImportError as exc:
        raise RuntimeError(
            "PyMySQL is required for MySQL connections. Install it with `pip install pymysql`."
        ) from exc

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False  # local tunnel uses 127.0.0.1, so skip hostname validation
    ssl_ctx.verify_mode = ssl.CERT_NONE  # mirror mysql --ssl-mode=REQUIRED (TLS without hostname validation)

    return pymysql.connect(
        host="127.0.0.1",
        port=LOCAL_PORT,
        user=user,
        password=password,
        db=DB_NAME,
        ssl=ssl_ctx,
        connect_timeout=10,
    )


def cleanup(signum=None, frame=None):
    global tunnel_process
    if tunnel_process:
        print("\n[*] Closing tunnel...")
        tunnel_process.terminate()
        tunnel_process.wait()
    sys.exit(0)


def build_examples(remote_host):
    if ENGINE == "postgres":
        return f"""🔹 Using psql:
   PGPASSWORD=$(aws rds generate-db-auth-token \\
    --hostname {remote_host} \\
    --port {REMOTE_PORT} \\
    --username {DB_USER} \\
    --region {REGION}) \\
 psql "host={remote_host} hostaddr=127.0.0.1 port={LOCAL_PORT} sslmode=require dbname={DB_NAME} user={DB_USER}"

🔹 Using pgAdmin or DBeaver:
  - Host: {remote_host}
  - Host Address: 127.0.0.1
  - Port: {LOCAL_PORT}
  - Database: {DB_NAME}
  - Username: {DB_USER}
  - SSL mode: require"""

    return f"""🔹 Using the mysql client:
   TOKEN=$(aws rds generate-db-auth-token \\
    --hostname {remote_host} \\
    --port {REMOTE_PORT} \\
    --username {DB_USER} \\
    --region {REGION}) \\
 mysql --host=127.0.0.1 --port={LOCAL_PORT} --ssl-mode=REQUIRED \\
   --enable-cleartext-plugin \\
   --user={DB_USER} --password="$TOKEN" {DB_NAME}

🔹 Using MySQL Workbench or DBeaver:
  - Hostname: 127.0.0.1
  - Port: {LOCAL_PORT}
  - Default Schema: {DB_NAME}
  - Username: {DB_USER}
  - SSL: require (set the server name to {remote_host} if your client supports it)"""


def build_notes(remote_host):
    if ENGINE == "postgres":
        return [
            f"Always set 'host' = the database endpoint ({remote_host}) so IAM tokens and TLS work.",
            "Always set 'hostaddr' = 127.0.0.1 so the connection travels through the tunnel.",
        ]
    return [
        f"Generate IAM auth tokens with the real endpoint hostname ({remote_host}).",
        "TLS verification is disabled by default (similar to mysql --ssl-mode=REQUIRED). Provide a CA bundle and adjust the script if you need strict certificate checks.",
    ]


if __name__ == "__main__":
    tunnel_process = None
    try:
        INSTANCE_ID = get_bastion_instance_id()
        TARGET = get_target_database()
        REMOTE_HOST = get_endpoint(TARGET)

        REMOTE_PORT = get_target_port(TARGET)
        if not LOCAL_PORT_OVERRIDE:
            LOCAL_PORT = REMOTE_PORT

        tunnel_process = start_port_forwarding(INSTANCE_ID, REMOTE_HOST)
        time.sleep(5)

        conn = None
        if TARGET["resource"].get("IAMDatabaseAuthenticationEnabled", False):
            try:
                token = generate_rds_auth_token(REMOTE_HOST)
                conn = connect_to_database(DB_USER, token, REMOTE_HOST)
                print("[+] Connected with IAM token.")
            except Exception as e:
                print(f"[!] IAM auth failed: {e}")

        if conn is None:
            print("[*] Falling back to Secrets Manager...")
            secret = get_db_secret(TARGET)
            conn = connect_to_database(secret["username"], secret["password"], REMOTE_HOST)
            print("[+] Connected with managed secret.")

        with conn.cursor() as cur:
            cur.execute("SELECT CURRENT_TIMESTAMP;")
            print("[+] Query result:", cur.fetchone())
        conn.close()

        examples = build_examples(REMOTE_HOST)
        notes = "\n".join(f"- {note}" for note in build_notes(REMOTE_HOST))

        print(
            f"""
[+] Connected successfully and tunnel is open to {REMOTE_HOST}:{REMOTE_PORT}.

You can now connect to your {SUPPORTED_ENGINES[ENGINE]['label']} database through the tunnel using
standard client tools. When possible, use the real RDS hostname so IAM tokens and SSL certificates validate correctly.

Examples:

{examples}

  To generate a temporary password which is valid for 15 minutes, run
  aws rds generate-db-auth-token \\
    --hostname {REMOTE_HOST} \\
    --port {REMOTE_PORT} \\
    --username {DB_USER} \\
    --region {REGION}
  
Notes:
{notes}

[*] Tunnel will stay open until you press Ctrl+C.
"""
        )
        signal.signal(signal.SIGINT, cleanup)
        signal.signal(signal.SIGTERM, cleanup)
        signal.pause()

    except Exception as e:
        print("[!] Error:", str(e))
        cleanup()
