from flask import Flask, render_template, request, send_file, jsonify
from kubernetes import client, config
import os
import yaml
import tempfile
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from kubernetes.config.kube_config import KUBE_CONFIG_DEFAULT_LOCATION
import time

app = Flask(__name__)

# Load Kubernetes configuration
try:
    config.load_incluster_config()  # Try to load in-cluster config
except:
    config.load_kube_config()  # Fall back to local kubeconfig

def generate_certificate(username, role):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    # Save private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Save certificate
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    return private_key_pem, cert_pem

def create_rbac_resources(username, role):
    core_v1 = client.CoreV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    
    try:
        # Create ServiceAccount
        service_account = client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(name=username, namespace="default")
        )
        core_v1.create_namespaced_service_account(namespace="default", body=service_account)
        
        # Create RoleBinding or ClusterRoleBinding based on role
        if role == "admin":
            role_ref = client.V1RoleRef(
                kind="ClusterRole",
                name="cluster-admin",
                api_group="rbac.authorization.k8s.io"
            )
            binding = client.V1ClusterRoleBinding(
                metadata=client.V1ObjectMeta(name=f"{username}-binding"),
                role_ref=role_ref,
                subjects=[client.V1Subject(
                    kind="ServiceAccount",
                    name=username,
                    namespace="default"
                )]
            )
            rbac_v1.create_cluster_role_binding(body=binding)
        else:  # readonly
            role_ref = client.V1RoleRef(
                kind="ClusterRole",
                name="view",
                api_group="rbac.authorization.k8s.io"
            )
            binding = client.V1ClusterRoleBinding(
                metadata=client.V1ObjectMeta(name=f"{username}-binding"),
                role_ref=role_ref,
                subjects=[client.V1Subject(
                    kind="ServiceAccount",
                    name=username,
                    namespace="default"
                )]
            )
            rbac_v1.create_cluster_role_binding(body=binding)
            
        # Get the ServiceAccount token
        secret_name = f"{username}-token"
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace="default",
                annotations={
                    "kubernetes.io/service-account.name": username
                }
            ),
            type="kubernetes.io/service-account-token"
        )
        core_v1.create_namespaced_secret(namespace="default", body=secret)
        
        # Wait for the token to be generated
        time.sleep(2)  # Give the controller time to generate the token
        
        # Get the token from the secret
        secret = core_v1.read_namespaced_secret(name=secret_name, namespace="default")
        token = base64.b64decode(secret.data["token"]).decode()
        
        return token
        
    except Exception as e:
        # Clean up if there's an error
        try:
            core_v1.delete_namespaced_service_account(name=username, namespace="default")
            rbac_v1.delete_cluster_role_binding(name=f"{username}-binding")
            core_v1.delete_namespaced_secret(name=secret_name, namespace="default")
        except:
            pass
        raise e

def create_kubeconfig(username, role, cluster_name, cluster_server, ca_cert, token):
    # Create kubeconfig structure
    kubeconfig = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": cluster_name,
            "cluster": {
                "server": cluster_server,
                "certificate-authority-data": base64.b64encode(ca_cert.encode()).decode()
            }
        }],
        "users": [{
            "name": username,
            "user": {
                "token": token
            }
        }],
        "contexts": [{
            "name": f"{username}-context",
            "context": {
                "cluster": cluster_name,
                "user": username,
                "namespace": "default"
            }
        }],
        "current-context": f"{username}-context"
    }
    
    return yaml.dump(kubeconfig)

def get_ca_cert():
    # Try in-cluster path first
    ca_path = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
    if os.path.exists(ca_path):
        with open(ca_path, 'r') as f:
            return f.read()
    
    # If not in cluster, try to get from kubeconfig
    try:
        kubeconfig_path = os.environ.get('KUBECONFIG', os.path.expanduser('~/.kube/config'))
        if not os.path.exists(kubeconfig_path):
            raise FileNotFoundError(f"Kubeconfig not found at {kubeconfig_path}")
            
        with open(kubeconfig_path, 'r') as f:
            kubeconfig = yaml.safe_load(f)
            
        current_context = kubeconfig.get('current-context')
        if not current_context:
            raise ValueError("No current context found in kubeconfig")
            
        context = next((ctx for ctx in kubeconfig['contexts'] if ctx['name'] == current_context), None)
        if not context:
            raise ValueError(f"Context {current_context} not found in kubeconfig")
            
        cluster_name = context['context']['cluster']
        cluster = next((cl for cl in kubeconfig['clusters'] if cl['name'] == cluster_name), None)
        if not cluster:
            raise ValueError(f"Cluster {cluster_name} not found in kubeconfig")
            
        cluster_info = cluster['cluster']
        if 'certificate-authority-data' in cluster_info:
            return base64.b64decode(cluster_info['certificate-authority-data']).decode()
        elif 'certificate-authority' in cluster_info:
            ca_file = os.path.expanduser(cluster_info['certificate-authority'])
            if not os.path.exists(ca_file):
                raise FileNotFoundError(f"CA certificate file not found at {ca_file}")
            with open(ca_file, 'r') as caf:
                return caf.read()
        else:
            raise ValueError('No CA certificate found in kubeconfig')
            
    except Exception as e:
        raise Exception(f"Failed to get CA certificate: {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.json
    username = data.get('username')
    role = data.get('role')
    
    if not username or role not in ['admin', 'readonly']:
        return jsonify({'error': 'Invalid input'}), 400
    
    try:
        # Create RBAC resources and get token
        token = create_rbac_resources(username, role)
        
        # Get cluster information
        v1 = client.CoreV1Api()
        cluster_server = 'https://192.168.1.70:6443'
        
        # Read CA certificate
        ca_cert = get_ca_cert()
        
        # Generate kubeconfig
        kubeconfig = create_kubeconfig(
            username=username,
            role=role,
            cluster_name='default-cluster',
            cluster_server=cluster_server,
            ca_cert=ca_cert,
            token=token
        )
        
        # Save kubeconfig to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.yaml') as tmp:
            tmp.write(kubeconfig.encode())
            tmp_path = tmp.name
        
        return send_file(
            tmp_path,
            as_attachment=True,
            download_name=f'{username}-kubeconfig.yaml',
            mimetype='application/x-yaml'
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001) 