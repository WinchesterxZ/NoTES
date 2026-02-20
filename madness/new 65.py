File contents of '/app/dns-server/dns_server.py':

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
import sqlite3
import os
import hashlib
import secrets
from functools import wraps
from datetime import datetime
import logging
from dns_query_server import start_dns_server

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
DNS_ADMIN_USERNAME = os.getenv('DNS_ADMIN_USERNAME', 'admin')
DNS_ADMIN_PASSWORD = os.getenv('DNS_ADMIN_PASSWORD', 'admin')
SECRET_KEY = os.getenv('DNS_SECRET_KEY', secrets.token_hex(32))
DB_PATH = os.getenv('DNS_DB_PATH', '/app/dns-server/dns_server.db')
DNS_PORT = int(os.getenv('DNS_PORT', '5380'))
DNS_QUERY_PORT = int(os.getenv('DNS_QUERY_PORT', '53'))
DNS_BIND_IP = os.getenv('DNS_BIND_IP', '0.0.0.0')

app.secret_key = SECRET_KEY

# DNS Record Types
DNS_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SOA', 
    'SRV', 'CAA', 'NAPTR', 'DS', 'DNSKEY', 'SSHFP', 'TLSA'
]

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Ensure WAL mode is enabled for this connection
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def init_db():
    """Initialize database with tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Enable WAL mode for better concurrency and immediate visibility of writes
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')  # Better performance while still safe
    
    # Create DNS records table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INTEGER DEFAULT 3600,
            priority INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(domain, record_type, name)
        )
    ''')
    
    # Create admin user table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user if not exists
    password_hash = hashlib.sha256(DNS_ADMIN_PASSWORD.encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO admin_users (username, password_hash)
        VALUES (?, ?)
    ''', (DNS_ADMIN_USERNAME, password_hash))
    
    # Prefill DNS records for hopaitech.thm domain
    # Get container IPs from environment or use container names (Docker will resolve)
    import socket
    
    def get_container_ip(container_name):
        """Get container IP address by resolving container name"""
        try:
            # Try to resolve container name to IP
            ip = socket.gethostbyname(container_name)
            return ip
        except socket.gaierror:
            # If resolution fails, return None (will use container name as fallback)
            logger.warning(f"Could not resolve {container_name}, will use container name")
            return None
    
    # Get container IPs (resolve at runtime, fallback to container names)
    # Note: Container names will resolve via Docker's DNS at query time
    url_analyzer_ip = get_container_ip('url-analyzer')
    company_portfolio_ip = get_container_ip('company-portfolio')
    
    # Resolve host.docker.internal to its actual IP for containers to reach the host
    def get_host_docker_internal_ip():
        """Resolve host.docker.internal to its actual IP address"""
        try:
            ip = socket.gethostbyname('host.docker.internal')
            logger.info(f"Resolved host.docker.internal to IP: {ip}")
            return ip
        except socket.gaierror:
            logger.warning("Could not resolve host.docker.internal, will skip DNS record")
            return None
    
    host_docker_internal_ip = get_host_docker_internal_ip()
    
    # If IPs not available, use container names (Docker DNS will resolve them)
    if not url_analyzer_ip:
        url_analyzer_ip = 'url-analyzer'  # Docker will resolve this
    if not company_portfolio_ip:
        company_portfolio_ip = 'company-portfolio'  # Docker will resolve this
    
    # Prefill records for hopaitech.thm
    default_records = [
        # SOA record for hopaitech.thm
        ('hopaitech.thm', 'SOA', '@', 'ns1.hopaitech.thm. admin.hopaitech.thm. 1 3600 1800 604800 86400', 3600, 0),
        # NS record
        ('hopaitech.thm', 'NS', '@', 'ns1.hopaitech.thm', 3600, 0),
        # A records for subdomains (using resolved IPs or container names)
        ('hopaitech.thm', 'A', 'dns-manager', url_analyzer_ip, 3600, 0),
        ('hopaitech.thm', 'A', 'ticketing-system', company_portfolio_ip, 3600, 0),
        ('hopaitech.thm', 'A', 'url-analyzer', url_analyzer_ip, 3600, 0),
        ('hopaitech.thm', 'A', 'ns1', url_analyzer_ip, 3600, 0),
    ]
    
    # Add host.docker.internal as a DNS record if we could resolve it
    # Store it as domain='docker.internal' and name='host' so queries for 'host.docker.internal' will match
    # (The query parser splits 'host.docker.internal' into domain='docker.internal' and name='host')
    if host_docker_internal_ip:
        default_records.append(
            ('docker.internal', 'A', 'host', host_docker_internal_ip, 3600, 0)
        )
        logger.info(f"Added DNS A record for host.docker.internal -> {host_docker_internal_ip}")
    
    for domain, record_type, name, value, ttl, priority in default_records:
        cursor.execute('''
            INSERT OR IGNORE INTO dns_records (domain, record_type, name, value, ttl, priority, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (domain, record_type, name, value, ttl, priority))
    
    conn.commit()
    conn.close()
    logger.info("Database initialized with default records for hopaitech.thm")

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
@app.route('/dns/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        cursor = conn.cursor()
        password_hash = hash_password(password)
        
        cursor.execute('''
            SELECT * FROM admin_users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            logger.info(f"User {username} logged in")
            return redirect(url_for('dns_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('dns_login.html')

@app.route('/dns/logout')
def logout():
    """Logout"""
    session.clear()
    logger.info("User logged out")
    return redirect(url_for('login'))

@app.route('/dns')
@login_required
def dns_dashboard():
    """DNS Dashboard"""
    return render_template('dns_dashboard.html')

@app.route('/dns/api/records', methods=['GET'])
@login_required
def get_records():
    """Get all DNS records"""
    domain = request.args.get('domain', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    if domain:
        cursor.execute('''
            SELECT * FROM dns_records 
            WHERE domain = ?
            ORDER BY domain, record_type, name
        ''', (domain,))
    else:
        cursor.execute('''
            SELECT * FROM dns_records 
            ORDER BY domain, record_type, name
        ''')
    
    records = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(record) for record in records])

@app.route('/dns/api/records', methods=['POST'])
@login_required
def create_record():
    """Create a new DNS record"""
    data = request.get_json()
    
    domain = data.get('domain', '').strip()
    record_type = data.get('record_type', '').strip().upper()
    name = data.get('name', '').strip()
    value = data.get('value', '').strip()
    ttl = int(data.get('ttl', 3600))
    priority = int(data.get('priority', 0))
    
    # Validation
    if not domain or not record_type or not name or not value:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if record_type not in DNS_TYPES:
        return jsonify({'error': f'Invalid record type. Must be one of: {", ".join(DNS_TYPES)}'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO dns_records (domain, record_type, name, value, ttl, priority, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (domain, record_type, name, value, ttl, priority, datetime.now()))
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        
        logger.info(f"Created DNS record: {record_type} {name}.{domain} -> {value}")
        return jsonify({'id': record_id, 'message': 'Record created successfully'}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Record already exists'}), 400
    except Exception as e:
        conn.close()
        logger.error(f"Error creating record: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/dns/api/records/<int:record_id>', methods=['PUT'])
@login_required
def update_record(record_id):
    """Update a DNS record"""
    data = request.get_json()
    
    domain = data.get('domain', '').strip()
    record_type = data.get('record_type', '').strip().upper()
    name = data.get('name', '').strip()
    value = data.get('value', '').strip()
    ttl = int(data.get('ttl', 3600))
    priority = int(data.get('priority', 0))
    
    # Validation
    if not domain or not record_type or not name or not value:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if record_type not in DNS_TYPES:
        return jsonify({'error': f'Invalid record type. Must be one of: {", ".join(DNS_TYPES)}'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE dns_records 
            SET domain = ?, record_type = ?, name = ?, value = ?, ttl = ?, priority = ?, updated_at = ?
            WHERE id = ?
        ''', (domain, record_type, name, value, ttl, priority, datetime.now(), record_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Record not found'}), 404
        
        conn.commit()
        conn.close()
        
        logger.info(f"Updated DNS record ID {record_id}")
        return jsonify({'message': 'Record updated successfully'}), 200
    except Exception as e:
        conn.close()
        logger.error(f"Error updating record: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/dns/api/records/<int:record_id>', methods=['DELETE'])
@login_required
def delete_record(record_id):
    """Delete a DNS record"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM dns_records WHERE id = ?', (record_id,))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Record not found'}), 404
    
    conn.commit()
    conn.close()
    
    logger.info(f"Deleted DNS record ID {record_id}")
    return jsonify({'message': 'Record deleted successfully'}), 200

@app.route('/dns/api/domains', methods=['GET'])
@login_required
def get_domains():
    """Get all unique domains"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT DISTINCT domain FROM dns_records ORDER BY domain')
    domains = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(domains)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Start DNS query server (handles actual DNS protocol queries on port 53)
    dns_query_server, dns_thread = start_dns_server(DB_PATH, DNS_BIND_IP, DNS_QUERY_PORT)
    logger.info(f"DNS Query Server started on {DNS_BIND_IP}:{DNS_QUERY_PORT}")
    
    # Start Flask web interface (on port 5380)
    logger.info(f"DNS Web Interface starting on port {DNS_PORT}")
    app.run(host='0.0.0.0', port=DNS_PORT, debug=False)
