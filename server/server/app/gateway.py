import ipaddress


def nginx_config(trusted_ips):
    if not trusted_ips:
        raise ValueError('NPM address required')
    addresses=[str(ipaddress.ip_address(ip)) for ip in trusted_ips]
    allow='\n'.join(f'allow {ip};' for ip in addresses)
    return '''pid /tmp/ha-tunnel-nginx.pid;
error_log /dev/stderr crit;
events { worker_connections 1024; }
http {
  access_log off;
  map $http_upgrade $connection_upgrade { default upgrade; '' close; }
  server {
    listen 8080;
    server_tokens off;
    client_max_body_size 128m;
    '''+allow+'''
    deny all;
    if ($http_x_forwarded_proto != "https") { return 403; }
    if ($http_x_real_ip = "") { return 403; }
    location / {
      proxy_pass http://127.0.0.1:18081;
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $http_x_real_ip;
      proxy_set_header X-Real-IP $http_x_real_ip;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port 443;
      proxy_set_header Forwarded "";
      proxy_set_header X-Remote-User-Id "";
      proxy_set_header X-Remote-User-Name "";
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_read_timeout 3600s;
      proxy_send_timeout 3600s;
    }
  }
}
'''
