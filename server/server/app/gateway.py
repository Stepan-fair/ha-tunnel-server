import asyncio
import os
import signal
import ipaddress


def nginx_config(trusted_ips):
    if not trusted_ips:
        raise ValueError('NPM address required')
    addresses=[str(ipaddress.ip_address(ip)) for ip in trusted_ips]
    allow='\n'.join(f'allow {ip};' for ip in addresses)
    return '''pid /tmp/ha-tunnel-nginx.pid;
error_log stderr warn;
events { worker_connections 1024; }
http {
  client_body_temp_path /tmp/ha-tunnel-nginx-body;
  proxy_temp_path /tmp/ha-tunnel-nginx-proxy;
  fastcgi_temp_path /tmp/ha-tunnel-nginx-fastcgi;
  uwsgi_temp_path /tmp/ha-tunnel-nginx-uwsgi;
  scgi_temp_path /tmp/ha-tunnel-nginx-scgi;
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
    add_header Strict-Transport-Security "max-age=31536000" always;
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

def kill_gateway(process):
    # nginx workers can outlive a killed/exited master and retain its listeners.
    # Only the session created for this exact captured process is targeted.
    try:
        if os.name=='posix': os.killpg(process.pid,signal.SIGKILL)
        elif process.returncode is None: process.kill()
    except ProcessLookupError: pass


class Gateway:
    """Bounded nginx lifecycle with synchronous kill of revoked generations."""
    def __init__(self,path,diagnostics=None):
        from pathlib import Path
        self.path=Path(path)
        self.diagnostics=diagnostics
        self.process=None
        self.retired=[]
        self.outputs=[]
        self.spawn=None

    @property
    def running(self): return self.process is not None and self.process.returncode is None

    @property
    def returncode(self): return None if self.running else 1

    def revoke(self):
        process=self.process
        self.process=None
        if process is not None:
            kill_gateway(process)
            self.retired.append(process)
            if self.diagnostics: self.diagnostics.component('gateway','stopped')

    async def close(self):
        self.revoke()
        while self.retired:
            process=self.retired[0]
            await asyncio.wait_for(process.wait(),5)
            self.retired.pop(0)
        for task in self.outputs: task.cancel()
        await asyncio.gather(*self.outputs,return_exceptions=True)
        self.outputs.clear()

    async def start(self,snapshot):
        from shared.files import atomic_write
        from shared.environment import child_environment
        from shared.process_output import ProcessOutput
        await self.close()
        if not snapshot.fresh(): raise ValueError('NPM proof expired')
        atomic_write(self.path,nginx_config(snapshot.addresses).encode())
        sink=asyncio.subprocess.PIPE if self.diagnostics else asyncio.subprocess.DEVNULL
        self.spawn=asyncio.create_task(asyncio.create_subprocess_exec(
            'nginx','-c',str(self.path),'-g','daemon off;',stdout=sink,stderr=sink,env=child_environment(),start_new_session=True))
        try:
            self.process=await asyncio.wait_for(asyncio.shield(self.spawn),5)
        except BaseException:
            # Cancellation must not orphan a child that is still being created.
            try:
                self.process=await asyncio.wait_for(asyncio.shield(self.spawn),5)
            except BaseException:
                self.spawn.add_done_callback(self._reap_late)
            self.revoke()
            raise
        finally:
            self.spawn=None
        if not snapshot.fresh():
            self.revoke()
            raise ValueError('NPM proof expired')
        if self.diagnostics:
            for stream in (self.process.stdout,self.process.stderr):
                self.outputs.append(asyncio.create_task(ProcessOutput(self.diagnostics,'gateway').drain(stream)))
            self.diagnostics.component('gateway','running')

    @staticmethod
    def _reap_late(task):
        if task.cancelled(): return
        try: process=task.result()
        except Exception: return
        kill_gateway(process)
        # The subprocess transport reaps the killed child; never publish it.
