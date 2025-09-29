# Gunicorn configuration file
import multiprocessing

max_requests = 1000
max_requests_jitter = 100
workers = 2
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5
preload_app = True

# Server socket
bind = "0.0.0.0:10000"
backlog = 2048

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Process naming
proc_name = "burundian_market"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Worker processes
pythonpath = None

# SSL (if needed)
# keyfile = None
# certfile = None

# Server hooks
def pre_fork(server, worker):
    pass

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_exec(server):
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def worker_abort(worker):
    worker.log.info("worker received SIGABRT signal")