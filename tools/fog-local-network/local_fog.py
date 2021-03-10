# Copyright (c) 2018-2020 MobileCoin Inc.

import os
import subprocess

BASE_INGEST_CLIENT_PORT = 4200
BASE_INGEST_PEER_PORT = 4300
BASE_INGEST_ADMIN_PORT = 4400
BASE_INGEST_ADMIN_HTTP_GATEWAY_PORT = 4500

BASE_VIEW_CLIENT_PORT = 5200
BASE_VIEW_ADMIN_PORT = 5400
BASE_VIEW_ADMIN_HTTP_GATEWAY_PORT = 5500

BASE_REPORT_CLIENT_PORT = 6200
BASE_REPORT_ADMIN_PORT = 6400
BASE_REPORT_ADMIN_HTTP_GATEWAY_PORT = 6500

BASE_LEDGER_CLIENT_PORT = 7200
BASE_LEDGER_ADMIN_PORT = 7400
BASE_LEDGER_ADMIN_HTTP_GATEWAY_PORT = 7500

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'public'))
INTERNAL_PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

IAS_API_KEY = os.getenv('IAS_API_KEY', default='0'*64) # 32 bytes
IAS_SPID = os.getenv('IAS_SPID', default='0'*32) # 16 bytes

FOG_SQL_DATABASE_NAME = 'fog_local'

def target_dir(release):
    if release:
        return 'target/release'
    else:
        return 'target/debug'

class FogIngest:
    # Arguments:
    # name: A name for this instance for logging purposes
    # work_dir: A temporary directory
    # ledger_db_path: A path to the ledger_db to use as input
    # client_port: The port to which the ingest client can connect to on grpc
    # peer_port: The port to which peers can make attested connections
    # admin_port: The administrative port
    # admin_http_gateway_port: The admin http port
    # watcher_db_path: A path to the watcher_db to use as input
    # release: True if we should use the release mode binaries
    def __init__(self, name, work_dir, ledger_db_path, client_port, peer_port, admin_port, admin_http_gateway_port, watcher_db_path, release):
        assert os.path.exists(ledger_db_path)

        self.name = name
        self.work_dir = work_dir
        self.ledger_db_path = ledger_db_path
        self.watcher_db_path = watcher_db_path

        self.client_port = client_port
        self.client_listen_url = f"insecure-fog-ingest://localhost:{self.client_port}/"

        self.peer_port = peer_port
        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release

        self.state_file_path = os.path.join(work_dir, f'ingest-{name}-state-file')
        self.ingest_server_process = None
        self.distribution_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        self.stop()

        cmd = ' '.join([
            f'cd {INTERNAL_PROJECT_DIR} && MC_LOG=trace DATABASE_URL=postgres://localhost/{FOG_SQL_DATABASE_NAME} exec {target_dir(self.release)}/fog_ingest_server',
            f'--ledger-db={self.ledger_db_path}',
            f'--client-listen-uri={self.client_listen_url}',
            f'--peer-listen-uri=insecure-igp://localhost:{self.peer_port}/',
            f'--ias-api-key={IAS_API_KEY}',
            f'--ias-spid={IAS_SPID}',
            f'--local-node-id localhost:{self.client_port}',
            f'--state-file {self.state_file_path}',
            f'--admin-listen-uri=insecure-mca://127.0.0.1:{self.admin_port}/',
            f'--watcher-db {self.watcher_db_path}',
        ])

        print(f'Starting fog ingest {self.name}')
        print(cmd)
        print()

        self.ingest_server_process = subprocess.Popen(cmd, shell=True)

        cmd = ' '.join([
            f'cd {PROJECT_DIR} && export ROCKET_CLI_COLORS=0 && exec {target_dir(self.release)}/mc-admin-http-gateway',
            f'--listen-host localhost',
            f'--listen-port {self.admin_http_gateway_port}',
            f'--admin-uri insecure-mca://127.0.0.1:{self.admin_port}/',
        ])
        print(f'Starting admin http gateway for fog ingest: {cmd}')
        self.admin_http_gateway_process = subprocess.Popen(cmd, shell=True)

    def stop(self):
        if self.ingest_server_process and self.ingest_server_process.poll() is None:
            self.ingest_server_process.terminate()
            self.ingest_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None


class FogView:
    def __init__(self, name, client_port, admin_port, admin_http_gateway_port, release):
        self.name = name

        self.client_port = client_port
        self.client_listen_url = f'insecure-fog-view://localhost:{self.client_port}/'

        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release

        self.view_server_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        self.stop()

        cmd = ' '.join([
            f'cd {INTERNAL_PROJECT_DIR} && DATABASE_URL=postgres://localhost/{FOG_SQL_DATABASE_NAME} exec {target_dir(self.release)}/fog_view_server',
            f'--client-listen-uri={self.client_listen_url}',
            f'--client-responder-id=localhost:{self.client_port}',
            f'--ias-api-key={IAS_API_KEY}',
            f'--ias-spid={IAS_SPID}',
            f'--admin-listen-uri=insecure-mca://127.0.0.1:{self.admin_port}/',
        ])

        print(f'Starting fog view {self.name}')
        print(cmd)
        print()

        self.view_server_process = subprocess.Popen(cmd, shell=True)

        cmd = ' '.join([
            f'cd {PROJECT_DIR} && export ROCKET_CLI_COLORS=0 && exec {target_dir(self.release)}/mc-admin-http-gateway',
            f'--listen-host localhost',
            f'--listen-port {self.admin_http_gateway_port}',
            f'--admin-uri insecure-mca://127.0.0.1:{self.admin_port}/',
        ])
        print(f'Starting admin http gateway for fog view: {cmd}')
        self.admin_http_gateway_process = subprocess.Popen(cmd, shell=True)

    def stop(self):
        if self.view_server_process and self.view_server_process.poll() is None:
            self.view_server_process.terminate()
            self.view_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None


class FogReport:
    def __init__(self, name, client_port, admin_port, admin_http_gateway_port, release, chain, key):
        self.name = name
        self.client_port = client_port
        self.client_listen_url = f"insecure-fog://localhost:{self.client_port}/"

        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port

        self.release = release

        self.chain = chain
        self.key = key

        self.report_server_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        self.stop()

        cmd = ' '.join([
            f'cd {INTERNAL_PROJECT_DIR} && DATABASE_URL=postgres://localhost/{FOG_SQL_DATABASE_NAME} exec {target_dir(self.release)}/report_server',
            f'--client-listen-uri={self.client_listen_url}',
            f'--admin-listen-uri=insecure-mca://127.0.0.1:{self.admin_port}/',
            f'--signing-chain={self.chain}',
            f'--signing-key={self.key}'
        ])

        print(f'Starting fog report {self.name}')
        print(cmd)
        print()

        self.report_server_process = subprocess.Popen(cmd, shell=True)

        cmd = ' '.join([
            f'cd {PROJECT_DIR} && export ROCKET_CLI_COLORS=0 && exec {target_dir(self.release)}/mc-admin-http-gateway',
            f'--listen-host localhost',
            f'--listen-port {self.admin_http_gateway_port}',
            f'--admin-uri insecure-mca://127.0.0.1:{self.admin_port}/',
        ])
        print(f'Starting admin http gateway for fog report : {cmd}')
        self.admin_http_gateway_process = subprocess.Popen(cmd, shell=True)

    def stop(self):
        if self.report_server_process and self.report_server_process.poll() is None:
            self.report_server_process.terminate()
            self.report_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None


class FogLedger:
    def __init__(self, name, ledger_db_path, client_port, admin_port, admin_http_gateway_port, watcher_db_path, release):
        self.name = name
        self.ledger_db_path = ledger_db_path
        self.watcher_db_path = watcher_db_path

        self.client_port = client_port
        self.client_listen_url = f'insecure-fog-ledger://localhost:{self.client_port}/'

        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port
        self.release = release

        self.ledger_server_process = None
        self.admin_http_gateway_process = None

    def __repr__(self):
        return self.name

    def start(self):
        assert os.path.exists(os.path.join(self.ledger_db_path, 'data.mdb')), self.ledger_db_path
        assert os.path.exists(os.path.join(self.watcher_db_path, 'data.mdb')), self.watcher_db_path
        self.stop()

        cmd = ' '.join([
            f'cd {INTERNAL_PROJECT_DIR} && exec {target_dir(self.release)}/ledger_server',
            f'--ledger-db={self.ledger_db_path}',
            f'--client-listen-uri={self.client_listen_url}',
            f'--client-responder-id=localhost:{self.client_port}',
            f'--ias-api-key={IAS_API_KEY}',
            f'--ias-spid={IAS_SPID}',
            f'--admin-listen-uri=insecure-mca://127.0.0.1:{self.admin_port}/',
            f'--watcher-db {self.watcher_db_path}',
        ])

        print(f'Starting fog ledger {self.name}')
        print(cmd)
        print()

        self.ledger_server_process = subprocess.Popen(cmd, shell=True)

        cmd = ' '.join([
            f'cd {PROJECT_DIR} && export ROCKET_CLI_COLORS=0 && exec {target_dir(self.release)}/mc-admin-http-gateway',
            f'--listen-host localhost',
            f'--listen-port {self.admin_http_gateway_port}',
            f'--admin-uri insecure-mca://127.0.0.1:{self.admin_port}/',
        ])
        print(f'Starting admin http gateway for fog ledger: {cmd}')
        self.admin_http_gateway_process = subprocess.Popen(cmd, shell=True)

    def stop(self):
        if self.ledger_server_process and self.ledger_server_process.poll() is None:
            self.ledger_server_process.terminate()
            self.ledger_server_process = None

        if self.admin_http_gateway_process and self.admin_http_gateway_process.poll() is None:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None
