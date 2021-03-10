# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse
import os
import subprocess
import sys

INTERNAL_PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
# FIXME: Avoid modifying sys.path
sys.path.append(os.path.join(INTERNAL_PROJECT_DIR, 'public', 'tools', 'local-network'))
from local_network import *
from local_fog import *

class FogNetwork(Network):
    def build_binaries(self):
        super().build_binaries()

        enclave_pem = os.path.join(PROJECT_DIR, 'Enclave_private.pem')
        assert os.path.exists(enclave_pem), enclave_pem

        subprocess.run(
            ' '.join([
                f'cd {INTERNAL_PROJECT_DIR} &&',
                f'CONSENSUS_ENCLAVE_PRIVKEY="{enclave_pem}"',
                f'INGEST_ENCLAVE_PRIVKEY="{enclave_pem}"',
                f'LEDGER_ENCLAVE_PRIVKEY="{enclave_pem}"',
                f'VIEW_ENCLAVE_PRIVKEY="{enclave_pem}"',
                f'cargo build -p fog-ingest-server -p fog-ingest-client -p fog-view-server -p fog-report-server -p fog-ledger-server -p fog-distribution -p fog-test-client -p slam -p fog-ingest-client -p fog-sql-recovery-db -p fog-test-client {CARGO_FLAGS}',
            ]),
            shell=True,
            check=True,
        )

    def start(self):
        cmd = ' && '.join([
            f'dropdb --if-exists {FOG_SQL_DATABASE_NAME}',
            f'createdb {FOG_SQL_DATABASE_NAME}',
            f'DATABASE_URL=postgres://localhost/{FOG_SQL_DATABASE_NAME} {TARGET_DIR}/fog-sql-recovery-db-migrations',
        ])
        print(f'Creating postgres database: {cmd}')
        subprocess.check_output(cmd, shell=True)

        print("Starting network...")
        super().start()

        print("Starting fog services...")
        try:
            # TODO
            subprocess.check_output("killall -9 fog_ingest_server 2>/dev/null", shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 1:
                raise

        # Directory for fog to store its databases
        fog_work_dir = os.path.join(WORK_DIR, 'fog')
        try:
            os.makedirs(fog_work_dir)
        except:
            pass

        # Start fog services
        self.fog_ingest = FogIngest(
            'ingest1',
            fog_work_dir,
            self.nodes[0].ledger_dir,
            BASE_INGEST_CLIENT_PORT,
            BASE_INGEST_PEER_PORT,
            BASE_INGEST_ADMIN_PORT,
            BASE_INGEST_ADMIN_HTTP_GATEWAY_PORT,
            self.mobilecoind.watcher_db,
            release=True,
        )
        self.fog_ingest.start()

        self.fog_view = FogView(
            'view1',
            BASE_VIEW_CLIENT_PORT,
            BASE_VIEW_ADMIN_PORT,
            BASE_VIEW_ADMIN_HTTP_GATEWAY_PORT,
            release=True,
        )
        self.fog_view.start()

        self.fog_report = FogReport(
            'report1',
            BASE_REPORT_CLIENT_PORT,
            BASE_REPORT_ADMIN_PORT,
            BASE_REPORT_ADMIN_HTTP_GATEWAY_PORT,
            release=True,
        )
        self.fog_report.start()

        self.fog_ledger = FogLedger(
            'ledger1',
            self.nodes[0].ledger_dir,
            BASE_LEDGER_CLIENT_PORT,
            BASE_LEDGER_ADMIN_PORT,
            BASE_LEDGER_ADMIN_HTTP_GATEWAY_PORT,
            self.mobilecoind.watcher_db,
            release=True,
        )
        self.fog_ledger.start()

        # Tell the ingest server to activate, giving it a little time for RPC to wakeup
        time.sleep(5 if self.release else 15)
        cmd = ' '.join([
            f'exec {INTERNAL_PROJECT_DIR}/{target_dir(self.release)}/fog_ingest_client',
            f'--uri insecure-fog-ingest://localhost:{BASE_INGEST_CLIENT_PORT}',
            f'activate',
        ])
        print(cmd)
        result = subprocess.check_output(cmd, shell=True)

    def stop(self):
        if self.fog_ledger:
            self.fog_ledger.stop()

        if self.fog_report:
            self.fog_report.stop()

        if self.fog_view:
            self.fog_view.stop()

        if self.fog_ingest:
            self.fog_ingest.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Local network tester')
    parser.add_argument('--network-type', help='Type of network to create', required=True)
    parser.add_argument('--skip-build', help='Skip building binaries', action='store_true')
    args = parser.parse_args()

    FogNetwork().default_entry_point(args.network_type, args.skip_build)
