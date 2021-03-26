#!/usr/bin/env python3
# Copyright (c) 2018-2021 MobileCoin Inc.

import argparse
import json
import os
import shutil
import signal # To catch timeouts using signal.alarm
import subprocess
import sys
import time
from urllib.request import urlopen


from local_fog import *

# If a balance check process doesn't respond in 60 seconds, SIGALRM is sent and the test is aborted
RESPOND_SECONDS = 60
# If balance check process doesn't converge to an expected final answer in 60 seconds, fail
DEADLINE_SECONDS = 60
# Number of seconds to retry before for ingest publishes report
FOG_REPORT_RETRY_SECONDS = 30

# Global variable tracking which balance_check instance we are waiting on during SIGALRM period
sigalrm_watched_prog = None
# Handler used with SIGALRM
def handler(signum, frame):
    if signum == signal.SIGALRM:
        # If watched_prog is not None, it is expected to be an instance of class BalanceCheckProgram
        if sigalrm_watched_prog is not None:
            raise Exception(f"Program `{sigalrm_watched_prog.balance_check_path}` instance \"{sigalrm_watched_prog.name}\" did not respond in {RESPOND_SECONDS} seconds while checking balance for account {sigalrm_watched_prog.key_num}")
        else:
            raise Exception(f"SIGALRM occurred at an unexpected time")

# A context-manager guard class that sets the alarm and watches an instance of BalanceCheckProgram for timeouts, while we do a blocking read from it
# It unsets the alarm and unsets the watched program variable, when we exit the scope
class AlarmGuard:
    # The AlarmGuard watches an instance of class BalanceCheckProgram
    def __init__(self, watched):
        assert isinstance(watched, BalanceCheckProgram)
        self.watched = watched

    # When we enter the scope, set the sigalrm_watched_prog variable and arm the alarm
    def __enter__(self):
        global sigalrm_watched_prog
        assert sigalrm_watched_prog is None
        sigalrm_watched_prog = self.watched
        signal.alarm(RESPOND_SECONDS)

    # When we enter the scope, disarm the alarm and unset sigalrm_watched_prog
    def __exit__(self, tp, value, tb):
        global sigalrm_watched_prog
        signal.alarm(0)
        assert sigalrm_watched_prog is not None
        sigalrm_watched_prog = None

# Log a command and then call subprocess.run
def log_and_run_shell(cmd):
    print(cmd)
    subprocess.run(cmd, shell=True, check=True)

# A class that represents a handle to a new ledger_db and watcher_db which can be populated by the test
#
# This mocks out the inputs to fog that normally come from consensus
class TestLedger:
    def __init__(self, name, ledger_db_path, watcher_db_path, keys_dir, release, initial_seed=0):
        self.name = name
        self.ledger_db_path = ledger_db_path
        self.watcher_db_path = watcher_db_path
        self.keys_dir = keys_dir
        self.release = release
        self.seed = initial_seed

        if initial_seed == 0:
            os.makedirs(ledger_db_path)

            cmd = ' '.join([
                f'cd {self.ledger_db_path} && exec {FOG_PROJECT_DIR}/{target_dir(self.release)}/init_test_ledger',
                f'--keys {keys_dir}',
                f'--ledger-db {self.ledger_db_path}',
                f'--watcher-db {self.watcher_db_path}',
                f'--seed {self.seed}',
            ])
            print(cmd)
            result = subprocess.check_output(cmd, shell=True)
            # Increment seed, so that the next block will have different TxOuts even if the credits are the same.
            # A tx public key cannot be reused, and the ledger db enforces this.
            self.seed = 1

    def __repr__(self):
        return self.name

    # Add a block with new tx outs for users, and some new key images removed.
    # Users are indicated by number, corresponding to accounts in key_dir.
    #
    # Arguments:
    # * credits is a list of { account, amount } dict objects, where both values are integers
    # * key_images is a list of hex-encoded hashes, obtained from earlier run of init_test_ledger or add_test_block
    #
    # Returns:
    # * A list of key images corresponding to the created credits,
    #   corresponding to the order that those credits are presented
    def add_block(self, credits, key_images, fog_pubkey):

        cmd = ' '.join([
            f'cd {FOG_PROJECT_DIR} && exec {target_dir(self.release)}/add_test_block',
            f'--ledger-db {self.ledger_db_path}',
            f'--watcher-db {self.watcher_db_path}',
            f'--keys {self.keys_dir}',
            f'--seed {self.seed}',
            f'--fog-pubkey {fog_pubkey}',
        ])

        # add_test_block expects a JSON blob on STDIN containing credits and key images
        arg_bytes = json.dumps({
            'credits': credits,
            'key_images': key_images,
        }).encode("ascii")

        # Run the add_test_block program
        print(cmd)
        process_result = subprocess.run(cmd, input=arg_bytes, shell=True, check=True, stdout=subprocess.PIPE)

        # Interpret its response as json { "key_images": [...] }
        result_json = json.loads(process_result.stdout)

        # Increment seed, so that the next block will have different TxOuts even if the credits are the same.
        # A tx public key cannot be reused, and the ledger db enforces this.
        self.seed = self.seed + 1
        return result_json['key_images']

    def clone(self, clone_name):
        ledger_db_path = f"{self.ledger_db_path}-{clone_name}"
        watcher_db_path = f"{self.watcher_db_path}-{clone_name}"

        os.makedirs(ledger_db_path)
        os.makedirs(watcher_db_path)

        shutil.copy(
            os.path.join(self.ledger_db_path, 'data.mdb'),
            os.path.join(ledger_db_path, 'data.mdb'),
        )

        shutil.copy(
            os.path.join(self.watcher_db_path, 'data.mdb'),
            os.path.join(watcher_db_path, 'data.mdb'),
        )

        return TestLedger(clone_name, ledger_db_path, watcher_db_path, self.keys_dir, self.release, self.seed)


# Parse a line that came back from the balance_check program on STDOUT
# Expected to contain a json object with two integers `{ block_count: XXX, balance: YYY }`
def parse_balance_check_output(line):
    if not line:
        raise Exception("stdout pipe was unexpectedly closed")
    # Expect structure `{ block_count: ..., balance: ... }`
    try:
        result = json.loads(line)
    except json.decoder.JSONDecodeError as err:
        raise Exception(f"balance_check program produced bad json line: {line}, error: {err}")

    if 'balance' not in result:
        raise Exception(f"missing required field 'balance': {result}");
    if 'block_count' not in result:
        raise Exception(f"missing required field 'block_count': {result}");
    return result


class BalanceCheckProgram:
    def __init__(self, name, balance_check_path, keys_dir, ledger_url, view_url, key_num, release):
        self.name = name
        self.balance_check_path = balance_check_path
        self.keys_dir = keys_dir
        self.ledger_url = ledger_url
        self.view_url = view_url
        self.key_num = key_num
        self.release = release
        self.client_id = None

    def start(self):
        assert self.client_id is None
        print(f'Starting fresh balance check for {self.key_num}...')
        key = json.load(open(os.path.join(self.keys_dir, f'account_keys_{self.key_num}.json')))
        response = self.retrying_http_request({
            "method": "fresh-balance-check",
            "root_entropy": key['root_entropy'],
        })
        print(f'Key {self.key_num} started: {response}')
        self.client_id = response["client_id"]
        return {
            "balance": response["balance"],
            "block_count": response["block_index"] + 1,
        }

    def check(self):
        assert self.client_id is not None
        response = self.retrying_http_request({
            "method": "followup-balance-check",
            "client_id": self.client_id,
        })
        assert response["client_id"] == self.client_id
        print(f'Key {self.key_num} followup check: {response}')
        return {
            "balance": response["balance"],
            "block_count": response["block_index"] + 1,
        }

    def debug(self):
        # Debugging is not currently supported with the android balance checker.
        pass

    def assert_balance(self, acceptable_answers, expected_eventual_block_count):
        for ebc in expected_eventual_block_count:
            assert ebc in acceptable_answers

        print(f"Checking account {self.key_num} on {self.name}...")
        start_time = time.perf_counter()

        result = self.check() if self.client_id else self.start()
        while True:
            if result['block_count'] not in acceptable_answers:
                self.debug()
                raise Exception(f"{self.name} computed balance {result} for account {self.key_num}, but this block count was not expected. Acceptable answers were {acceptable_answers}")

            if acceptable_answers.get(result['block_count']) != result['balance']:
                self.debug()
                raise Exception(f"{self.name} computed balance {result} for account {self.key_num}, but this balance was not expected. Expected balance at that block_count was {acceptable_answers.get(result['block_count'])}")

            if result['block_count'] in expected_eventual_block_count:
                print(f"Checking account {self.key_num} on {self.name} done: {result}")
                break

            elapsed = time.perf_counter() - start_time
            if elapsed > DEADLINE_SECONDS:
                raise Exception(f"{self.name} did not converge to expected answer within {elapsed} seconds")

            result = self.check()

    def stop(self):
        if self.client_id:
            self.http_request({
                "method": "stop",
                "client_id": self.client_id,
            })
            print(f'Client {self.client_id} stopped')
            self.client_id = None

    def http_request(self, post_data):
        with urlopen("http://127.0.0.1:8080/", json.dumps(post_data).encode()) as response:
            response_content = response.read()
            try:
                return json.loads(response_content)
            except Exception as exc:
                raise Exception('Error: ' + response_content.decode())

    def retrying_http_request(self, post_data):
        i = 0
        while True:
            try:
                return self.http_request(post_data)
            except:
                if i == 30:
                    raise
            print(i)
            time.sleep(1)
            i += 1


class XXXBalanceCheckProgram:
    """An object for starting and controlling the execution of an external balance check program."""
    def __init__(self, name, balance_check_path, keys_dir, ledger_url, view_url, key_num, release):
        self.name = name
        self.balance_check_path = balance_check_path
        self.keys_dir = keys_dir
        self.ledger_url = ledger_url
        self.view_url = view_url
        self.key_num = key_num
        self.release = release
        self.popen = None

    # Run the program, and return a balance check result (json object => python dict)
    def start(self):
        assert self.popen is None
        # Note: {self.key_dir}/{self.key_num}.json must match mc-util-keyfile::keygen
        cmd = [
            self.balance_check_path,
            "--keyfile",
            f"{self.keys_dir}/account_keys_{self.key_num}.json",
            "--view-uri",
            f"{self.view_url}",
            "--ledger-uri",
            f"{self.ledger_url}",
        ]
        with AlarmGuard(self):
            print(cmd)
            self.popen = subprocess.Popen(cmd, bufsize=0, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            line = self.popen.stdout.readline()
        return parse_balance_check_output(line)

    # With the program still running, print ' ' to prompt another balance check result,
    # then return the parsed result.
    def check(self):
        assert self.popen is not None
        self.popen.stdin.write(b' ')
        with AlarmGuard(self):
            line = self.popen.stdout.readline()
        return parse_balance_check_output(line)

    # With the program still running, print 'd' to prompt the program to dump debug output to STDERR,
    # then pause for it to be finished, signaled by a newline on STDOUT.
    # This is used when a wrong balance was returned, to aid debugging.
    def debug(self):
        assert self.popen is not None
        print('requesting debug dump')
        self.popen.stdin.write(b'd')
        with AlarmGuard(self):
            # wait for program to be done printing on STDERR
            # this will block until a new line on STDOUT or until STDOUT is closed
            _ = self.popen.stdout.readline()

    # Stop the program
    def stop(self):
        assert self.popen is not None
        self.popen.terminate()
        self.popen = None

    # Check that the wallet is able to compute expected balance and reach an expected
    # block count.
    #
    # Arguments:
    # * acceptable_answers: a dict mapping block_counts to balance values which would be considered correct
    # * expected_eventual_block_count: The block counts which we expect to eventually see in order to be satisfied
    #                                  otherwise, we continue testing.
    #                                  This is a list because in some cases a client could reasonably stop at one place or another.
    def assert_balance(self, acceptable_answers, expected_eventual_block_count):
        for ebc in expected_eventual_block_count:
            assert ebc in acceptable_answers

        print(f"Checking account {self.key_num} on {self.name}...")
        start_time = time.perf_counter()

        result = self.check() if self.popen else self.start()
        while True:
            if result['block_count'] not in acceptable_answers:
                self.debug()
                raise Exception(f"{self.name} computed balance {result} for account {self.key_num}, but this block count was not expected. Acceptable answers were {acceptable_answers}")

            if acceptable_answers.get(result['block_count']) != result['balance']:
                self.debug()
                raise Exception(f"{self.name} computed balance {result} for account {self.key_num}, but this balance was not expected. Expected balance at that block_count was {acceptable_answers.get(result['block_count'])}")

            if result['block_count'] in expected_eventual_block_count:
                print(f"Checking account {self.key_num} on {self.name} done: {result}")
                break

            elapsed = time.perf_counter() - start_time
            if elapsed > DEADLINE_SECONDS:
                raise Exception(f"{self.name} did not converge to expected answer within {elapsed} seconds")

            result = self.check()


class MultiBalanceChecker:
    """The MultiBalanceChecker keeps track of an ever-growing set of BalanceCheckProgram
    instances.

    At each step of the conformance tests we want to verify:
    1. That a freshly-started client/wallet (balance checker) is able to get correct
       balances for the accounts it is tracking.
    2. That all previously-started balance checkers update correctly and are able to
       get correct balances for the accounts they are tracking.
    """

    # The number of wallets we are playing with at each step.
    NUM_WALLETS = 5

    def __init__(self, balance_check_path, keys_dir, fog_ledger, fog_view, release, skip_followup_balance_checks):
        self.balance_check_path = balance_check_path
        self.keys_dir = keys_dir
        self.fog_ledger = fog_ledger
        self.fog_view = fog_view
        self.release = release
        self.skip_followup_balance_checks = skip_followup_balance_checks

        self.steps = []

    def __enter__(self):
        return self

    def __exit__(self):
        self.stop()

    # Perform balance checks using both fresh and pre-existing wallets.
    #
    # Arguments:
    # * step_name: a name to give this balance check instance e.g. "from-block-20", to help diagnostics
    # * acceptable_answers_per_wallet: A list of tuples, having a tuple per wallet (so a total of NUM_WALLETS
    #   tuples) that contain information on the acceptable balances and eventual block count for each account.
    #   Each tuple contains two elements:
    #   1) A dict mapping block_counts to balance values which would be considered correct
    #   2) The block counts which we expect to eventually see in order to be satisfied otherwise, we continue testing.
    #      This is a list because in some cases a client could reasonably stop at one place or another.
    def balance_check(self, step_name, acceptable_answers_per_wallet):
        assert len(acceptable_answers_per_wallet) == self.NUM_WALLETS

        print(f'{step_name}: Performing fresh balance checks')
        new_wallets = [
            self._fresh_balance_check(step_name, wallet_num, acceptable_balances, expected_eventual_block_count)
            for wallet_num, (acceptable_balances, expected_eventual_block_count) in enumerate(acceptable_answers_per_wallet)
        ]

        if self.steps and not self.skip_followup_balance_checks:
            print(f'{step_name}: Performing followup balance checks')
            for wallets in self.steps:
                for wallet, (acceptable_balances, expected_eventual_block_count) in zip(wallets, acceptable_answers_per_wallet):
                    print(f'{step_name}: Followup balane check on {wallet.name} {wallet.key_num}...')
                    self._follow_up_balance_check(wallet, acceptable_balances, expected_eventual_block_count)

        self.steps.append(new_wallets)

    def stop(self):
        for wallets in self.steps:
            for balance_checker in wallets:
                balance_checker.stop()

        self.steps = []

    # Make a fresh balance_check program, and check that it computes an expected balance
    #
    # Arguments:
    # * name: a name to give this balance check instance e.g. "from-block-20", to help diagnostics
    # * key_num: The number of the account keys to use, within the sample keys directory
    # * acceptable_answers: a dict mapping block_counts to balance values which would be considered correct
    # * expected_eventual_block_count: The block counts which we expect to eventually see in order to be satisfied
    #                                  otherwise, we continue testing.
    #                                  This is a list because in some cases a client could reasonably stop at one place or another.
    #
    # Returns:
    # * The running balance check program, so that we can query this same wallet later for balances after more updates
    #
    # Invariant:
    # * If this function returns without throwing, then we eventually computed a balance at one of the expected_eventual_block_count,
    #   without ever returning an answer that wasn't in the acceptable_answers list.
    def _fresh_balance_check(self, name, key_num, acceptable_answers, expected_eventual_block_count):
        for ebc in expected_eventual_block_count:
            assert ebc in acceptable_answers

        print(f"Fresh-checking account {key_num} on {name}...")
        prog = BalanceCheckProgram(
            name = name,
            balance_check_path = self.balance_check_path,
            keys_dir = self.keys_dir,
            ledger_url = f'insecure-fog-ledger://localhost:{self.fog_ledger.client_port}/',
            view_url = f'insecure-fog-view://localhost:{self.fog_view.client_port}/',
            key_num = key_num,
            release = self.release
        )

        prog.assert_balance(acceptable_answers, expected_eventual_block_count)
        return prog

    # Takes an existing balance_check program (wallet), and check that it computes an expected balance
    #
    # Arguments:
    # * acceptable_answers: a dict mapping block_counts to balance values which would be considered correct
    # * expected_eventual_block_count: The block counts which we expect to eventually see in order to be satisfied
    #                                  otherwise, we continue testing.
    #                                  This is a list because in some cases a client could reasonably stop at one place or another.
    #
    # Returns:
    # * The running balance check program. This is the same as the prog argument
    #
    # Invariant:
    # * If this function returns without throwing, then we eventually computed a balance at one of the expected_eventual_block_count,
    #   without ever returning an answer that wasn't in the acceptable_answers list.
    def _follow_up_balance_check(self, prog, acceptable_answers, expected_eventual_block_count):
        prog.assert_balance(acceptable_answers, expected_eventual_block_count)


class FogConformanceTest:
    # Build the fog and mobilecoin repos for needed code, in release mode if selected
    def build(args):
        print("Building for fog_conformance_test")
        FLAGS = "--release" if args.release else ""

        enclave_pem = os.path.join(PROJECT_DIR, 'Enclave_private.pem')
        if not os.path.exists(enclave_pem):
            log_and_run_shell(f'openssl genrsa -out {enclave_pem} -3 3072')

        log_and_run_shell(f"cd {PROJECT_DIR} && exec cargo build {FLAGS} -p mc-util-keyfile -p mc-admin-http-gateway -p mc-crypto-x509-test-vectors")
        log_and_run_shell(f"cd {FOG_PROJECT_DIR} && CONSENSUS_ENCLAVE_PRIVKEY={enclave_pem} INGEST_ENCLAVE_PRIVKEY={enclave_pem} LEDGER_ENCLAVE_PRIVKEY={enclave_pem} VIEW_ENCLAVE_PRIVKEY={enclave_pem} exec cargo build {FLAGS}")

    def __init__(self, work_dir, args):
        self.release = args.release
        # Directory for fog to store its databases
        self.work_dir = work_dir
        # Balance check
        self.balance_check_path = os.path.abspath(args.balance_check)
        assert os.path.exists(self.balance_check_path)

        self.fog_ingest = None
        self.fog_ingest2 = None
        self.fog_view = None
        self.fog_ledger = None
        self.fog_report = None
        self.multi_balance_checker = None

    # These allow us to use `with ... as ...` python syntax,
    # and guarantees that servers are stopped if an exception occurs
    def __enter__(self):
        return self

    def __exit__(self, tp, value, tb):
        self.stop()

    # Helper for making ledgers in the fog work dir, with directory fog_work_dir/name
    def make_ledger(self, name):
        ledger_dir = os.path.join(self.work_dir, name)
        ledger_db_dir = os.path.join(ledger_dir, 'ledger_db')
        watcher_db_dir = os.path.join(ledger_dir, 'watcher_db')
        test_ledger = TestLedger(name, ledger_db_dir, watcher_db_dir, keys_dir = self.keys_dir, release = self.release)
        return test_ledger

    # Create the databases and servers in the workdir and run the actual test
    def run(self, skip_followup_balance_checks):
        #######################################################################
        # Set up the fog network
        #######################################################################

        # Report server url
        report_server_url = f'insecure-fog://localhost:{BASE_REPORT_CLIENT_PORT}'

        # Get chain and key
        root = subprocess.check_output(f"mobilecoin/{target_dir(self.release)}/mc-crypto-x509-test-vectors --type=chain --test-name=ok_rsa_head",
                                   encoding='utf8', shell=True).strip()
        chain = subprocess.check_output(f"mobilecoin/{target_dir(self.release)}/mc-crypto-x509-test-vectors --type=chain --test-name=ok_rsa_chain_25519_leaf",
                                   encoding='utf8', shell=True).strip()
        key = subprocess.check_output(f"mobilecoin/{target_dir(self.release)}/mc-crypto-x509-test-vectors --type=key --test-name=ok_rsa_chain_25519_leaf",
                                 encoding='utf8', shell=True).strip()
        print(f"chain path = {chain}, key path = {key}")

        # Create account keys
        print("Creating account keys...")
        log_and_run_shell(f"cd {self.work_dir} && {PROJECT_DIR}/{target_dir(self.release)}/sample-keys --num 5 --fog-report-url {report_server_url} --fog-authority-root {root}")
        self.keys_dir = os.path.join(self.work_dir, 'keys')

        # Creating ledgers
        print("Creating ledgers...")
        ledger1 = self.make_ledger('ledger1')
        ledger2 = self.make_ledger('ledger2')

        # Create fog SQL db
        cmd = ' && '.join([
            f'dropdb --if-exists {FOG_SQL_DATABASE_NAME}',
            f'createdb {FOG_SQL_DATABASE_NAME}',
            f'DATABASE_URL=postgres://localhost/{FOG_SQL_DATABASE_NAME} {target_dir(self.release)}/fog-sql-recovery-db-migrations',
        ])
        print(f'Creating postgres database: {cmd}')
        subprocess.check_output(cmd, shell=True)

        # Start fog services
        print("Starting fog services...")
        self.fog_ingest = FogIngest(
            name = 'ingest1',
            work_dir = self.work_dir,
            ledger_db_path = ledger1.ledger_db_path,
            client_port = BASE_INGEST_CLIENT_PORT,
            peer_port = BASE_INGEST_PEER_PORT,
            admin_port = BASE_INGEST_ADMIN_PORT,
            admin_http_gateway_port = BASE_INGEST_ADMIN_HTTP_GATEWAY_PORT,
            watcher_db_path = ledger1.watcher_db_path,
            release = self.release,
        )
        self.fog_ingest.start()

        self.fog_view = FogView(
            name = 'view1',
            client_port = BASE_VIEW_CLIENT_PORT,
            admin_port = BASE_VIEW_ADMIN_PORT,
            admin_http_gateway_port = BASE_VIEW_ADMIN_HTTP_GATEWAY_PORT,
            release = self.release,
        )
        self.fog_view.start()

        self.fog_ledger = FogLedger(
            name = 'ledger_server1',
            ledger_db_path = ledger2.ledger_db_path,
            client_port = BASE_LEDGER_CLIENT_PORT,
            admin_port = BASE_LEDGER_ADMIN_PORT,
            admin_http_gateway_port = BASE_LEDGER_ADMIN_HTTP_GATEWAY_PORT,
            watcher_db_path = ledger2.watcher_db_path,
            release = self.release,
        )
        self.fog_ledger.start()

        self.fog_report = FogReport(
            name = 'report1',
            client_port = BASE_REPORT_CLIENT_PORT,
            admin_port = BASE_REPORT_ADMIN_PORT,
            admin_http_gateway_port = BASE_REPORT_ADMIN_HTTP_GATEWAY_PORT,
            release = self.release,
            chain = chain,
            key = key,
        )
        self.fog_report.start()

        print("Giving ingest some time for RPC to wake up...")
        time.sleep(10 if self.release else 30)

        # Reduce the ingest pubkey expiry window to 1. This makes it easier for us to test retirement
        # by reducing the amount of blocks we need to generate after requesting the server to retire.
        status = self.fog_ingest.set_pubkey_expiry_window(1)
        assert status["mode"] == "Idle" and status["pubkey_expiry_window"] == 1, status

        # Tell the ingest server to activate
        status = self.fog_ingest.activate()
        assert status["mode"] == "Active" and status["pubkey_expiry_window"] == 1, status

        # Report a missed block range from 0 to 1. This is needed after FOG-337 and should not be needed after FOG-393
        cmd = ' '.join([
            f'exec {FOG_PROJECT_DIR}/{target_dir(self.release)}/fog_ingest_client',
            f'--uri insecure-fog-ingest://localhost:{BASE_INGEST_CLIENT_PORT}',
            f'report-missed-block-range',
            f'--start 0',
            f'--end 1',
        ])
        print(cmd)
        result = subprocess.check_output(cmd, shell=True)

        #######################################################################
        # Begin a series of tests testing incremental balance changes with the
        # fog setup created above.
        #######################################################################

        # Get fog pubkey
        print("Getting fog pubkey...")
        keyfile = os.path.join(self.keys_dir, "account_keys_0.pub")
        fog_pubkey = subprocess.check_output(f"cd {FOG_PROJECT_DIR} && exec {target_dir(self.release)}/fog-report-cli --public-address {keyfile} --retry-seconds={FOG_REPORT_RETRY_SECONDS}", shell = True).decode("utf-8")
        assert len(fog_pubkey) == 64
        print("Fog pubkey = ", fog_pubkey)

        # Create the multi balance checker
        self.multi_balance_checker = MultiBalanceChecker(
            self.balance_check_path,
            self.keys_dir,
            self.fog_ledger,
            self.fog_view,
            self.release,
            skip_followup_balance_checks,
        )

        # Check all accounts
        print("Beginning balance checks...")
        self.multi_balance_checker.balance_check("from1", [
            [{0: 0, 1: 0}, [1]],
            [{0: 0, 1: 0}, [1]],
            [{0: 0, 1: 0}, [1]],
            [{0: 0, 1: 0}, [1]],
            [{0: 0, 1: 0}, [1]],
        ])

        # Add block 1 (everywhere)
        credits1 = [
            {'account': 0, 'amount': 15}, {'account': 0, 'amount': 4},
            {'account': 1, 'amount': 9},
            {'account': 3, 'amount': 17},
            {'account': 4, 'amount': 27},
        ]
        key_images1 = ['0' * 64] # fake key image (32 bytes hex), can't add block with no key images
        block1_key_images = ledger1.add_block(credits1, key_images1, fog_pubkey)
        ledger2.add_block(credits1, key_images1, fog_pubkey)
        print("Key images for new transactions in Block 1: ", block1_key_images)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from2", [
            [{1: 0, 2: 19}, [2]],
            [{1: 0, 2: 9}, [2]],
            [{1: 0, 2: 0}, [2]],
            [{1: 0, 2: 17}, [2]],
            [{1: 0, 2: 27}, [2]],
        ])

        # Add block 2 (everywhere)
        # Adds 19 to 3, 2 to 4
        # Spends 15 from 0, 9 from 1, 27 from 4
        credits2 = [
            {'account': 3, 'amount': 19},
            {'account': 4, 'amount': 2},
        ]
        key_images2 = [block1_key_images[x] for x in [0, 2, 4]]
        print("Key images spent in Block 2: ", key_images2)
        block2_key_images = ledger1.add_block(credits2, key_images2, fog_pubkey)
        ledger2.add_block(credits2, key_images2, fog_pubkey)
        print("Key images for new transactions in Block 2: ", block2_key_images)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from3", [
            [{2: 19, 3: 4}, [3]],
            [{2: 9, 3: 0}, [3]],
            [{2: 0, 3: 0}, [3]],
            [{2: 17, 3: 36}, [3]],
            [{2: 27, 3: 2}, [3]],
        ])

        # Add block 3 to ingest only
        # Adds 3 to 3, 1 to everyone else
        # Spends all credits introduced in block 2, so 19 from 3, 2 from 4
        credits3 = [
            {'account': 0, 'amount': 1},
            {'account': 1, 'amount': 1},
            {'account': 2, 'amount': 1},
            {'account': 3, 'amount': 3},
            {'account': 4, 'amount': 1},
        ]
        key_images3 = block2_key_images # Spend all credits introduced in block 2
        print("Key images spent in Block 3: ", key_images3)
        block3_key_images = ledger1.add_block(credits3, key_images3, fog_pubkey)
        print("Key images for new transactions in Block 3: ", block3_key_images)
        time.sleep(1)

        # Check all accounts
        # Note: At this point, both 3 and 4 are acceptable block_count values, for accouns that had 0 balance before this block.
        # This is because if you had no outstanding TxOuts after block 3, then even if the key image server is behind, you don't
        # need that compute your balance at block 4, because none of the new TxOuts in block 4 can also be spent in block 4.
        # But the client doesn't need to think that way -- the fog-sample-paykit just happens to.
        # It's also reasonable to say that if the key image server is stuck on block 5, then we won't try to compute a balance past 5.
        self.multi_balance_checker.balance_check("from3a", [
            [{3: 4}, [3]],
            [{3: 0, 4: 1}, [3, 4]],
            [{3: 0, 4: 1}, [3, 4]],
            [{3: 36}, [3]],
            [{3: 2}, [3]],
        ])

        # Add block 3 to ledger
        ledger2.add_block(credits3, key_images3, fog_pubkey)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from4", [
            [{3: 4, 4: 5}, [4]],
            [{3: 0, 4: 1}, [4]],
            [{3: 0, 4: 1}, [4]],
            [{3: 36, 4: 20}, [4]],
            [{3: 2, 4: 1}, [4]],
        ])

        # Add block 4 to ledger only
        # Adds 10 to account 0 and 6 to account 1, in two outputs
        # Wipes out all outstanding key images
        credits4 = [
            {'account': 0, 'amount': 7}, {'account': 0, 'amount': 3},
            {'account': 1, 'amount': 2}, {'account': 1, 'amount': 4},
        ]
        key_images4 = block3_key_images + [block1_key_images[x] for x in [1, 3]]
        print("Key images spent in Block 4: ", key_images4)
        block4_key_images = ledger2.add_block(credits4, key_images4, fog_pubkey)
        print("Key images for new transactions in Block 4: ", block4_key_images)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from4a", [
            [{4: 5}, [4]],
            [{4: 1}, [4]],
            [{4: 1}, [4]],
            [{4: 20}, [4]],
            [{4: 1}, [4]],
        ])

        # Add block 4 to ingest
        ledger1.add_block(credits4, key_images4, fog_pubkey)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from5", [
            [{4: 5, 5: 10}, [5]],
            [{4: 1, 5: 6}, [5]],
            [{4: 1, 5: 0}, [5]],
            [{4: 20, 5: 0}, [5]],
            [{4: 1, 5: 0}, [5]],
        ])

        # Add block 5 to ingest only
        # Give 9 to everyone
        # Take 7 from 0 and 4 from 1
        credits5 = [
            {'account': 0, 'amount': 9},
            {'account': 1, 'amount': 9},
            {'account': 2, 'amount': 9},
            {'account': 3, 'amount': 9},
            {'account': 4, 'amount': 9},
        ]
        key_images5 = [block4_key_images[x] for x in [0, 3]]
        print("Key images spent in Block 5: ", key_images5)
        block5_key_images = ledger1.add_block(credits5, key_images5, fog_pubkey)
        print("Key images for new transactions in Block 5: ", block5_key_images)
        time.sleep(1)

        # Check all accounts
        # Note: At this point, both 5 and 6 are acceptable block_count values, for accounts that had 0 balance before this block.
        # The reason is, the fog-sample-paykit reasons that, if ingest is at block 6 and gives me a TxOut,
        # I know that it cannot be spent in block 6, even if key image service is still at block 5.
        # So I can return a correct balance for block 6, IF my balance is otherwise 0.
        self.multi_balance_checker.balance_check("from5a", [
            [{5: 10}, [5]],
            [{5: 6}, [5]],
            [{5: 0, 6: 9}, [5, 6]],
            [{5: 0, 6: 9}, [5, 6]],
            [{5: 0, 6: 9}, [5, 6]],
        ])

        # Add block 6 to ingest only
        # Give 1 to everyone
        # Take 2 from 1 and 9 from 3
        credits6 = [
            {'account': 0, 'amount': 1},
            {'account': 1, 'amount': 1},
            {'account': 2, 'amount': 1},
            {'account': 3, 'amount': 1},
            {'account': 4, 'amount': 1},
        ]
        key_images6 = [block4_key_images[2], block5_key_images[3]]
        print("Key images spent in Block 6: ", key_images6)
        block6_key_images = ledger1.add_block(credits6, key_images6, fog_pubkey)
        print("Key images for new transactions in Block 6: ", block6_key_images)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from6a", [
            [{5: 10}, [5]],
            [{5: 6}, [5]],
            [{5: 0, 6: 9}, [5, 6]],
            [{5: 0, 6: 9}, [5, 6]],
            [{5: 0, 6: 9}, [5, 6]],
        ])

        # Add block 5 to ledger
        ledger2.add_block(credits5, key_images5, fog_pubkey)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from6b", [
            [{5: 10, 6: 12}, [6]],
            [{5: 6, 6: 11}, [6]],
            [{5: 0, 6: 9}, [6]],
            [{5: 0, 6: 9}, [6]],
            [{5: 0, 6: 9}, [6]],
        ])

        # Add block 7 to ingest only
        # Add 4 to 4,
        # Take 9 from 2
        credits7 = [{'account': 4, 'amount': 4}]
        key_images7 = [block5_key_images[2]]
        print("Key images spent in Block 7: ", key_images7)
        block7_key_images = ledger1.add_block(credits7, key_images7, fog_pubkey)
        print("Key images for new transactions in Block 7: ", block7_key_images)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from7a", [
            [{6: 12}, [6]],
            [{6: 11}, [6]],
            [{6: 9}, [6]],
            [{6: 9}, [6]],
            [{6: 9}, [6]],
        ])

        # Add block 6 to ledger
        ledger2.add_block(credits6, key_images6, fog_pubkey)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from7b", [
            [{6: 12, 7: 13}, [7]],
            [{6: 11, 7: 10}, [7]],
            [{6: 9, 7: 10}, [7]],
            [{6: 9, 7: 1}, [7]],
            [{6: 9, 7: 10}, [7]],
        ])

        # Add block 7 to ledger
        ledger2.add_block(credits7, key_images7, fog_pubkey)
        time.sleep(1)

        # Check all accounts
        self.multi_balance_checker.balance_check("from7c", [
            [{7: 13, 8: 13}, [8]],
            [{7: 10, 8: 10}, [8]],
            [{7: 10, 8: 1}, [8]],
            [{7: 1, 8: 1}, [8]],
            [{7: 10, 8: 14}, [8]],
        ])

        #######################################################################
        # Test what happens if we introduce a second ingest server and retire
        # the original one. The desired behavior is that the work is picked by
        # the second server and balance checks continue as expected.
        #######################################################################

        # Start a second ingest server
        self.fog_ingest2 = FogIngest(
            name = 'ingest2',
            work_dir = self.work_dir,
            ledger_db_path = ledger1.ledger_db_path,
            client_port = BASE_INGEST_CLIENT_PORT + 1,
            peer_port = BASE_INGEST_PEER_PORT + 1,
            admin_port = BASE_INGEST_ADMIN_PORT + 1,
            admin_http_gateway_port = BASE_INGEST_ADMIN_HTTP_GATEWAY_PORT + 1,
            watcher_db_path = ledger1.watcher_db_path,
            release = self.release,
        )
        self.fog_ingest2.start()
        print("Giving ingest2 some time for RPC to wake up...")
        time.sleep(10 if self.release else 30)

        # Tell the second ingest server to activate.
        status = self.fog_ingest2.activate()
        assert status["mode"] == "Active"

        # Tell the first ingest server to retire.
        status = self.fog_ingest.retire()
        assert status["mode"] == "Active"

        # Store fog pubkey of the 2nd ingest.
        fog_pubkey = self.fog_ingest2.get_status()["ingress_pubkey"]
        assert len(fog_pubkey) == 64

        # Add block 8 to ingest and ledger
        # Give 2 to everyone
        # Take 4 from 4
        credits8 = [
            {'account': 0, 'amount': 2},
            {'account': 1, 'amount': 2},
            {'account': 2, 'amount': 2},
            {'account': 3, 'amount': 2},
            {'account': 4, 'amount': 2},
        ]
        key_images8 = [block7_key_images[0]]
        print("Key images spent in Block 8: ", key_images8)
        block8_key_images = ledger1.add_block(credits8, key_images8, fog_pubkey)
        ledger2.add_block(credits8, key_images8, fog_pubkey)
        print("Key images for new transactions in Block 8: ", block8_key_images)
        time.sleep(1)

        # Check balances. These should come from the new RNG of the second ingest server
        self.multi_balance_checker.balance_check("from8", [
            [{8: 13, 9: 15}, [9]],
            [{8: 10, 9: 12}, [9]],
            [{8: 1, 9: 3}, [9]],
            [{8: 1, 9: 3}, [9]],
            [{8: 14, 9: 12}, [9]],
        ])

        # Both ingests should currently be active
        status = self.fog_ingest.get_status()
        assert status["mode"] == "Active", status

        status = self.fog_ingest2.get_status()
        assert status["mode"] == "Active", status

        # Add block 9 to ingest and ledger. This should cause ingest1 to become Idle.
        # Give 1 to everyone
        # Take 2 from wallet0
        credits9 = [
            {'account': 0, 'amount': 1},
            {'account': 1, 'amount': 1},
            {'account': 2, 'amount': 1},
            {'account': 3, 'amount': 1},
            {'account': 4, 'amount': 1},
        ]
        key_images9 = [block8_key_images[0]]
        print("Key images spent in Block 9: ", key_images9)
        block9_key_images = ledger1.add_block(credits9, key_images9, fog_pubkey)
        ledger2.add_block(credits9, key_images9, fog_pubkey)
        print("Key images for new transactions in Block 9: ", block9_key_images)
        time.sleep(1)

        # Check balances. These should come from the new RNG of the second ingest server
        self.multi_balance_checker.balance_check("from9", [
            [{9: 15, 10: 14}, [10]],
            [{9: 12, 10: 13}, [10]],
            [{9: 3, 10: 4}, [10]],
            [{9: 3, 10: 4}, [10]],
            [{9: 12, 10: 13}, [10]],
        ])

        # Ingest1 should now be retired, ingest2 should still be active
        status = self.fog_ingest.get_status()
        assert status["mode"] == "Idle", status

        status = self.fog_ingest2.get_status()
        assert status["mode"] == "Active", status

        # TODO - stop the first ingest server. Currently not doable since it remains
        # commissioned in the database (there is no way to set decommissioned=false)

        #######################################################################
        # Test what happens when we restart the view server
        #######################################################################

        # Restarting the view server should not impact things.
        print("Restarting fog view server")
        self.fog_view.stop()
        self.fog_view.start()
        time.sleep(10 if self.release else 30)

        # We will encounter 0: 0 while we wait for the view server to come up.
        # Android will encounter 1: 0 because the SDK returns block index=0 when in fact block
        # count=0, so that would result in block count being 1...
        # In theory we could get anything between 0 and 10, but since the view server loads
        # TxOut data in batches, the observed behavior is going from block 0 to the highest
        # available one (10).
        self.multi_balance_checker.balance_check("from10a", [
            [{0: 0, 1: 0, 10: 14}, [10]],
            [{0: 0, 1: 0, 10: 13}, [10]],
            [{0: 0, 1: 0, 10: 4}, [10]],
            [{0: 0, 1: 0, 10: 4}, [10]],
            [{0: 0, 1: 0, 10: 13}, [10]],
        ])

        # Add block 10 to ingest and ledger. This should get reported by the restarted view server.
        # Give 3 to everyone
        # Take 1 from wallet1
        credits10 = [
            {'account': 0, 'amount': 3},
            {'account': 1, 'amount': 3},
            {'account': 2, 'amount': 3},
            {'account': 3, 'amount': 3},
            {'account': 4, 'amount': 3},
        ]
        key_images10 = [block9_key_images[1]]
        print("Key images spent in Block 10: ", key_images10)
        block10_key_images = ledger1.add_block(credits10, key_images10, fog_pubkey)
        ledger2.add_block(credits10, key_images10, fog_pubkey)
        print("Key images for new transactions in Block 10: ", block10_key_images)
        time.sleep(1)

        self.multi_balance_checker.balance_check("from10b", [
            [{10: 14, 11: 17}, [11]],
            [{10: 13, 11: 15}, [11]],
            [{10: 4, 11: 7}, [11]],
            [{10: 4, 11: 7}, [11]],
            [{10: 13, 11: 16}, [11]],
        ])

        #######################################################################
        # Done
        #######################################################################

        print("All checks succeeded!")

    def stop(self):
        if self.multi_balance_checker:
            self.multi_balance_checker.stop()

        if self.fog_ledger:
            self.fog_ledger.stop()

        if self.fog_report:
            self.fog_report.stop()

        if self.fog_view:
            self.fog_view.stop()

        if self.fog_ingest:
            self.fog_ingest.stop()

        if self.fog_ingest2:
            self.fog_ingest2.stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Balance check conformance tester')
    parser.add_argument('--skip-build', help='Skip building binaries', action='store_true')
    parser.add_argument('--release', help='Use release mode binaries', action='store_true')
    parser.add_argument('--skip-followup-balance-checks', help='Skip followup balance checks', action='store_true')
    parser.add_argument('balance_check', help='Balance check program to test conformance of')
    args = parser.parse_args()

    if not args.skip_build:
        FogConformanceTest.build(args)

    work_dir = '/tmp/fog-conformance-tests'
    shutil.rmtree(work_dir, ignore_errors=True)
    os.makedirs(work_dir)

    # Install signal handler for SIGALRM
    signal.signal(signal.SIGALRM, handler)
    with FogConformanceTest(work_dir, args) as test:
        test.run(args.skip_followup_balance_checks)
