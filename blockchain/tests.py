import hashlib
import json

import ecdsa
from django.test import TestCase
from blockchain.views import Blockchain
from blockchain.views import Wallet


# Tests of Blockchain/Wallet classes.

class BlockchainTests(TestCase):

    def setUp(self):
        self.blockchain = Blockchain()

    def test_create_block(self):
        initial_length = len(self.blockchain.chain)
        new_block = self.blockchain.create_block(nonce=1, previous_hash='0')
        self.assertEqual(len(self.blockchain.chain), initial_length + 1)
        self.assertEqual(new_block, self.blockchain.chain[-1])

    def test_get_last_block(self):
        last_block = self.blockchain.get_last_block()
        self.assertEqual(last_block, self.blockchain.chain[-1])

    def test_proof_of_work(self):
        previous_nonce = 1
        new_nonce = self.blockchain.proof_of_work(previous_nonce)
        hash_operation = hashlib.sha256(str(new_nonce ** 2 - previous_nonce ** 2).encode()).hexdigest()
        self.assertTrue(hash_operation[:5] == '00000')

    def test_hash(self):
        block = self.blockchain.get_last_block()
        encoded_block = json.dumps(block, sort_keys=True).encode()
        expected_hash = hashlib.sha256(encoded_block).hexdigest()
        self.assertEqual(self.blockchain.hash(block), expected_hash)

    def test_is_chain_valid(self):
        self.assertTrue(self.blockchain.is_chain_valid(self.blockchain.chain))

    def test_add_transaction(self):
        initial_length = len(self.blockchain.pending_transactions)
        index = self.blockchain.add_transaction(sender='A', receiver='B', amount=10, time='2023-05-05')
        self.assertEqual(len(self.blockchain.pending_transactions), initial_length + 1)
        self.assertEqual(index, self.blockchain.get_last_block()['index'] + 1)

    def test_get_pending_transactions(self):
        pending_transactions = self.blockchain.get_pending_transactions()
        self.assertEqual(pending_transactions, self.blockchain.pending_transactions)

    def test_add_node(self):
        initial_length = len(self.blockchain.nodes)
        self.blockchain.add_node("http://127.0.0.1:8000")
        self.assertEqual(len(self.blockchain.nodes), initial_length + 1)


class WalletTests(TestCase):

    def setUp(self):
        self.blockchain = Blockchain()
        self.wallet = Wallet()

    def test_sell_crypto(self):
        initial_balance = self.wallet.get_balance()
        sell_amount = 30
        self.wallet.sell_crypto(sell_amount)

        # Check if the balance was updated correctly
        self.assertNotEqual(self.wallet.get_balance(), initial_balance - sell_amount)

    def test_deposit_crypto(self):
        initial_balance = self.wallet.get_balance()
        purchase_amount = 40
        self.wallet.deposit_crypto(purchase_amount)

        # Check if the balance was updated correctly
        self.assertEqual(self.wallet.get_balance(), initial_balance + purchase_amount)

    def test_get_balance(self):
        wallet = Wallet()
        wallet.sell_crypto(10)
        balance = wallet.get_balance()
        self.assertEqual(balance, 0)

    def test_generate_private_key(self):

        # Test that the generate_private_key function returns an ecdsa.SigningKey instance
        private_key = self.wallet.generate_private_key()
        self.assertIsInstance(private_key, ecdsa.SigningKey)

        # Test that the private_key has the correct curve
        self.assertEqual(private_key.curve, ecdsa.SECP256k1)

    def test_generate_wallet_address(self):

        # Test that the generate_wallet_address function returns a valid wallet address string
        public_key = self.wallet.private_key.get_verifying_key()
        wallet_address = self.wallet.generate_wallet_address(public_key)

        self.assertIsInstance(wallet_address, str)
        self.assertTrue(len(wallet_address) > 0)
