import hashlib, ecdsa
import time, json, copy, datetime

# Exception Class
# ****************************************
class ValidationExceptionError(Exception):
    pass

# Block Class
# ****************************************
class Block:
    def __init__(self, index, prev_hash, transactions):
        self.timestamp = time.time()
        self.index = index
        self.prev_hash = prev_hash
        self.transactions = copy.deepcopy(transactions)           # list with dictionary
        self.nonce = 0                                  # start point
        self.hash = self.compute_hash()
    def compute_hash(self):
        serialized = json.dumps({
            "timestamp": self.timestamp,
            "index": self.index,
            "prev_hash": self.prev_hash,
            "transactions": self.transactions,
            "nonce": self.nonce,
        }, sort_keys=True).encode()                     # serializing dictionary to use sort option
        return hashlib.sha256(serialized).hexdigest()   # human readable string

# BlockChain Class
# ****************************************
class BlockChain:
    def __init__(self, difficulty=4):
        self.difficulty = difficulty
        self.chain = []
        self.chain.append(Block(0, "0", []))        # genesis block
    def add_block(self, transactions, public_key):
        try:
            self.is_valid_chain()
            self.verify_signature(transactions, public_key)
            b = self.mine(transactions)      
            self.chain.append(b)
        except ValidationExceptionError as e:
            print(e)
            return False
        return True
    #
    # inspect existing chains
    # -----------------------------------------
    def is_valid_chain(self):
        for i in range(1, len(self.chain)):
            prev, curr = self.chain[i-1], self.chain[i]
            if prev.hash != curr.prev_hash:
                raise ValidationExceptionError("ERROR: prev hash not match")
            if curr.hash != curr.compute_hash():
                raise ValidationExceptionError("ERROR: last hash not match")
        return
    #
    # verify signature
    # -----------------------------------------
    def verify_signature(self, transactions, public_key):
        for tx in transactions:
            payload = json.dumps({
                "from": tx["from"],
                "to": tx["to"],
                "amount": tx["amount"],
                "timestamp": tx["timestamp"]
            }, sort_keys=True).encode()
            try:
                # signature sotored as hex string so needs to convert it to bytes string
                public_key.verify(bytes.fromhex(tx["signature"]), payload)
            except ecdsa.BadSignatureException as e:
                # print("Verification failed:", type(e).__name__)
                raise ValidationExceptionError("Error: INVALID SIGNATURE")
        return True

    #
    # create a new block
    # proof_of_work: make difficult to create a block
    # -----------------------------------------
    def mine(self, tx):
        hash_pattern = "0" * self.difficulty
        b = Block(len(self.chain), self.chain[-1].hash, tx)
        while not b.hash.startswith(hash_pattern):
            b.nonce += 1
            b.hash = b.compute_hash()
        return b

# Wallet
# ****************************************
class Wallet:
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
    def get_address(self):
        return hashlib.sha256(self.public_key.to_string()).hexdigest()
    def sign_transaction(self, tx):
        payload = json.dumps({
            "from": tx["from"],
            "to": tx["to"],
            "amount": tx["amount"],
            "timestamp": tx["timestamp"]
        }, sort_keys=True).encode()

        # save signature in transaction as JSON safe or creating hash of block fails
        tx["signature"] = self.private_key.sign(payload).hex()
        return tx

class Transaction:
    def __init__(self, from_addr, to_addr, amount):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.amount = amount
        self.timestamp = time.time()
    def get_transaction(self):
        return {
            "from": self.from_addr,
            "to": self.to_addr,
            "amount": self.amount,
            "timestamp": self.timestamp
        }
def demo_block_class():
    tx = [{"amount": 100}, {"amount": 200}]
    b = Block(0, "0", tx)
    print(f"block created: hash={b.hash[0:10]}, tx[0]={b.transactions[0]}")

def demo_chain_class():
    tran_1 = Transaction("Tom", "Paul", 100).get_transaction()
    tran_2 = Transaction("Paul", "Tom", 200).get_transaction()
    transactions = [tran_1, tran_2]

    w = Wallet()
    for tx in transactions:
        w.sign_transaction(tx)
    for tx in transactions:
        print(f"signed signature={tx['signature'][0:10]}")

    bc = BlockChain()
    if bc.add_block(transactions, w.public_key):
        b = bc.chain[-1]
        print(f"block added: index={b.index}, hash={b.hash[0:10]}, transaction number={len(b.transactions)}")
    else:
        return
    
    # tamper previous transaction
    bc.chain[-1].transactions[0]["amount"] = 900
    if bc.add_block(transactions, w.public_key):
        b = bc.chain[-1]
        print(f"block added: index={b.index}, hash={b.hash[0:10]}, tx={b.transactions[0]}")

def demo_proof_of_work():
    tx = [{"amount": 100}, {"amount": 200}]
    for i in range(0, 4):
        bc = BlockChain(i)
        bc.add_block(tx)
        print(f"index:{i}, hash={bc.chain[-1].hash[0:10]}, time={datetime.datetime.now()}")
def demo_tran_class():
    tran = Transaction("Tom", "Paul", 100)
    print(f"tran={tran.get_transaction()}")

def demo_wallet_class():
    w = Wallet()
    tran_1 = Transaction("Tom", "Paul", 100)
    print(f"BEFORE:{tran_1.get_transaction()}")
    signed_tran_1 = w.sign_transaction(tran_1.get_transaction())
    print(f"AFTER:{signed_tran_1['signature'][0:10]}")

    tran_2 = Transaction("Paul", "Tom", 200)
    print(f"BEFORE:{tran_2.get_transaction()}")
    signed_tran_2 = w.sign_transaction(tran_2.get_transaction())
    print(f"AFTER:{signed_tran_2['signature'][0:10]}")

    bc = BlockChain()
    try:
        # original transaction
        transactions = [signed_tran_1, signed_tran_2]
        if bc.verify_signature(transactions, w.public_key):
            print("Verified transactions successfully")

        # tampering transaction
        transactions[0]["to"] = "Jack"
        if bc.verify_signature(transactions, w.public_key):
            print("Verified transactions successfully")
    except ValidationExceptionError as e:
        print(e)

if __name__ == "__main__":
    # demo_block_class()
    demo_chain_class()
    # demo_proof_of_work()
    # demo_tran_class()
    # demo_wallet_class()

