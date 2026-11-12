"""State provider for pgs.check: a node with evm_snapshot/evm_revert (Hardhat, anvil).

Any object with the same attribute and methods can stand in for Web3Chain:
  wallet                         the guarded wallet's address
  balance(token, who) -> int     token address, or None for the native coin
  allowance(token, owner, spender) -> int
  owner(contract) -> address     owner() of a contract the wallet must keep owning
  has_code(addr) -> bool
  simulate(calls)                context manager: runs the batch from the wallet on a throwaway copy of
                                 the state and yields its receipt (.gasUsed, .logs), or None if it
                                 reverted; reads inside the block see the post-state
"""
from contextlib import contextmanager
from web3 import Web3

_ABI = [
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "a", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "allowance", "stateMutability": "view",
     "inputs": [{"name": "o", "type": "address"}, {"name": "s", "type": "address"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "owner", "stateMutability": "view", "inputs": [],
     "outputs": [{"name": "", "type": "address"}]},
    {"type": "function", "name": "execute", "stateMutability": "nonpayable", "outputs": [],
     "inputs": [{"name": "calls", "type": "tuple[]", "components": [
         {"name": "target", "type": "address"}, {"name": "value", "type": "uint256"},
         {"name": "data", "type": "bytes"}]}]},
]


class Web3Chain:
    """`wallet` exposes AgentWallet.execute(calls); `sender` is the account allowed to call it."""

    def __init__(self, w3, wallet, sender):
        self.w3, self.wallet, self.sender = w3, Web3.to_checksum_address(wallet), sender

    def _c(self, address):
        return self.w3.eth.contract(address=address, abi=_ABI)

    def balance(self, token, who):
        if token is None:
            return self.w3.eth.get_balance(who)
        return self._c(token).functions.balanceOf(who).call()

    def allowance(self, token, owner, spender):
        return self._c(token).functions.allowance(owner, spender).call()

    def owner(self, contract):
        return self._c(contract).functions.owner().call()

    def has_code(self, addr):
        return len(self.w3.eth.get_code(addr)) > 0

    @contextmanager
    def simulate(self, calls):
        # lean: simulates by sending the batch on the node itself and reverting it, so it needs evm_snapshot and an
        # unlocked sender (Hardhat, a local fork); for a public chain, write a provider on eth_simulateV1 or a fork.
        sid =self.w3.provider.make_request("evm_snapshot", [])["result"]
        try:
            tup = [(c["target"], c["value"], bytes.fromhex(c["data"][2:])) for c in calls]
            try:
                h = self._c(self.wallet).functions.execute(tup).transact(
                    {"from": self.sender, "gas": 5_000_000, "gasPrice": 0})
                r = self.w3.eth.wait_for_transaction_receipt(h)
            except Exception:
                r = None
            yield r if r is not None and r.status == 1 else None
        finally:
            r = self.w3.provider.make_request("evm_revert", [sid])
            if r.get("result") is not True:
                raise RuntimeError(f"evm_revert failed; the node may still hold the simulated batch: {r}")
