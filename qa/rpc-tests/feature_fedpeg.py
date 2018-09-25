#!/usr/bin/env python3

from decimal import Decimal
import json
import time

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    connect_nodes_bi,
    rpc_auth_pair,
    rpc_port,
    start_node,
    start_nodes,
    stop_node,
)

# Sync mempool, make a block, sync blocks
def sync_all(sidechain, sidechain2, makeblock=True):
    block = ""
    timeout = 20
    while len(sidechain.getrawmempool()) != len(sidechain2.getrawmempool()):
        time.sleep(1)
        timeout -= 1
        if timeout == 0:
            raise Exception("Peg-in has failed to propagate.")
    if makeblock:
        block = sidechain2.generate(1)
    while sidechain.getblockcount() != sidechain2.getblockcount():
        time.sleep(1)
        timeout -= 1
        if timeout == 0:
            raise Exception("Blocks are not propagating.")
    return block

def get_new_unconfidential_address(node):
    addr = node.getnewaddress()
    val_addr = node.validateaddress(addr)
    if 'unconfidential' in val_addr:
        return val_addr['unconfidential']
    return val_addr['address']

class FedPegTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 4

    def setup_network(self, split=False):

        # Parent chain args
        self.extra_args = [[
            # '-printtoconsole',
            '-validatepegin=0',
            '-anyonecanspendaremine',
            '-initialfreecoins=2100000000000000',
        ]] * 2

        self.nodes = start_nodes(2, self.options.tmpdir, self.extra_args[:2], chain='parent')
        connect_nodes_bi(self.nodes, 0, 1)
        self.parentgenesisblockhash = self.nodes[0].getblockhash(0)
        print('parentgenesisblockhash', self.parentgenesisblockhash)
        parent_pegged_asset = self.nodes[0].getsidechaininfo()['pegged_asset']

        # Sidechain args
        parent_chain_signblockscript = '51'
        for n in range(2):
            rpc_u, rpc_p = rpc_auth_pair(n)
            self.extra_args.append([
                # '-printtoconsole',
                '-parentgenesisblockhash=%s' % self.parentgenesisblockhash,
                '-validatepegin=1',
                '-anyonecanspendaremine=0',
                '-initialfreecoins=0',
                '-peginconfirmationdepth=10',
                '-mainchainrpchost=127.0.0.1',
                '-mainchainrpcport=%s' % rpc_port(n),
                '-mainchainrpcuser=%s' % rpc_u,
                '-mainchainrpcpassword=%s' % rpc_p,
                '-parentpubkeyprefix=235',
                '-parentscriptprefix=75',
                '-con_parent_chain_signblockscript=%s' % parent_chain_signblockscript,
                '-con_parent_pegged_asset=%s' % parent_pegged_asset,
            ])
            self.nodes.append(start_node(n + 2, self.options.tmpdir, self.extra_args[n + 2], chain='sidechain'))

        connect_nodes_bi(self.nodes, 2, 3)
        self.is_network_split = True
        self.sync_all()

    def test_pegout(self, parent_chain_addr, sidechain):
        pegout_txid = sidechain.sendtomainchain(parent_chain_addr, 1)
        raw_pegout = sidechain.getrawtransaction(pegout_txid, True)
        assert 'vout' in raw_pegout and len(raw_pegout['vout']) > 0
        pegout_tested = False
        for output in raw_pegout['vout']:
            scriptPubKey = output['scriptPubKey']
            if 'type' in scriptPubKey and scriptPubKey['type'] == 'nulldata':
                assert ('pegout_hex' in scriptPubKey and 'pegout_asm' in scriptPubKey and 'pegout_type' in scriptPubKey and
                        'pegout_chain' in scriptPubKey and 'pegout_reqSigs' in scriptPubKey and 'pegout_addresses' in scriptPubKey)
                assert scriptPubKey['pegout_chain'] == self.parentgenesisblockhash
                assert scriptPubKey['pegout_reqSigs'] == 1
                assert parent_chain_addr in scriptPubKey['pegout_addresses']
                pegout_tested = True
                break
        assert pegout_tested

    def run_test(self):
        parent = self.nodes[0]
        parent2 = self.nodes[1]
        sidechain = self.nodes[2]
        sidechain2 = self.nodes[3]

        parent.generate(101)
        sidechain.generate(101)

        addrs = sidechain.getpeginaddress()
        addr = parent.validateaddress(addrs["mainchain_address"])
        print('addrs', addrs)
        print('addr', addr)
        txid1 = parent.sendtoaddress(addrs["mainchain_address"], 24)
        # 10+2 confirms required to get into mempool and confirm
        parent.generate(1)
        time.sleep(2)
        proof = parent.gettxoutproof([txid1])
        
        raw = parent.getrawtransaction(txid1)
        print('raw', parent.getrawtransaction(txid1, True))

        print("Attempting peg-in")
        # First attempt fails the consensus check but gives useful result
        try:
            pegtxid = sidechain.claimpegin(raw, proof)
            raise Exception("Peg-in should not be mature enough yet, need another block.")
        except JSONRPCException as e:
            print('ERROR:', e.error)
            assert("Peg-in Bitcoin transaction needs more confirmations to be sent." in e.error["message"])

        # Second attempt simply doesn't hit mempool bar
        parent.generate(10)
        try:
            pegtxid = sidechain.claimpegin(raw, proof)
            raise Exception("Peg-in should not be mature enough yet, need another block.")
        except JSONRPCException as e:
            assert("Peg-in Bitcoin transaction needs more confirmations to be sent." in e.error["message"])

        # Should fail due to non-witness
        try:
            pegtxid = sidechain.claimpegin(raw, proof, get_new_unconfidential_address(sidechain))
            raise Exception("Peg-in with non-matching claim_script should fail.")
        except JSONRPCException as e:
            print(e.error["message"])
            assert("Given or recovered script is not a witness program." in e.error["message"])

        # # Should fail due to non-matching wallet address
        # try:
        #     pegtxid = sidechain.claimpegin(raw, proof, get_new_unconfidential_address(sidechain))
        #     raise Exception("Peg-in with non-matching claim_script should fail.")
        # except JSONRPCException as e:
        #     print(e.error["message"])
        #     assert("Given claim_script does not match the given Bitcoin transaction." in e.error["message"])

        # 12 confirms allows in mempool
        parent.generate(1)
        # Should succeed via wallet lookup for address match, and when given
        pegtxid1 = sidechain.claimpegin(raw, proof)

        # Will invalidate the block that confirms this transaction later
        sync_all(parent, parent2)
        blockhash = sync_all(sidechain, sidechain2)
        sidechain.generate(5)

        tx1 = sidechain.gettransaction(pegtxid1)

        print('tx1', tx1)
        if "confirmations" in tx1 and tx1["confirmations"] == 6:
            print("Peg-in is confirmed: Success!")
        else:
            raise Exception("Peg-in confirmation has failed.")

        # Look at pegin fields
        decoded = sidechain.decoderawtransaction(tx1["hex"])
        assert decoded["vin"][0]["is_pegin"] == True
        assert len(decoded["vin"][0]["pegin_witness"]) > 0
        # Check that there's sufficient fee for the peg-in
        vsize = decoded["vsize"]
        fee_output = decoded["vout"][1]
        fallbackfee_pervbyte = Decimal("0.00001")/Decimal("1000")
        assert fee_output["scriptPubKey"]["type"] == "fee"
        assert fee_output["value"] >= fallbackfee_pervbyte*vsize

        # Quick reorg checks of pegs
        sidechain.invalidateblock(blockhash[0])
        if sidechain.gettransaction(pegtxid1)["confirmations"] != 0:
            raise Exception("Peg-in didn't unconfirm after invalidateblock call.")
        # Re-enters block
        sidechain.generate(1)
        if sidechain.gettransaction(pegtxid1)["confirmations"] != 1:
            raise Exception("Peg-in should have one confirm on side block.")
        sidechain.reconsiderblock(blockhash[0])
        if sidechain.gettransaction(pegtxid1)["confirmations"] != 6:
            raise Exception("Peg-in should be back to 6 confirms.")

        # Do many claims in mempool
        n_claims = 5

        print("Flooding mempool with many small claims")
        pegtxs = []
        sidechain.generate(101)

        for i in range(n_claims):
            addrs = sidechain.getpeginaddress()
            txid = parent.sendtoaddress(addrs["mainchain_address"], 1)
            parent.generate(12)
            proof = parent.gettxoutproof([txid])
            raw = parent.getrawtransaction(txid)
            pegtxs += [sidechain.claimpegin(raw, proof)]

        sync_all(parent, parent2)
        sync_all(sidechain, sidechain2)

        sidechain2.generate(1)
        for pegtxid in pegtxs:
            tx = sidechain.gettransaction(pegtxid)
            if "confirmations" not in tx or tx["confirmations"] == 0:
                raise Exception("Peg-in confirmation has failed.")

        print("Test pegout")
        self.test_pegout(get_new_unconfidential_address(parent), sidechain)

        print("Test pegout P2SH")
        parent_chain_addr = get_new_unconfidential_address(parent)
        parent_pubkey = parent.validateaddress(parent_chain_addr)["pubkey"]
        parent_chain_p2sh_addr = parent.createmultisig(1, [parent_pubkey])["address"]
        self.test_pegout(parent_chain_p2sh_addr, sidechain)

        print("Test pegout Garbage")
        parent_chain_addr = "garbage"
        try:
            self.test_pegout(parent_chain_addr, sidechain)
            raise Exception("A garbage address should fail.")
        except JSONRPCException as e:
            assert("Invalid Bitcoin address" in e.error["message"])

        print("Test pegout Garbage valid")
        prev_txid = sidechain.sendtoaddress(sidechain.getnewaddress(), 1)
        sidechain.generate(1)
        pegout_chain = 'a' * 64
        pegout_hex = 'b' * 500
        inputs = [{"txid": prev_txid, "vout": 0}]
        outputs = {"vdata": [pegout_chain, pegout_hex]}
        rawtx = sidechain.createrawtransaction(inputs, outputs)
        raw_pegout = sidechain.decoderawtransaction(rawtx)

        assert 'vout' in raw_pegout and len(raw_pegout['vout']) > 0
        pegout_tested = False
        for output in raw_pegout['vout']:
            scriptPubKey = output['scriptPubKey']
            if 'type' in scriptPubKey and scriptPubKey['type'] == 'nulldata':
                assert ('pegout_hex' in scriptPubKey and 'pegout_asm' in scriptPubKey and 'pegout_type' in scriptPubKey and
                        'pegout_chain' in scriptPubKey and 'pegout_reqSigs' not in scriptPubKey and 'pegout_addresses' not in scriptPubKey)
                assert scriptPubKey['pegout_type'] == 'nonstandard'
                assert scriptPubKey['pegout_chain'] == pegout_chain
                assert scriptPubKey['pegout_hex'] == pegout_hex
                pegout_tested = True
                break
        assert pegout_tested

        print ("Now test failure to validate peg-ins based on intermittant bitcoind rpc failure")
        stop_node(self.nodes[1], 1)
        txid = parent.sendtoaddress(addrs["mainchain_address"], 1)
        parent.generate(12)
        proof = parent.gettxoutproof([txid])
        raw = parent.getrawtransaction(txid)
        stuck_peg = sidechain.claimpegin(raw, proof)
        sidechain.generate(1)
        print("Waiting to ensure block is being rejected by sidechain2")
        time.sleep(5)

        assert(sidechain.getblockcount() != sidechain2.getblockcount())

        print("Restarting parent2")
        self.nodes[1] = start_node(1, self.options.tmpdir, self.extra_args[1], chain='parent')
        parent2 = self.nodes[1]
        connect_nodes_bi(self.nodes, 0, 1)
        time.sleep(5)

        # Don't make a block, race condition when pegin-invalid block
        # is awaiting further validation, nodes reject subsequent blocks
        # even ones they create
        sync_all(sidechain, sidechain2, makeblock=False)
        print("Now send funds out in two stages, partial, and full")
        some_btc_addr = get_new_unconfidential_address(parent)
        bal_1 = sidechain.getwalletinfo()["balance"]["bitcoin"]
        try:
            sidechain.sendtomainchain(some_btc_addr, bal_1 + 1)
            raise Exception("Sending out too much; should have failed")
        except JSONRPCException as e:
            assert("Insufficient funds" in e.error["message"])

        assert(sidechain.getwalletinfo()["balance"]["bitcoin"] == bal_1)
        try:
            sidechain.sendtomainchain(some_btc_addr+"b", bal_1 - 1)
            raise Exception("Sending to invalid address; should have failed")
        except JSONRPCException as e:
            assert("Invalid Bitcoin address" in e.error["message"])

        assert(sidechain.getwalletinfo()["balance"]["bitcoin"] == bal_1)
        try:
            sidechain.sendtomainchain("1Nro9WkpaKm9axmcfPVp79dAJU1Gx7VmMZ", bal_1 - 1)
            raise Exception("Sending to mainchain address when should have been testnet; should have failed")
        except JSONRPCException as e:
            assert("Invalid Bitcoin address" in e.error["message"])

        assert(sidechain.getwalletinfo()["balance"]["bitcoin"] == bal_1)

        peg_out_txid = sidechain.sendtomainchain(some_btc_addr, 1)

        peg_out_details = sidechain.decoderawtransaction(sidechain.getrawtransaction(peg_out_txid))
        # peg-out, change
        assert(len(peg_out_details["vout"]) == 3)
        found_pegout_value = False
        for output in peg_out_details["vout"]:
            if "value" in output and output["value"] == 1:
                found_pegout_value = True
        assert(found_pegout_value)

        bal_2 = sidechain.getwalletinfo()["balance"]["bitcoin"]
        # Make sure balance went down
        assert(bal_2 + 1 < bal_1)

        sidechain.sendtomainchain(some_btc_addr, bal_2, True)

        assert("bitcoin" not in sidechain.getwalletinfo()["balance"])

        print('Success!')

if __name__ == '__main__':
    FedPegTest().main()
