// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "blind.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "keystore.h"
#include "validation.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "util.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <secp256k1_rangeproof.h>

#include <univalue.h>

using namespace std;

static secp256k1_context* secp256k1_blind_context = NULL;

class RPCRawTransaction_ECC_Init {
public:
    RPCRawTransaction_ECC_Init() {
        assert(secp256k1_blind_context == NULL);

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        assert(ctx != NULL);

        secp256k1_blind_context = ctx;
    }

    ~RPCRawTransaction_ECC_Init() {
        secp256k1_context *ctx = secp256k1_blind_context;
        secp256k1_blind_context = NULL;

        if (ctx) {
            secp256k1_context_destroy(ctx);
        }
    }
};
static RPCRawTransaction_ECC_Init ecc_init_on_load;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("hash", tx.GetWitnessHash().GetHex()));
    entry.push_back(Pair("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
    entry.push_back(Pair("vsize", (int)::GetVirtualTransactionSize(tx)));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    
    UniValue vin(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        if (tx.HasWitness()) {
                UniValue txinwitness(UniValue::VARR);
                for (unsigned int j = 0; j < tx.vin[i].scriptWitness.stack.size(); j++) {
                    std::vector<unsigned char> item = tx.vin[i].scriptWitness.stack[j];
                    txinwitness.push_back(HexStr(item.begin(), item.end()));
                }
                in.push_back(Pair("txinwitness", txinwitness));
        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        if (txout.nValue.IsExplicit())
            out.push_back(Pair("value", ValueFromAmount(txout.nValue.GetAmount())));
        else {
            int exp;
            int mantissa;
            uint64_t minv;
            uint64_t maxv;
            if (secp256k1_rangeproof_info(secp256k1_blind_context, &exp, &mantissa, &minv, &maxv, &txout.vchRangeproof[0], txout.vchRangeproof.size())) {
                if (exp == -1) {
                    out.push_back(Pair("value", ValueFromAmount((CAmount)minv)));
                } else {
                    out.push_back(Pair("value-minimum", ValueFromAmount((CAmount)minv)));
                    out.push_back(Pair("value-maximum", ValueFromAmount((CAmount)maxv)));
                }
                out.push_back(Pair("ct-exponent", exp));
                out.push_back(Pair("ct-bits", mantissa));
            }
        }
        const CConfidentialAsset& asset = txout.nAsset;
        if (asset.IsExplicit()) {
            out.push_back(Pair("asset", asset.GetAsset().GetHex()));
        }
        else if (asset.IsCommitment()) {
            out.push_back(Pair("assettag", HexStr(asset.vchCommitment)));
        }

        {
            CDataStream ssValue(SER_NETWORK, PROTOCOL_VERSION);
            ssValue << txout.nValue;
            out.push_back(Pair("serValue", HexStr(ssValue.begin(), ssValue.end())));
        }
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

UniValue getrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getrawtransaction \"txid\" ( verbose )\n"

            "\nNOTE: By default this function only works for mempool transactions. If the -txindex option is\n"
            "enabled, it also works for blockchain transactions.\n"
            "DEPRECATED: for now, it also works for transactions with unspent outputs.\n"

            "\nReturn the raw transaction data.\n"
            "\nIf verbose is 'true', returns an Object with information about 'txid'.\n"
            "If verbose is 'false' or omitted, returns a string that is serialized, hex-encoded data for 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (bool, optional, default=false) If false, return a string, otherwise return a json object\n"

            "\nResult (if verbose is not set or set to false):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose is set to true):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"hash\" : \"id\",        (string) The transaction hash (differs from txid for witness transactions)\n"
            "  \"size\" : n,             (numeric) The serialized transaction size\n"
            "  \"vsize\" : n,            (numeric) The virtual transaction size (differs from size for witness transactions)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "       \"txinwitness\": [\"hex\", ...] (array of string) hex-encoded witness data (if any)\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"fee_value\" : x.xxx,        (numeric) The fee value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"asset\" : \"hex\"           (string) the asset id, if unblinded\n"
            "       \"assettag\" : \"hex\"        (string) the asset tag, if blinded\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"address\"        (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" true")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", true")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashV(request.params[0], "parameter 1");

    // Accept either a bool (true) or a num (>=1) to indicate verbose output.
    bool fVerbose = false;
    if (request.params.size() > 1) {
        if (request.params[1].isNum()) {
            if (request.params[1].get_int() != 0) {
                fVerbose = true;
            }
        }
        else if(request.params[1].isBool()) {
            if(request.params[1].isTrue()) {
                fVerbose = true;
            }
        }
        else {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid type provided. Verbose parameter must be a boolean.");
        } 
    }

    CTransactionRef tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string(fTxIndex ? "No such mempool or blockchain transaction"
            : "No such mempool transaction. Use -txindex to enable blockchain transaction queries") +
            ". Use gettransaction for wallet transactions.");

    string strHex = EncodeHexTx(*tx, RPCSerializationFlags());

    if (!fVerbose)
        return strHex;

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", strHex));
    TxToJSON(*tx, hashBlock, result);
    return result;
}

UniValue gettxoutproof(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw runtime_error(
            "gettxoutproof [\"txid\",...] ( blockhash )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
            "\nNOTE: By default this function only works sometimes. This is when there is an\n"
            "unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option or\n"
            "specify the block in which the transaction is included manually (by blockhash).\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"blockhash\"   (string, optional) If specified, looks for txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n"
        );

    set<uint256> setTxids;
    uint256 oneTxid;
    UniValue txids = request.params[0].get_array();
    for (unsigned int idx = 0; idx < txids.size(); idx++) {
        const UniValue& txid = txids[idx];
        if (txid.get_str().length() != 64 || !IsHex(txid.get_str()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ")+txid.get_str());
        uint256 hash(uint256S(txid.get_str()));
        if (setTxids.count(hash))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ")+txid.get_str());
       setTxids.insert(hash);
       oneTxid = hash;
    }

    LOCK(cs_main);

    CBlockIndex* pblockindex = NULL;

    uint256 hashBlock;
    if (request.params.size() > 1)
    {
        hashBlock = uint256S(request.params[1].get_str());
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        pblockindex = mapBlockIndex[hashBlock];
    } else {
        CCoins coins;
        if (pcoinsTip->GetCoins(oneTxid, coins) && coins.nHeight > 0 && coins.nHeight <= chainActive.Height())
            pblockindex = chainActive[coins.nHeight];
    }

    if (pblockindex == NULL)
    {
        CTransactionRef tx;
        if (!GetTransaction(oneTxid, tx, Params().GetConsensus(), hashBlock, false) || hashBlock.IsNull())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        pblockindex = mapBlockIndex[hashBlock];
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    unsigned int ntxFound = 0;
    for (const auto& tx : block.vtx)
        if (setTxids.count(tx->GetHash()))
            ntxFound++;
    if (ntxFound != setTxids.size())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    CMerkleBlock mb(block, setTxids);
    ssMB << mb;
    std::string strHex = HexStr(ssMB.begin(), ssMB.end());
    return strHex;
}

UniValue verifytxoutproof(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof generated by gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is invalid\n"
        );

    CDataStream ssMB(ParseHexV(request.params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    UniValue res(UniValue::VARR);

    vector<uint256> vMatch;
    vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
        return res;

    LOCK(cs_main);

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

    BOOST_FOREACH(const uint256& hash, vMatch)
        res.push_back(hash.GetHex());
    return res;
}

UniValue createrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4)
        throw runtime_error(
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n,\"amount\":n},...] {\"address\":amount,\"data\":\"hex\",...} ( locktime {\"address\":asset} )\n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"inputs\"                (array, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction id\n"
            "         \"vout\":n,         (numeric, required) The output number\n"
            "         \"amount\": x.xxx,    (numeric, required) The amount being spent\n"
            "         \"asset\": \"string\"   (string, optional, default=bitcoin) The asset of the input, as a tag string or a hex value\n"
            "         \"sequence\":n      (numeric, optional) The sequence number\n"
            "       } \n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"               (object, required) a json object with outputs\n"
            "    {\n"
            "      \"address\": x.xxx,    (numeric or string, required) The key is the bitcoin address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
            "      \"data\": \"hex\"      (string, required) The key is \"data\", the value is hex encoded data\n"
            "      ,...\n"
            "    }\n"
            "3. locktime                  (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
            "4. \"output_assets\"           (strings, optional, default=bitcoin) A json object of assets to addresses\n"
            "   {\n"
            "       \"address\": \"hex\" \n"
            "       ...\n"
            "   }\n"
            "\nResult:\n"
            "\"transaction\"              (string) hex string of the transaction\n"

            "\nExamples:\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"amount\\\":2.5}]\" \"{\\\"address\\\":2.41}\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"amount\\\":2.5,\\\"asset\\\":\\\"myasset\\\"}]\" \"{\\\"address\\\":2.41}\" 0 \"{\\\"address\\\":\\\"myasset\\\"}\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"amount\\\":2.5}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"amount\\\":2.5}]\", \"{\\\"address\\\":2.41}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"amount\\\":2.5,\\\"asset\\\":\\\"myasset\\\"}]\", \"{\\\"address\\\":2.41}\", 0, \"{\\\"address\\\":\\\"myasset\\\"}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"amount\\\":2.5}]\", \"{\\\"data\\\":\\\"00010203\\\"}\"")
        );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ)(UniValue::VNUM)(UniValue::VOBJ), true);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    UniValue inputs = request.params[0].get_array();
    UniValue sendTo = request.params[1].get_obj();

    CMutableTransaction rawTx;

    if (request.params.size() > 2 && !request.params[2].isNull()) {
        int64_t nLockTime = request.params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    UniValue assets;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        assets = request.params[3].get_obj();
    }

    CAsset bitcoinid(BITCOINID);
    CAmountMap inputValue;

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");
        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            else
                nSequence = (uint32_t)seqNr64;
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        CAsset asset(bitcoinid);
        const UniValue& asset_val = find_value(o, "asset");
        if (asset_val.isStr()) {
            asset = CAsset(ParseHashO(o, "asset"));
        }

        UniValue vout_value = find_value(o, "amount");
        if (vout_value.isNull()) {
            LogPrintf("deprecated use of `nValue' in call to createrawtransaction --- use `amount' instead\n");
            vout_value = find_value(o, "nValue");
        }
        inputValue[asset] += AmountFromValue(vout_value);

        rawTx.vin.push_back(in);
    }

    CAmountMap outputValue;

    set<CBitcoinAddress> setAddress;
    vector<string> addrList = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, addrList) {
        // Defaults to bitcoin
        CAsset asset(bitcoinid);
        if (!assets.isNull()) {
            if (find_value(assets, name_).isNull())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Given output_asset address is not a valid given output address: ")+name_);
            asset = CAsset(ParseHashO(assets, name_));
        }

        if (name_ == "data") {
            std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(),"Data");

            CTxOut out(asset, 0, CScript() << OP_RETURN << data);
            rawTx.vout.push_back(out);
        } else {
            CBitcoinAddress address(name_);
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+name_);

            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
            setAddress.insert(address);

            CScript scriptPubKey = GetScriptForDestination(address.Get());
            CAmount nAmount = AmountFromValue(sendTo[name_]);

            outputValue[asset] += nAmount;

            CTxOut out(asset, nAmount, scriptPubKey);
            if (address.IsBlinded()) {
                CPubKey confidentiality_pubkey = address.GetBlindingKey();
                if (!confidentiality_pubkey.IsValid())
                     throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: invalid confidentiality public key given"));
                out.vchNonceCommitment = std::vector<unsigned char>(confidentiality_pubkey.begin(), confidentiality_pubkey.end());
            }
            rawTx.vout.push_back(out);
        }
    }

    // Now add fee outputs
    CAmountMap fees = inputValue - outputValue;
    for(std::map<CAsset, CAmount>::const_iterator it = fees.begin(); it != fees.end(); it++) {
        if (it->second < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid transaction: Value out exceeds value in for some asset type."));
        }
        else if (it->second > 0) {
            CTxOut out(it->first, it->second, CScript());
            rawTx.vout.push_back(out);
        }
    }

    return EncodeHexTx(rawTx);
}

// Retrieve already-existing output blinds for a given transaction (if known to wallet)
// or blank spots to be filled by BlindOutputs
void FillOutputBlinds(const CMutableTransaction& tx, bool fUseWallet, std::vector<uint256>& output_value_blinds, std::vector<uint256>& output_asset_blinds, std::vector<CAsset>& output_assets, std::vector<CPubKey>& output_pubkeys) {
    for (size_t nOut = 0; nOut < tx.vout.size(); nOut++) {
        if (!tx.vout[nOut].nValue.IsExplicit()) {
            uint256 blinding_factor;
            uint256 asset_blinding_factor;
            CAsset asset;
            CAmount amount;
#ifdef ENABLE_WALLET
            if (fUseWallet && UnblindOutput(pwalletMain->GetBlindingKey(&tx.vout[nOut].scriptPubKey), tx.vout[nOut], amount, blinding_factor, asset, asset_blinding_factor) != 0) {
                output_value_blinds.push_back(blinding_factor);
                output_pubkeys.push_back(CPubKey());
                output_asset_blinds.push_back(asset_blinding_factor);
                output_assets.push_back(asset);
            } else if (fUseWallet)
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: transaction outputs must be unblinded or to wallet"));
#endif
            if (!fUseWallet)
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: transaction outputs must be unblinded"));
        } else if (tx.vout[nOut].vchNonceCommitment.size() == 0) {
            output_pubkeys.push_back(CPubKey());
            output_value_blinds.push_back(uint256());
            output_asset_blinds.push_back(uint256());
            output_assets.push_back(CAsset());
        } else {
            CPubKey pubkey(tx.vout[nOut].vchNonceCommitment);
            if (!pubkey.IsValid()) {
                 throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: invalid confidentiality public key given"));
            }
            output_pubkeys.push_back(pubkey);
            output_value_blinds.push_back(uint256());
            output_asset_blinds.push_back(uint256());
            output_assets.push_back(CAsset());
        }
    }
}

UniValue rawblindrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() < 5 || request.params.size() > 6))
        throw std::runtime_error(
            "rawblindrawtransaction \"hexstring\" [\"inputblinder\",...] [\"totalblinder\"]\n"
            "\nConvert one or more outputs of a raw transaction into confidential ones.\n"
            "Returns the hex-encoded raw transaction.\n"
            "If at least one of the inputs is confidential, at least one of the outputs must be.\n"
            "The input raw transaction cannot have already-blinded outputs.\n"
            "The output keys used can be specified by using a confidential address in createrawtransaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\",          (string, required) A hex-encoded raw transaction.\n"
            "2. [                     (array, required) An array with one entry per transaction input.\n"
            "    \"inputblinder\"       (string, required) A hex-encoded blinding factor, one for each input.\n"
            "                         Blinding factors can be found in the \"blinder\" output of listunspent.\n"
            "   ],\n"
            "3. [                     (array, required) An array with one entry per transaction input.\n"
            "   \"inputamount\"       (numeric, required) An amount for each input.\n"
            "   ],\n"
            "4. [                     (array, required) An array with one entry per transaction input.\n"
            "   \"inputasset\"        (string, required) A hex-encoded asset id, one for each input.\n"
            "   ],\n"
            "5. [                     (array, required) An array with one entry per transaction input.\n"
            "   \"inputassetblinder\" (string, required) A hex-encoded asset blinding factor, one for each input.\n"
            "   ],\n"
            "6. \"totalblinder\"        (string, optional) Ignored for now.\n"

            "\nResult:\n"
            "\"transaction\"              (string) hex string of the transaction\n"
        );

    if (request.params.size() == 5) {
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VARR)(UniValue::VARR));
    } else {
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR));
    }

    vector<unsigned char> txData(ParseHexV(request.params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction tx;
    try {
        ssData >> tx;
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue inputBlinds = request.params[1].get_array();
    UniValue inputAmounts = request.params[2].get_array();
    UniValue inputAssets = request.params[3].get_array();
    UniValue inputAssetBlinds = request.params[4].get_array();

    if (inputBlinds.size() != tx.vin.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: one (potentially empty) input blind for each input must be provided"));
    if (inputAmounts.size() != tx.vin.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: one (potentially empty) input blind for each input must be provided"));
    if (inputAssets.size() != tx.vin.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: one (potentially empty) input asset id for each input must be provided"));
    if (inputAssetBlinds.size() != tx.vin.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: one (potentially empty) input asset blind for each input must be provided"));

    std::vector<CAmount> input_amounts;
    std::vector<uint256> input_blinds;
    std::vector<uint256> input_asset_blinds;
    std::vector<CAsset> input_assets;
    std::vector<uint256> output_value_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CAsset> output_assets;
    std::vector<CPubKey> output_pubkeys;
    for (size_t nIn = 0; nIn < tx.vin.size(); nIn++) {
        if (!inputBlinds[nIn].isStr())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input blinds must be an array of hex strings");
        if (!inputAssetBlinds[nIn].isStr())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input asset blinds must be an array of hex strings");
        if (!inputAssets[nIn].isStr())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input asset ids must be an array of hex strings");
        if (!inputAmounts[nIn].isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Amounts must be numeric.");

        std::string blind(inputBlinds[nIn].get_str());
        std::string assetblind(inputAssetBlinds[nIn].get_str());
        std::string asset(inputAssets[nIn].get_str());
        if (!IsHex(blind) || blind.length() != 32*2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input blinds must be an array of 32-byte hex-encoded strings");
        if (!IsHex(assetblind) || assetblind.length() != 32*2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input asset blinds must be an array of 32-byte hex-encoded strings");
        if (!IsHex(asset) || asset.length() != 32*2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "input asset blinds must be an array of 32-byte hex-encoded strings");

        input_blinds.push_back(uint256S(blind));
        input_asset_blinds.push_back(uint256S(assetblind));
        input_assets.push_back(CAsset(uint256S(asset)));
        input_amounts.push_back(inputAmounts[nIn].get_int64());
    }

    FillOutputBlinds(tx, false, output_value_blinds, output_asset_blinds, output_assets, output_pubkeys);

    // Since we assume all inputs must be unblinded, we can pass in blank input_amounts to BlindOutputs

    if (!BlindOutputs(input_blinds, input_asset_blinds, input_assets, input_amounts, output_value_blinds, output_asset_blinds, output_pubkeys, tx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, string("Unable to blind transaction: add an additional output with a blinding pubkey"));
    }

    return EncodeHexTx(tx);
}

#ifdef ENABLE_WALLET
UniValue blindrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw runtime_error(
            "blindrawtransaction \"hexstring\" [\"totalblinder\"]\n"
            "\nConvert one or more outputs of a raw transaction into confidential ones using only wallet inputs.\n"
            "Returns the hex-encoded raw transaction.\n"
            "If at least one of the inputs is confidential, at least one of the outputs must be.\n"
            "The output keys used can be specified by using a confidential address in createrawtransaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\",          (string, required) A hex-encoded raw transaction.\n"
            "2. \"totalblinder\"        (string, optional) Ignored for now.\n"

            "\nResult:\n"
            "\"transaction\"              (string) hex string of the transaction\n"
        );

    if (request.params.size() == 1) {
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR));
    } else {
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR));
    }

    vector<unsigned char> txData(ParseHexV(request.params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction tx;
    try {
        ssData >> tx;
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    LOCK(pwalletMain->cs_wallet);

    std::vector<uint256> input_blinds;
    std::vector<uint256> input_asset_blinds;
    std::vector<CAsset> input_assets;
    std::vector<CAmount> input_amounts;
    std::vector<uint256> output_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CAsset> output_assets;
    std::vector<CPubKey> output_pubkeys;
    for (size_t nIn = 0; nIn < tx.vin.size(); nIn++) {
        std::map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.find(tx.vin[nIn].prevout.hash);
        if (it == pwalletMain->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: transaction spends from non-wallet output"));
        }
        if (tx.vin[nIn].prevout.n >= it->second.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter: transaction spends non-existing output"));
        }
        input_blinds.push_back(it->second.GetBlindingFactor(tx.vin[nIn].prevout.n));
        input_asset_blinds.push_back(it->second.GetAssetBlindingFactor(tx.vin[nIn].prevout.n));
        if (it->second.tx->vout[tx.vin[nIn].prevout.n].nAsset.IsExplicit()) {
            input_assets.push_back(it->second.tx->vout[tx.vin[nIn].prevout.n].nAsset.GetAsset());
        }
        else {
            input_assets.push_back(it->second.GetAsset(tx.vin[nIn].prevout.n));
        }
        if (it->second.tx->vout[tx.vin[nIn].prevout.n].nValue.IsExplicit()) {
            input_amounts.push_back(it->second.tx->vout[tx.vin[nIn].prevout.n].nValue.GetAmount());
        }
        else {
            input_amounts.push_back(it->second.GetValueOut(tx.vin[nIn].prevout.n));
        }
    }

    FillOutputBlinds(tx, true, output_blinds, output_asset_blinds, output_assets,  output_pubkeys);

    if (!BlindOutputs(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, tx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, string("Unable to blind transaction: add an additional output with a blinding pubkey"));
    }

    return EncodeHexTx(tx);
}
#endif

UniValue decoderawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"hexstring\"      (string, required) The transaction hex string\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id\n"
            "  \"hash\" : \"id\",        (string) The transaction hash (differs from txid for witness transactions)\n"
            "  \"size\" : n,             (numeric) The transaction size\n"
            "  \"vsize\" : n,            (numeric) The virtual transaction size (differs from size for witness transactions)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"fee\" : x.xxx,          (numeric) The transaction fee in " + CURRENCY_UNIT + "\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"txinwitness\": [\"hex\", ...] (array of string) hex-encoded witness data (if any)\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"asset\" : \"hex\"           (string) the asset id, if unblinded\n"
            "       \"assettag\" : \"hex\"        (string) the asset tag, if blinded\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR));

    CMutableTransaction mtx;

    if (!DecodeHexTx(mtx, request.params[0].get_str(), true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(CTransaction(std::move(mtx)), uint256(), result);

    return result;
}

UniValue decodescript(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "decodescript \"hexstring\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hexstring\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) bitcoin address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) address of P2SH script wrapping this redeem script (not returned if the script is already a P2SH).\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodescript", "\"hexstring\"")
            + HelpExampleRpc("decodescript", "\"hexstring\"")
        );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR));

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    UniValue type;
    type = find_value(r, "type");

    if (type.isStr() && type.get_str() != "scripthash") {
        // P2SH cannot be wrapped in a P2SH. If this script is already a P2SH,
        // don't return the address for a P2SH of the P2SH.
        r.push_back(Pair("p2sh", CBitcoinAddress(CScriptID(script)).ToString()));
    }

    return r;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

UniValue signrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
        throw runtime_error(
            "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
            + HelpRequiringPassphrase() + "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
            "     [               (json array of json objects, or 'null' if none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
            "         \"redeemScript\": \"hex\",   (string, required for P2SH or P2WSH) redeem script\n"
            "         \"amount\": value            (numeric, required) The amount spent\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privkeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence number\n"
            "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif
    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR), true);

    vector<unsigned char> txData(ParseHexV(request.params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CMutableTransaction> txVariants;
    while (!ssData.empty()) {
        try {
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (const std::exception&) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = request.params[2].get_array();
        for (unsigned int idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

    // Add previous txouts given in the RPC call:
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        UniValue prevTxs = request.params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coins->vout[nOut].scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut+1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0;
                if (prevOut.exists("amount")) {
                    coins->vout[nOut].nValue = AmountFromValue(find_value(prevOut, "amount"));
                }
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && (scriptPubKey.IsPayToScriptHash() || scriptPubKey.IsPayToWitnessScriptHash())) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"txid", UniValueType(UniValue::VSTR)},
                        {"vout", UniValueType(UniValue::VNUM)},
                        {"scriptPubKey", UniValueType(UniValue::VSTR)},
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                    });
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = request.params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;
        const CConfidentialValue& amount = coins->vout[txin.prevout.n].nValue;

        SignatureData sigdata;
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mergedTx, i, amount, nHashType), prevPubKey, sigdata);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CMutableTransaction& txv, txVariants) {
            if (txv.vin.size() > i) {
                sigdata = CombineSignatures(prevPubKey, TransactionNoWithdrawsSignatureChecker(&txConst, i, amount), sigdata, DataFromTransaction(txv, i));
            }
        }

        UpdateTransaction(mergedTx, i, sigdata);

        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionNoWithdrawsSignatureChecker(&txConst, i, amount), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
    result.push_back(Pair("complete", fComplete));
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors));
    }

    AuditLogPrintf("%s : signrawtransaction %s\n", getUser(), EncodeHexTx(mergedTx));

    return result;
}

UniValue sendrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw runtime_error(
            "sendrawtransaction \"hexstring\" ( allowhighfees ) ( allowunblindfails )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "3. allowblindfails  (boolean, optional, default=false) Allow outputs which have a pubkey attached (ie are blindable), which are unblinded\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)(UniValue::VBOOL));

    // parse hex string from parameter
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    const uint256& hashTx = tx->GetHash();

    bool fLimitFree = false;
    CAmount nMaxRawTxFee = maxTxFee;
    if (request.params.size() > 1 && request.params[1].get_bool())
        nMaxRawTxFee = 0;

    bool fOverrideBlindable = false;
    if (request.params.size() > 2)
        fOverrideBlindable = request.params[2].get_bool();

    if (!fOverrideBlindable) {
        for (unsigned i = 0; i < tx->vout.size(); i++) {
            const CTxOut& txout = tx->vout[i];
            if (txout.nValue.IsExplicit() && txout.vchNonceCommitment.size() != 0)
                throw JSONRPCError(RPC_TRANSACTION_ERROR, strprintf("Output %u is unblinded, but has blinding pubkey attached, please use [raw]blindrawtransaction", i));
        }
    }

    CCoinsViewCache &view = *pcoinsTip;
    const CCoins* existingCoins = view.AccessCoins(hashTx);
    bool fHaveMempool = mempool.exists(hashTx);
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000;
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, std::move(tx), fLimitFree, &fMissingInputs, NULL, false, nMaxRawTxFee)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    AuditLogPrintf("%s : sendrawtransaction %s\n", getUser(), hashTx.GetHex());

    CInv inv(MSG_TX, hashTx);
    g_connman->ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });
    return hashTx.GetHex();
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "rawtransactions",    "getrawtransaction",      &getrawtransaction,      true,  {"txid","verbose"} },
    { "rawtransactions",    "createrawtransaction",   &createrawtransaction,   true,  {"inputs","outputs","locktime"} },
    { "rawtransactions",    "decoderawtransaction",   &decoderawtransaction,   true,  {"hexstring"} },
    { "rawtransactions",    "decodescript",           &decodescript,           true,  {"hexstring"} },
    { "rawtransactions",    "sendrawtransaction",     &sendrawtransaction,     false, {"hexstring","allowhighfees"} },
    { "rawtransactions",    "signrawtransaction",     &signrawtransaction,     false, {"hexstring","prevtxs","privkeys","sighashtype"} }, /* uses wallet if enabled */
    { "rawtransactions",    "rawblindrawtransaction", &rawblindrawtransaction, false, {}},
#ifdef ENABLE_WALLET
    { "rawtransactions",    "blindrawtransaction",    &blindrawtransaction,    true, {}},
#endif
    { "blockchain",         "gettxoutproof",          &gettxoutproof,          true,  {"txids", "blockhash"} },
    { "blockchain",         "verifytxoutproof",       &verifytxoutproof,       true,  {"proof"} },
};

void RegisterRawTransactionRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
