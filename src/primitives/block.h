// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

// ELEMENTS:
// Globals to avoid circular dependencies.
extern bool g_con_blockheightinheader;
extern bool g_signed_blocks;

class CProof
{
public:
    CScript challenge;
    CScript solution;

    CProof()
    {
        SetNull();
    }
    CProof(CScript challengeIn, CScript solutionIn) : challenge(challengeIn), solution(solutionIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*(CScriptBase*)(&challenge));
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(*(CScriptBase*)(&solution));
    }

    void SetNull()
    {
        challenge.clear();
        solution.clear();
    }

    bool IsNull() const
    {
        return challenge.empty();
    }

    std::string ToString() const;
};


class ConsensusParamEntry
{
public:
    unsigned char m_serialize_type; // Determines how it is serialized, defaults to null
    uint256 m_root;
    CScript m_signblockscript;
    uint32_t m_sbs_wit_limit; // Max block signature witness serialized size
    CScript m_fedpegscript;
    // No consensus meaning to the particular bytes, currently we interpret as PAK keys, details in pak.h
    std::vector<std::vector<unsigned char>> m_extension_space;

    // TODO Delete unused constructors such as below?
    ConsensusParamEntry() { m_sbs_wit_limit = 0; m_serialize_type = 0; };
    // TODO pass in serialization, put everything behind private?
    ConsensusParamEntry(const CScript& signblockscript_in, const uint32_t sbs_wit_limit_in, const CScript& fedpegscript_in, const std::vector<std::vector<unsigned char>> extension_space_in) : m_signblockscript(signblockscript_in), m_sbs_wit_limit(sbs_wit_limit_in), m_fedpegscript(fedpegscript_in), m_extension_space(extension_space_in) { m_serialize_type = 0; m_root = CalculateRoot(); };

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_serialize_type);
        switch(m_serialize_type) {
            case 0:
                /* Null entry, used to signal "no vote" proposal */
                break;
            case 1:
                READWRITE(m_signblockscript);
                break;
            case 2:
                READWRITE(m_signblockscript);
                READWRITE(m_sbs_wit_limit);
                READWRITE(m_fedpegscript);
                READWRITE(m_extension_space);
                break;
            default:
                throw std::ios_base::failure("Invalid consensus parameter entry type");
        }
    }

    // TODO fix/remove this
    uint256 CalculateRoot() const;

    bool IsNull() const
    {
        return m_serialize_type == 0;
    }
};

class DynaFedParams
{
public:

    // Currently enforced by network, not all fields may be known
    ConsensusParamEntry m_current;
    // Proposed rules for next epoch
    ConsensusParamEntry m_proposed;

    DynaFedParams() {};
    DynaFedParams(const ConsensusParamEntry& current, const ConsensusParamEntry& proposed) {};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_current);
        READWRITE(m_proposed);
    }

    uint256 CalculateRoot() const;

    bool IsNull() const
    {
        return m_current.IsNull() && m_proposed.IsNull();
    }
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    // Height in header as well as in coinbase for easier hsm validation
    // Is set for serialization with `-con_blockheightinheader=1`
    uint32_t block_height;
    uint32_t nBits;
    uint32_t nNonce;
    // Only used pre-dynamic federation
    CProof proof;
    // Dynamic federation: Subsumes the proof field
    DynaFedParams m_dyna_params;
    CScriptWitness m_signblock_witness;

    // Versionbits bit 27 has been redefined to dynamic blocks header version bit
    static const uint32_t DYNAMIC_MASK = (uint32_t)1 << 27;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        if (this->nVersion & DYNAMIC_MASK) {
            READWRITE(hashPrevBlock);
            READWRITE(hashMerkleRoot);
            READWRITE(nTime);
            READWRITE(block_height);
            READWRITE(m_dyna_params);
            if (!(s.GetType() & SER_GETHASH)) {
                READWRITE(m_signblock_witness.stack);
            }
        } else {
            READWRITE(hashPrevBlock);
            READWRITE(hashMerkleRoot);
            READWRITE(nTime);
            if (g_con_blockheightinheader) {
                READWRITE(block_height);
            }
            if (g_signed_blocks) {
                READWRITE(proof);
            } else {
                READWRITE(nBits);
                READWRITE(nNonce);
            }
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        block_height = 0;
        nBits = 0;
        nNonce = 0;
        proof.SetNull();
    }

    bool IsNull() const
    {
        if (g_signed_blocks) {
            return proof.IsNull();
        } else {
            return (nBits == 0);
        }
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.block_height   = block_height;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.proof          = proof;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
