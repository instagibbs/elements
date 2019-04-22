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

class ConsensusParameterMerkleTree
{
public:
    // Computed and stored on construction
    uint256 m_cpmt_root;

    // Current consensus parameters
    CScript c_sbs; // (s)ign(b)lock(s)cript
    CScript c_fps; // (f)ed(p)eg(s)cript
    std::vector<std::vector<unsigned char>> c_pe; // (p)ak (e)ntries

    // Proposed consensus paramaters
    CScript p_sbs; // (s)ign(b)lock(s)cript
    CScript p_fps; // (f)ed(p)eg(s)cript
    std::vector<std::vector<unsigned char>> p_pe; // (p)ak (e)ntries

    ConsensusParameterMerkleTree() = delete;
    ConsensusParameterMerkleTree(ConsensusParameterMerkleTree& cmpt) = delete;
    ConsensusParameterMerkelTree(const CScript& c_sbs_in, const CScript& c_fps_in, const std::vector<std::vector<unsigned char>> c_pe_in, const CScript& p_sbs_in, const CScript& p_fps_in, const std::vector<std::vector<unsigned char>> p_pe_in) c_sbs(c_sbs_in), c_fps(c_fps_in), c_pe(c_pe_in), p_sbs(p_sbs_in), p_fps(p_fps_in), p_pe(p_pe_in),   { m_cpmt_root = CalculateCPMTRoot(); }

    uint256 CalculateCPMTRoot() const;
}

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
    CProof proof;
    // Memory-only, used to tell serializer what to serialize
    bool m_serialize_full_cpmt = false;
    // Subsumes the proof field
    ConsensusParameterMerkleTree m_cpmt;

    // Versionbits bit 27 has been redefined to dynamic blocks header version bit
    static const uint32_t DYNAMIC_MASK = (uint32_t)1 << 27;
    // Versionbits bit 26 has been redefined to dynamic blocks full cpmt serialization bit
    static const uint32_t DYNAMIC_TREE_MASK = (uint32_t)1 << 26;

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
            if (this->nVersion & DYNAMIC_TREE_MASK) {
                READWRITE(cpmt);
            } else {
                // FIXME: Need to call different serialization based on mode?
                READWRITE(cpmt.CalculateCPMTRoot());
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
