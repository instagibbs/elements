// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>


bool g_con_blockheightinheader = false;
bool g_signed_blocks = false;

std::string CProof::ToString() const
{
    return strprintf("CProof(challenge=%s, solution=%s)",
                     HexStr(challenge), HexStr(solution));
}

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, proof=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, proof.ToString(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

uint256 ConsensusParamEntry::CalculateRoot() const
{
    std::vector<uint256> leaves;
    leaves.push_back(SerializeHash(signblockscript, SER_GETHASH, 0));
    leaves.push_back(SerializeHash(sbs_wit_limit, SER_GETHASH, 0));
    leaves.push_back(SerializeHash(fedpegscript, SER_GETHASH, 0));
    leaves.push_back(SerializeHash(pak_entries, SER_GETHASH, 0));
    return ComputeFastMerkleRoot(leaves);
}

uint256 DynaFedParams::CalculateRoot() const
{
    std::vector<uint256> leaves;
    leaves.push_back(m_current.CalculateRoot());
    leaves.push_back(m_proposed.CalculateRoot());
    return ComputeFastMerkleRoot(leaves);
}
