// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <primitives/block.h>
#include <script/interpreter.h>
#include <script/generic.hpp>

bool CheckChallenge(const CBlockHeader& block, const CBlockIndex& indexLast, const Consensus::Params& params)
{
    if (g_signed_blocks) {
        return block.proof.challenge == indexLast.proof.challenge;
    } else {
        return block.nBits == GetNextWorkRequired(&indexLast, &block, params);
    }
}

static bool CheckProofGeneric(const CBlockHeader& block, const uint32_t max_block_signature_size, const CScript& challenge, const CScript& scriptSig, const CScriptWitness& witness)
{
    uint32_t wit_size = witness.GetSerializedSize();

    // scriptSig or witness will be nonempty, but not both
    // Former is for legacy blocksigning, latter for dynamic federations
    assert(scriptSig.empty() != witness.IsNull());

    if (scriptSig.size() > max_block_signature_size) {
        return false;
    }

    if (witness.GetSerializedSize() > max_block_signature_size) {
        return false;
    }

    // Some anti-DoS flags, though consensus.max_block_signature_size caps the possible
    // danger in malleation of the block witness data.
    unsigned int proof_flags = SCRIPT_VERIFY_P2SH // For cleanstack evalution under segwit flag
        | SCRIPT_VERIFY_STRICTENC // Minimally-sized DER sigs
        | SCRIPT_VERIFY_NULLDUMMY // No extra data stuffed into OP_CMS witness
        | SCRIPT_VERIFY_CLEANSTACK // No extra pushes leftover in witness
        | SCRIPT_VERIFY_MINIMALDATA // Pushes are minimally-sized
        | SCRIPT_VERIFY_SIGPUSHONLY // Witness is push-only
        | SCRIPT_VERIFY_LOW_S // Stop easiest signature fiddling
        | SCRIPT_VERIFY_WITNESS // Required for cleanstack eval in VerifyScript
        | SCRIPT_NO_SIGHASH_BYTE; // non-Check(Multi)Sig signatures will not have sighash byte
    return GenericVerifyScript(scriptSig, witness, challenge, proof_flags, block);
}

bool CheckProof(const CBlockHeader& block, const Consensus::Params& params)
{
    if (g_signed_blocks) {
        const DynaFedParams& d_params = block.m_dyna_params;
        if (d_params.IsNull()) {
            return CheckProofGeneric(block, params.max_block_signature_size, params.signblockscript, block.proof.solution);
        } else {
            return CheckProofGeneric(block, d_params.m_current.m_sbs_wit_limit, d_params.m_current.m_signblockscript, CScript(), block.m_signblock_witness);
        }
    } else {
        return CheckProofOfWork(block.GetHash(), block.nBits, params);
    }
}

// TODO DYNAFED: Use RPC to get parent signblockscript
bool CheckProofSignedParent(const CBlockHeader& block, const Consensus::Params& params)
{
    return CheckProofGeneric(block, params.max_block_signature_size, params.parent_chain_signblockscript, block.proof.solution);
}
