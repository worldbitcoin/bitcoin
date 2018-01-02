// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKPOINTS_H
#define BITCOIN_CHECKPOINTS_H

#include "uint256.h"
#include "key.h"
#include "dbwrapper.h"

#include <map>
#include <univalue/include/univalue.h>

class CBlockIndex;
struct CCheckpointData;

/**
 * Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{

//! Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
CBlockIndex* GetLastCheckpoint(const CCheckpointData& data);

CBlockIndex const * GetLastCheckPointBlockIndex(const CCheckpointData& data);

class CDynamicCheckpointData {
    private:
        int height;
        uint256 hash;
        std::vector<unsigned char> vchSig;
    public :
        CDynamicCheckpointData(){};
        CDynamicCheckpointData(const int &nHeight, const uint256 &blockHash) : height(nHeight), hash(blockHash){
        }
        virtual ~CDynamicCheckpointData();
        bool CheckSignature(const CPubKey & pubkey) const;
        bool Sign(const CKey & key);
        UniValue ToJsonObj();
        ADD_SERIALIZE_METHODS;
        template<typename Stream, typename Operation>
          inline void SerializationOp(Stream &s, Operation ser_action) {
              READWRITE(VARINT(height));
              READWRITE(hash);
              READWRITE(vchSig);
          }
        int GetHeight() const {return height;}
        void SetHeight(const int &heightIn) {height = heightIn;}
        const uint256 &GetHash() const {return hash;}
        void SetHash(const uint256 &blockHash) {hash = blockHash;}
        const std::vector<unsigned char> &GetVchSig() const{return vchSig;}
        void SetVchSig(const std::vector<unsigned char> &vchSigIn){vchSig = vchSigIn;}
};

class CDynamicCheckpointDB {
    public:
        CDynamicCheckpointDB();
        bool WriteCheckpoint(int height, const CDynamicCheckpointData& data);
        bool ReadCheckpoint(int height, CDynamicCheckpointData& data);
        bool ExistCheckpoint(int height);
        bool LoadCheckPoint(std::map<int, CDynamicCheckpointData>& values);

    protected:
        CDBWrapper db;
};

} //namespace Checkpoints

#endif // BITCOIN_CHECKPOINTS_H
