// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "chain.h"
#include "chainparams.h"
#include "reverse_iterator.h"
#include "validation.h"
#include "uint256.h"

#include <stdint.h>


namespace Checkpoints {

    CBlockIndex* GetLastCheckpoint(const CCheckpointData& data)
    {
        LOCK(cs_main);
        const MapCheckpoints& checkpoints = data.mapCheckpoints;

        for (const MapCheckpoints::value_type& i : reverse_iterate(checkpoints))
        {
            const uint256& hash = i.second;
            BlockMap::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return nullptr;
    }

    CBlockIndex const * GetLastCheckPointBlockIndex(const CCheckpointData& data)
    {
         LOCK(cs_main);
         const MapCheckpoints& checkpoints = data.mapCheckpoints;
         auto lastItem = checkpoints.rbegin();

         for(auto it = lastItem; it != checkpoints.rend(); it++) {
             auto t = mapBlockIndex.find(it->second);
             if (t != mapBlockIndex.end())
                 return t->second;
         }
         return nullptr;
     }


     bool GetCheckpointByHeight(const int nHeight, std::vector<CDynamicCheckpointData> &vnCheckPoints) {
         Checkpoints::CDynamicCheckpointDB db;
         std::map<int, CDynamicCheckpointData> mapCheckPoint;
         if(db.LoadCheckPoint(mapCheckPoint))
         {
             auto iterMap = mapCheckPoint.upper_bound(nHeight);
             while (iterMap != mapCheckPoint.end()) {
                 vnCheckPoints.push_back(iterMap->second);
                 ++iterMap;
             }
         }
         return !vnCheckPoints.empty();
     }

    CDynamicCheckpointData::~CDynamicCheckpointData() {
    }

    bool CDynamicCheckpointData::CheckSignature(const CPubKey & pubkey) const {
         CDataStream data(SER_NETWORK, PROTOCOL_VERSION) ;
         data << height << hash;
         uint256 sighash = Hash(data.begin(), data.end());
         if (!pubkey.Verify(sighash, vchSig)) {
             return  error("CDynamicCheckpointData::CheckSignature : verify signature failed");
         }
         return true;
    }

    bool CDynamicCheckpointData::Sign(const CKey & key) {
        CDataStream data(SER_NETWORK, PROTOCOL_VERSION) ;
        data << height << hash;
        uint256 sighash = Hash(data.begin(), data.end());
        if (!key.Sign(sighash, vchSig)) {
            return error("CDynamicCheckpointData::Sign: Unable to sign checkpoint, check private key?");
        }
        return true;
    }

    UniValue CDynamicCheckpointData::ToJsonObj() {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", height));
        obj.push_back(Pair("hash", hash.ToString()));
        obj.push_back(Pair("sig", HexStr(vchSig)));
        return obj;
    }

    CDynamicCheckpointDB::CDynamicCheckpointDB() : db(GetDataDir() / "checkpoint", 0)  {}

    bool CDynamicCheckpointDB::WriteCheckpoint(int height, const CDynamicCheckpointData &data) {
            return  db.Write(std::make_pair('c', height), data);
    }

    bool CDynamicCheckpointDB::ReadCheckpoint(int height, CDynamicCheckpointData &data) {
           return db.Read(std::make_pair('c', height), data);
    }

    bool CDynamicCheckpointDB::ExistCheckpoint(int height) {
        return  db.Exists(std::make_pair('c', height));
    }

    bool CDynamicCheckpointDB::LoadCheckPoint(std::map<int, CDynamicCheckpointData> &values) {
        std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
        pcursor->Seek(std::make_pair('c',0));

        while (pcursor->Valid()) {
            std::pair<char, int > key;
            if (pcursor->GetKey(key) && key.first == 'c') {
                CDynamicCheckpointData data;
                if (pcursor->GetValue(data)) {
                    pcursor->Next();
                    values.insert(std::make_pair(data.GetHeight(),data));
                } else {
                    return error("%s: failed to read value", __func__);
                }
            } else {
                break;
            }
     }

       return values.size() > 0;
    }

} // namespace Checkpoints
