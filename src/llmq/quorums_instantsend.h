// Copyright (c) 2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PAC_QUORUMS_INSTANTSEND_H
#define PAC_QUORUMS_INSTANTSEND_H

#include "quorums_signing.h"

#include "coins.h"
#include "unordered_lru_cache.h"
#include "primitives/transaction.h"

#include <unordered_map>
#include <unordered_set>

namespace llmq
{

class CInstaPACLock
{
public:
    std::vector<COutPoint> inputs;
    uint256 txid;
    CBLSLazySignature sig;

public:
    ADD_SERIALIZE_METHODS

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(inputs);
        READWRITE(txid);
        READWRITE(sig);
    }

    uint256 GetRequestId() const;
};

typedef std::shared_ptr<CInstaPACLock> CInstaPACLockPtr;

class CInstaPACDb
{
private:
    CDBWrapper& db;

    unordered_lru_cache<uint256, CInstaPACLockPtr, StaticSaltedHasher, 10000> islockCache;
    unordered_lru_cache<uint256, uint256, StaticSaltedHasher, 10000> txidCache;
    unordered_lru_cache<COutPoint, uint256, SaltedOutpointHasher, 10000> outpointCache;

public:
    CInstaPACDb(CDBWrapper& _db) : db(_db) {}

    void WriteNewInstaPACLock(const uint256& hash, const CInstaPACLock& islock);
    void RemoveInstaPACLock(CDBBatch& batch, const uint256& hash, CInstaPACLockPtr islock);

    void WriteInstaPACLockMined(const uint256& hash, int nHeight);
    void RemoveInstaPACLockMined(const uint256& hash, int nHeight);
    void WriteInstaPACLockArchived(CDBBatch& batch, const uint256& hash, int nHeight);
    std::unordered_map<uint256, CInstaPACLockPtr> RemoveConfirmedInstaPACLocks(int nUntilHeight);
    void RemoveArchivedInstaPACLocks(int nUntilHeight);
    bool HasArchivedInstaPACLock(const uint256& islockHash);
    size_t GetInstaPACLockCount();

    CInstaPACLockPtr GetInstaPACLockByHash(const uint256& hash);
    uint256 GetInstaPACLockHashByTxid(const uint256& txid);
    CInstaPACLockPtr GetInstaPACLockByTxid(const uint256& txid);
    CInstaPACLockPtr GetInstaPACLockByInput(const COutPoint& outpoint);

    std::vector<uint256> GetInstaPACLocksByParent(const uint256& parent);
    std::vector<uint256> RemoveChainedInstaPACLocks(const uint256& islockHash, const uint256& txid, int nHeight);
};

class CInstaPACManager : public CRecoveredSigsListener
{
private:
    CCriticalSection cs;
    CInstaPACDb db;

    std::thread workThread;
    CThreadInterrupt workInterrupt;

    /**
     * Request ids of inputs that we signed. Used to determine if a recovered signature belongs to an
     * in-progress input lock.
     */
    std::unordered_set<uint256, StaticSaltedHasher> inputRequestIds;

    /**
     * These are the islocks that are currently in the middle of being created. Entries are created when we observed
     * recovered signatures for all inputs of a TX. At the same time, we initiate signing of our sigshare for the islock.
     * When the recovered sig for the islock later arrives, we can finish the islock and propagate it.
     */
    std::unordered_map<uint256, CInstaPACLock, StaticSaltedHasher> creatingInstaPACLocks;
    // maps from txid to the in-progress islock
    std::unordered_map<uint256, CInstaPACLock*, StaticSaltedHasher> txToCreatingInstaPACLocks;

    // Incoming and not verified yet
    std::unordered_map<uint256, std::pair<NodeId, CInstaPACLock>> pendingInstaPACLocks;

    // TXs which are neither IS locked nor ChainLocked. We use this to determine for which TXs we need to retry IS locking
    // of child TXs
    struct NonLockedTxInfo {
        const CBlockIndex* pindexMined{nullptr};
        CTransactionRef tx;
        std::unordered_set<uint256, StaticSaltedHasher> children;
    };
    std::unordered_map<uint256, NonLockedTxInfo, StaticSaltedHasher> nonLockedTxs;
    std::unordered_multimap<uint256, std::pair<uint32_t, uint256>> nonLockedTxsByInputs;

    std::unordered_set<uint256, StaticSaltedHasher> pendingRetryTxs;

public:
    CInstaPACManager(CDBWrapper& _llmqDb);
    ~CInstaPACManager();

    void Start();
    void Stop();
    void InterruptWorkerThread();

public:
    bool ProcessTx(const CTransaction& tx, const Consensus::Params& params);
    bool CheckCanLock(const CTransaction& tx, bool printDebug, const Consensus::Params& params);
    bool CheckCanLock(const COutPoint& outpoint, bool printDebug, const uint256& txHash, CAmount* retValue, const Consensus::Params& params);
    bool IsLocked(const uint256& txHash);
    bool IsConflicted(const CTransaction& tx);
    CInstaPACLockPtr GetConflictingLock(const CTransaction& tx);

    virtual void HandleNewRecoveredSig(const CRecoveredSig& recoveredSig);
    void HandleNewInputLockRecoveredSig(const CRecoveredSig& recoveredSig, const uint256& txid);
    void HandleNewInstaPACLockRecoveredSig(const CRecoveredSig& recoveredSig);

    void TrySignInstaPACLock(const CTransaction& tx);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    void ProcessMessageInstaPACLock(CNode* pfrom, const CInstaPACLock& islock, CConnman& connman);
    bool PreVerifyInstaPACLock(NodeId nodeId, const CInstaPACLock& islock, bool& retBan);
    bool ProcessPendingInstaPACLocks();
    std::unordered_set<uint256> ProcessPendingInstaPACLocks(int signHeight, const std::unordered_map<uint256, std::pair<NodeId, CInstaPACLock>>& pend, bool ban);
    void ProcessInstaPACLock(NodeId from, const uint256& hash, const CInstaPACLock& islock);
    void UpdateWalletTransaction(const uint256& txid, const CTransactionRef& tx);

    void SyncTransaction(const CTransaction &tx, const CBlockIndex *pindex, int posInBlock);
    void AddNonLockedTx(const CTransactionRef& tx);
    void RemoveNonLockedTx(const uint256& txid, bool retryChildren);
    void RemoveConflictedTx(const CTransaction& tx);

    void NotifyChainLock(const CBlockIndex* pindexChainLock);
    void UpdatedBlockTip(const CBlockIndex* pindexNew);

    void HandleFullyConfirmedBlock(const CBlockIndex* pindex);

    void RemoveMempoolConflictsForLock(const uint256& hash, const CInstaPACLock& islock);
    void ResolveBlockConflicts(const uint256& islockHash, const CInstaPACLock& islock);
    void RemoveChainLockConflictingLock(const uint256& islockHash, const CInstaPACLock& islock);
    void AskNodesForLockedTx(const uint256& txid);
    bool ProcessPendingRetryLockTxs();

    bool AlreadyHave(const CInv& inv);
    bool GetInstaPACLockByHash(const uint256& hash, CInstaPACLock& ret);

    size_t GetInstaPACLockCount();

    void WorkThreadMain();
};

extern CInstaPACManager* quorumInstaPACManager;

// This involves 2 sporks: SPORK_2_INSTANTSEND_ENABLED and SPORK_20_INSTANTSEND_LLMQ_BASED
// SPORK_2_INSTANTSEND_ENABLED generally enables/disables InstaPAC and SPORK_20_INSTANTSEND_LLMQ_BASED switches
// between the old and the new (LLMQ based) system
// TODO When the new system is fully deployed and enabled, we can remove this special handling in a future version
// and revert to only using SPORK_2_INSTANTSEND_ENABLED.
bool IsOldInstaPACEnabled();
bool IsNewInstaPACEnabled();
bool IsInstaPACEnabled();

}

#endif//PAC_QUORUMS_INSTANTSEND_H
