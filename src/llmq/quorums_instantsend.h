// Copyright (c) 2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CADEX_QUORUMS_INSTANTSEND_H
#define CADEX_QUORUMS_INSTANTSEND_H

#include "quorums_signing.h"

#include "coins.h"
#include "unordered_lru_cache.h"
#include "primitives/transaction.h"

#include <unordered_map>
#include <unordered_set>

namespace llmq
{

class CInstaCADEXLock
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

typedef std::shared_ptr<CInstaCADEXLock> CInstaCADEXLockPtr;

class CInstaCADEXDb
{
private:
    CDBWrapper& db;

    unordered_lru_cache<uint256, CInstaCADEXLockPtr, StaticSaltedHasher, 10000> islockCache;
    unordered_lru_cache<uint256, uint256, StaticSaltedHasher, 10000> txidCache;
    unordered_lru_cache<COutPoint, uint256, SaltedOutpointHasher, 10000> outpointCache;

public:
    CInstaCADEXDb(CDBWrapper& _db) : db(_db) {}

    void WriteNewInstaCADEXLock(const uint256& hash, const CInstaCADEXLock& islock);
    void RemoveInstaCADEXLock(CDBBatch& batch, const uint256& hash, CInstaCADEXLockPtr islock);

    void WriteInstaCADEXLockMined(const uint256& hash, int nHeight);
    void RemoveInstaCADEXLockMined(const uint256& hash, int nHeight);
    void WriteInstaCADEXLockArchived(CDBBatch& batch, const uint256& hash, int nHeight);
    std::unordered_map<uint256, CInstaCADEXLockPtr> RemoveConfirmedInstaCADEXLocks(int nUntilHeight);
    void RemoveArchivedInstaCADEXLocks(int nUntilHeight);
    bool HasArchivedInstaCADEXLock(const uint256& islockHash);
    size_t GetInstaCADEXLockCount();

    CInstaCADEXLockPtr GetInstaCADEXLockByHash(const uint256& hash);
    uint256 GetInstaCADEXLockHashByTxid(const uint256& txid);
    CInstaCADEXLockPtr GetInstaCADEXLockByTxid(const uint256& txid);
    CInstaCADEXLockPtr GetInstaCADEXLockByInput(const COutPoint& outpoint);

    std::vector<uint256> GetInstaCADEXLocksByParent(const uint256& parent);
    std::vector<uint256> RemoveChainedInstaCADEXLocks(const uint256& islockHash, const uint256& txid, int nHeight);
};

class CInstaCADEXManager : public CRecoveredSigsListener
{
private:
    CCriticalSection cs;
    CInstaCADEXDb db;

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
    std::unordered_map<uint256, CInstaCADEXLock, StaticSaltedHasher> creatingInstaCADEXLocks;
    // maps from txid to the in-progress islock
    std::unordered_map<uint256, CInstaCADEXLock*, StaticSaltedHasher> txToCreatingInstaCADEXLocks;

    // Incoming and not verified yet
    std::unordered_map<uint256, std::pair<NodeId, CInstaCADEXLock>> pendingInstaCADEXLocks;

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
    CInstaCADEXManager(CDBWrapper& _llmqDb);
    ~CInstaCADEXManager();

    void Start();
    void Stop();
    void InterruptWorkerThread();

public:
    bool ProcessTx(const CTransaction& tx, const Consensus::Params& params);
    bool CheckCanLock(const CTransaction& tx, bool printDebug, const Consensus::Params& params);
    bool CheckCanLock(const COutPoint& outpoint, bool printDebug, const uint256& txHash, CAmount* retValue, const Consensus::Params& params);
    bool IsLocked(const uint256& txHash);
    bool IsConflicted(const CTransaction& tx);
    CInstaCADEXLockPtr GetConflictingLock(const CTransaction& tx);

    virtual void HandleNewRecoveredSig(const CRecoveredSig& recoveredSig);
    void HandleNewInputLockRecoveredSig(const CRecoveredSig& recoveredSig, const uint256& txid);
    void HandleNewInstaCADEXLockRecoveredSig(const CRecoveredSig& recoveredSig);

    void TrySignInstaCADEXLock(const CTransaction& tx);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    void ProcessMessageInstaCADEXLock(CNode* pfrom, const CInstaCADEXLock& islock, CConnman& connman);
    bool PreVerifyInstaCADEXLock(NodeId nodeId, const CInstaCADEXLock& islock, bool& retBan);
    bool ProcessPendingInstaCADEXLocks();
    std::unordered_set<uint256> ProcessPendingInstaCADEXLocks(int signHeight, const std::unordered_map<uint256, std::pair<NodeId, CInstaCADEXLock>>& pend, bool ban);
    void ProcessInstaCADEXLock(NodeId from, const uint256& hash, const CInstaCADEXLock& islock);
    void UpdateWalletTransaction(const uint256& txid, const CTransactionRef& tx);

    void SyncTransaction(const CTransaction &tx, const CBlockIndex *pindex, int posInBlock);
    void AddNonLockedTx(const CTransactionRef& tx);
    void RemoveNonLockedTx(const uint256& txid, bool retryChildren);
    void RemoveConflictedTx(const CTransaction& tx);

    void NotifyChainLock(const CBlockIndex* pindexChainLock);
    void UpdatedBlockTip(const CBlockIndex* pindexNew);

    void HandleFullyConfirmedBlock(const CBlockIndex* pindex);

    void RemoveMempoolConflictsForLock(const uint256& hash, const CInstaCADEXLock& islock);
    void ResolveBlockConflicts(const uint256& islockHash, const CInstaCADEXLock& islock);
    void RemoveChainLockConflictingLock(const uint256& islockHash, const CInstaCADEXLock& islock);
    void AskNodesForLockedTx(const uint256& txid);
    bool ProcessPendingRetryLockTxs();

    bool AlreadyHave(const CInv& inv);
    bool GetInstaCADEXLockByHash(const uint256& hash, CInstaCADEXLock& ret);

    size_t GetInstaCADEXLockCount();

    void WorkThreadMain();
};

extern CInstaCADEXManager* quorumInstaCADEXManager;

// This involves 2 sporks: SPORK_2_INSTANTSEND_ENABLED and SPORK_20_INSTANTSEND_LLMQ_BASED
// SPORK_2_INSTANTSEND_ENABLED generally enables/disables InstaCADEX and SPORK_20_INSTANTSEND_LLMQ_BASED switches
// between the old and the new (LLMQ based) system
// TODO When the new system is fully deployed and enabled, we can remove this special handling in a future version
// and revert to only using SPORK_2_INSTANTSEND_ENABLED.
bool IsOldInstaCADEXEnabled();
bool IsNewInstaCADEXEnabled();
bool IsInstaCADEXEnabled();

}

#endif//CADEX_QUORUMS_INSTANTSEND_H
