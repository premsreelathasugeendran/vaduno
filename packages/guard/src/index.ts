export * from "./types.js";
export { VadunoGuard, ledgerSpendHistory } from "./guard.js";
export type {
  VadunoGuardOptions,
  RevocationCheck,
  RevocationVerdict,
  HydrateReport,
} from "./guard.js";
export { evaluatePolicy, merchantMatches, policyWindows } from "./policy/engine.js";
export {
  RiskScorecard,
  RiskConfigError,
  RiskUnscorableError,
  applyRiskTier,
  anchoredPrefix,
  RISK_SIGNAL_KEYS,
} from "./risk/scorecard.js";
export type {
  RiskAnchor,
  RiskAssessInput,
  RiskAssessment,
  RiskFiredSignal,
  RiskScorecardConfig,
  RiskSignalKey,
  RiskSignalsConfig,
  RiskTier,
  UtcMinuteWindow,
} from "./risk/scorecard.js";
export {
  AuditLedger,
  GENESIS_HASH,
} from "./ledger/ledger.js";
export type {
  EvidenceBundle,
  ExpectedTip,
  LedgerAppendResult,
  LedgerEntry,
  LedgerEntryType,
  LedgerHead,
  LedgerStore,
  LedgerTip,
  VerifyResult,
} from "./ledger/ledger.js";
export { canonicalJson, sha256Hex } from "./ledger/hash.js";
export { MemoryLedgerStore } from "./ledger/stores/memory.js";
export { JsonlLedgerStore } from "./ledger/stores/jsonl.js";
export { SupabaseLedgerStore } from "./ledger/stores/supabase.js";
export type { SupabaseLikeClient } from "./ledger/stores/supabase.js";
export {
  createQueuedApprovalHandler,
  MemoryApprovalStore,
  approvalFingerprint,
} from "./approval/approval.js";
export { FileApprovalStore } from "./approval/file-store.js";
export type {
  ApprovalStore,
  ApprovalDecision,
  PendingApproval,
  QueuedApprovalOptions,
} from "./approval/approval.js";
export {
  MandateManager,
  generateMandateKeyPair,
  mandateContextHash,
  mandateKeyId,
  MANDATE_DOMAIN,
  MANDATE_FORMAT_VERSION,
  MANDATE_ALG,
} from "./mandate/mandate.js";
export type { AnyMandate } from "./mandate/mandate.js";
export {
  MLDSA44_ALG,
  MLDSA44_PUBLIC_KEY_BYTES,
  MLDSA44_SIGNATURE_BYTES,
  PqUnavailableError,
  generateMlDsa44KeyPair,
  mlDsa44Available,
  mlDsa44KeyId,
  mlDsa44SpkiFromRawPublicKey,
  nativeMlDsa44Ops,
  rawMlDsa44PublicKey,
} from "./mandate/pq.js";
export type { MlDsa44KeyPair, MlDsa44Ops } from "./mandate/pq.js";
export {
  MANDATE_V2_ALGS,
  MANDATE_V2_DOMAIN,
  MANDATE_V2_FORMAT_VERSION,
  checkMandateV2Structure,
  mandateV2Payload,
} from "./mandate/hybrid.js";
export type { MandateV2, StructureCheck } from "./mandate/hybrid.js";
export {
  LocalKeySigner,
  checkedSign,
  SignerError,
  SignerTimeoutError,
  SignerVerificationError,
  DEFAULT_SIGN_TIMEOUT_MS,
} from "./mandate/signer.js";
export type { Ed25519Signer, CheckedSignOptions } from "./mandate/signer.js";
export type {
  Mandate,
  MandateCheck,
  MandateConstraints,
  MandateKeyPair,
  ConsumeOutcome,
} from "./mandate/mandate.js";
export { MemoryConsumeStore, intentDigest } from "./enforce/consume-store.js";
export type {
  ConsumeStore,
  ClaimResult,
  StoredOutcome,
  UseClaim,
} from "./enforce/consume-store.js";
export { FileConsumeStore } from "./enforce/file-consume-store.js";
export {
  MemorySpendLimiter,
  firstViolatedWindow,
  merchantKeyOf,
  scopeKey,
  windowConfigError,
} from "./enforce/spend-limiter.js";
export type { SpendRecord } from "./enforce/spend-limiter.js";
export { FileSpendLimiter } from "./enforce/file-spend-limiter.js";
export { FileMutex } from "./enforce/file-mutex.js";
export type { FileMutexOpts } from "./enforce/file-mutex.js";
