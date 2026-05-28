const shared = @import("shared");

const cost_model = shared.runtime.cost_model;

pub const SIGNATURE_COST = cost_model.SIGNATURE_COST;
pub const WRITE_LOCK_UNITS = cost_model.WRITE_LOCK_UNITS;
pub const COMPUTE_UNIT_TO_US_RATIO = cost_model.COMPUTE_UNIT_TO_US_RATIO;
pub const INSTRUCTION_DATA_BYTES_PER_UNIT = cost_model.INSTRUCTION_DATA_BYTES_PER_UNIT;
pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT = cost_model.DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;
pub const LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K = cost_model.LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K;
pub const ACCOUNT_DATA_COST_PAGE_SIZE = cost_model.ACCOUNT_DATA_COST_PAGE_SIZE;
pub const SIMPLE_VOTE_USAGE_COST = cost_model.SIMPLE_VOTE_USAGE_COST;
pub const TransactionCost = cost_model.TransactionCost;
pub const UsageCostDetails = cost_model.UsageCostDetails;
pub const calculateTransactionCost = cost_model.calculateTransactionCost;
pub const calculateCostForExecutedTransaction = cost_model.calculateCostForExecutedTransaction;
