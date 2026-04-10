use hex;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use starknet::core::crypto::{ecdsa_sign, ecdsa_verify, Signature};
use starknet_crypto::get_public_key;
use starknet::core::types::Felt;
use std::str::FromStr;

use crate::starknet_messages::{
    AccountId, AssetId, CancelOrder, CreateAccount, Hashable, LimitOrder, OffChainMessage, Order,
    PositionId, SetMarketLeverage,
    StarknetDomain, Timestamp, TransferArgs,
};
pub mod starknet_messages;

pub struct StarkSignature {
    pub r: Felt,
    pub s: Felt,
    pub v: Felt,
}

fn felt_from_bytes(bytes: &[u8; 32]) -> Felt {
    Felt::from_bytes_be(bytes)
}

fn signature_from_bytes(bytes: &[u8; 64]) -> StarkSignature {
    let mut r = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[32..]);
    StarkSignature {
        r: felt_from_bytes(&r),
        s: felt_from_bytes(&s),
        v: Felt::ZERO,
    }
}

fn signature_to_bytes(signature: &StarkSignature) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&signature.r.to_bytes_be());
    out[32..].copy_from_slice(&signature.s.to_bytes_be());
    out
}

fn grind_key(key_seed: BigUint) -> BigUint {
    let two_256 = BigUint::from_str(
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    )
    .unwrap();
    let key_value_limit = BigUint::from_str(
        "3618502788666131213697322783095070105526743751716087489154079457884512865583",
    )
    .unwrap();

    let max_allowed_value = two_256.clone() - (two_256.clone() % (&key_value_limit));
    let mut index = BigUint::ZERO;
    loop {
        let hash_input = {
            let mut input = Vec::new();
            input.extend_from_slice(&key_seed.to_bytes_be());
            input.extend_from_slice(&index.to_bytes_be());
            input
        };
        let hash_result = Sha256::digest(&hash_input);
        let hash = hash_result.as_slice();
        let key = BigUint::from_bytes_be(&hash);

        if key < max_allowed_value {
            return key % (&key_value_limit);
        }

        index += BigUint::from_str("1").unwrap();
    }
}

pub fn grind_private_key_bytes(seed: &[u8]) -> [u8; 32] {
    let key_seed = BigUint::from_bytes_be(seed);
    let private_key = grind_key(key_seed);
    let mut out = [0u8; 32];
    let bytes = private_key.to_bytes_be();
    let start = out.len().saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes);
    out
}

pub fn get_private_key_from_eth_signature(signature: &str) -> Result<Felt, String> {
    let eth_sig_truncated = signature.trim_start_matches("0x");
    if eth_sig_truncated.len() < 64 {
        return Err("Invalid signature length".to_string());
    }
    let r = &eth_sig_truncated[..64];
    let r_bytes = hex::decode(r).map_err(|e| format!("Failed to decode r as hex: {:?}", e))?;
    let key_bytes = grind_private_key_bytes(&r_bytes);
    Ok(felt_from_bytes(&key_bytes))
}

pub fn sign_message(message: &Felt, private_key: &Felt) -> Result<StarkSignature, String> {
    return ecdsa_sign(private_key, &message)
        .map(|extended_signature| StarkSignature {
            r: extended_signature.r,
            s: extended_signature.s,
            v: extended_signature.v,
        })
        .map_err(|e| format!("Failed to sign message: {:?}", e));
}

pub fn sign_message_bytes(
    message: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<[u8; 64], String> {
    let signature = sign_message(&felt_from_bytes(message), &felt_from_bytes(private_key))?;
    Ok(signature_to_bytes(&signature))
}

pub fn verify_message(
    message: &Felt,
    public_key: &Felt,
    signature: &StarkSignature,
) -> Result<bool, String> {
    ecdsa_verify(
        public_key,
        message,
        &Signature {
            r: signature.r,
            s: signature.s,
        },
    )
    .map_err(|e| format!("Failed to verify message: {:?}", e))
}

pub fn verify_message_bytes(
    message: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<bool, String> {
    verify_message(
        &felt_from_bytes(message),
        &felt_from_bytes(public_key),
        &signature_from_bytes(signature),
    )
}

pub fn public_key_from_private_key_bytes(private_key: &[u8; 32]) -> [u8; 32] {
    get_public_key(&felt_from_bytes(private_key)).to_bytes_be()
}

pub fn compute_extended_chain_domain_hash_bytes(chain_domain: &[u8; 32]) -> [u8; 32] {
    crate::starknet_messages::hash_extended_chain_domain(chain_domain).to_bytes_be()
}

fn domain_hash_felt(domain_hash: &[u8; 32]) -> Felt {
    Felt::from_bytes_be(domain_hash)
}

fn finalize_extended_chain_message_hash(
    message_kind: Felt,
    domain_hash: &[u8; 32],
    payload_hash: Felt,
) -> [u8; 32] {
    let mut hasher = starknet_crypto::PoseidonHasher::new();
    hasher.update(message_kind);
    hasher.update(domain_hash_felt(domain_hash));
    hasher.update(payload_hash);
    hasher.finalize().to_bytes_be()
}

pub fn get_extended_chain_order_hash_bytes(
    chain_domain: &[u8; 32],
    account_id: u64,
    nonce_channel: u8,
    nonce: u64,
    base_asset_id: u64,
    base_amount: i64,
    quote_asset_id: u64,
    quote_amount: i64,
    fee_asset_id: u64,
    fee_amount: u64,
    order_type: u8,
    time_in_force: u8,
    expire_ms: u64,
    expiration: u64,
    external_id: [u8; 16],
    post_only: bool,
) -> Result<[u8; 32], String> {
    let domain_hash = compute_extended_chain_domain_hash_bytes(chain_domain);
    get_extended_chain_order_hash_bytes_with_domain_hash(
        &domain_hash,
        account_id,
        nonce_channel,
        nonce,
        base_asset_id,
        base_amount,
        quote_asset_id,
        quote_amount,
        fee_asset_id,
        fee_amount,
        order_type,
        time_in_force,
        expire_ms,
        expiration,
        external_id,
        post_only,
    )
}

pub fn get_extended_chain_order_hash_bytes_with_domain_hash(
    domain_hash: &[u8; 32],
    account_id: u64,
    nonce_channel: u8,
    nonce: u64,
    base_asset_id: u64,
    base_amount: i64,
    quote_asset_id: u64,
    quote_amount: i64,
    fee_asset_id: u64,
    fee_amount: u64,
    order_type: u8,
    time_in_force: u8,
    expire_ms: u64,
    expiration: u64,
    external_id: [u8; 16],
    post_only: bool,
) -> Result<[u8; 32], String> {
    let external_id = Felt::from_hex(&format!("0x{}", hex::encode(external_id)))
        .map_err(|e| format!("Invalid external_id: {:?}", e))?;
    let order = Order {
        account_id: AccountId { value: account_id },
        nonce_channel,
        nonce,
        base_asset_id: AssetId {
            value: base_asset_id.into(),
        },
        base_amount,
        quote_asset_id: AssetId {
            value: quote_asset_id.into(),
        },
        quote_amount,
        fee_asset_id: AssetId {
            value: fee_asset_id.into(),
        },
        fee_amount,
        order_type,
        time_in_force,
        expire_ms,
        expiration: Timestamp {
            seconds: expiration,
        },
        external_id,
        post_only: if post_only { 1 } else { 0 },
    };
    Ok(finalize_extended_chain_message_hash(
        starknet::core::utils::cairo_short_string_to_felt("XC_ORDER").unwrap(),
        domain_hash,
        order.hash(),
    ))
}

pub fn get_extended_chain_cancel_hash_bytes(
    chain_domain: &[u8; 32],
    account_id: u64,
    nonce_channel: u8,
    nonce: u64,
    external_id: [u8; 16],
    order_height: u64,
    order_index: u32,
) -> Result<[u8; 32], String> {
    let domain_hash = compute_extended_chain_domain_hash_bytes(chain_domain);
    get_extended_chain_cancel_hash_bytes_with_domain_hash(
        &domain_hash,
        account_id,
        nonce_channel,
        nonce,
        external_id,
        order_height,
        order_index,
    )
}

pub fn get_extended_chain_cancel_hash_bytes_with_domain_hash(
    domain_hash: &[u8; 32],
    account_id: u64,
    nonce_channel: u8,
    nonce: u64,
    external_id: [u8; 16],
    order_height: u64,
    order_index: u32,
) -> Result<[u8; 32], String> {
    let external_id = Felt::from_hex(&format!("0x{}", hex::encode(external_id)))
        .map_err(|e| format!("Invalid external_id: {:?}", e))?;
    let cancel = CancelOrder {
        account_id: AccountId { value: account_id },
        nonce_channel,
        nonce,
        external_id,
        order_height,
        order_index,
    };
    Ok(finalize_extended_chain_message_hash(
        starknet::core::utils::cairo_short_string_to_felt("XC_CANCEL").unwrap(),
        domain_hash,
        cancel.hash(),
    ))
}

pub fn get_extended_chain_set_market_leverage_hash_bytes(
    chain_domain: &[u8; 32],
    account_id: u64,
    nonce_channel: u8,
    nonce: u64,
    market_id: u64,
    leverage: u32,
) -> Result<[u8; 32], String> {
    let domain_hash = compute_extended_chain_domain_hash_bytes(chain_domain);
    get_extended_chain_set_market_leverage_hash_bytes_with_domain_hash(
        &domain_hash,
        account_id,
        nonce_channel,
        nonce,
        market_id,
        leverage,
    )
}

pub fn get_extended_chain_set_market_leverage_hash_bytes_with_domain_hash(
    domain_hash: &[u8; 32],
    account_id: u64,
    nonce_channel: u8,
    nonce: u64,
    market_id: u64,
    leverage: u32,
) -> Result<[u8; 32], String> {
    let leverage = SetMarketLeverage {
        account_id: AccountId { value: account_id },
        nonce_channel,
        nonce,
        market_id,
        leverage,
    };
    Ok(finalize_extended_chain_message_hash(
        starknet::core::utils::cairo_short_string_to_felt("XC_LEVERAGE").unwrap(),
        domain_hash,
        leverage.hash(),
    ))
}

pub fn get_extended_chain_create_account_hash_bytes(
    chain_domain: &[u8; 32],
    nonce: u64,
    pubkey: [u8; 32],
) -> Result<[u8; 32], String> {
    let domain_hash = compute_extended_chain_domain_hash_bytes(chain_domain);
    get_extended_chain_create_account_hash_bytes_with_domain_hash(&domain_hash, nonce, pubkey)
}

pub fn get_extended_chain_create_account_hash_bytes_with_domain_hash(
    domain_hash: &[u8; 32],
    nonce: u64,
    pubkey: [u8; 32],
) -> Result<[u8; 32], String> {
    let create = CreateAccount {
        nonce,
        pubkey: felt_from_bytes(&pubkey),
    };
    Ok(finalize_extended_chain_message_hash(
        starknet::core::utils::cairo_short_string_to_felt("XC_CREATE").unwrap(),
        domain_hash,
        create.hash(),
    ))
}

fn hash_payload_bytes(payload: &[u8]) -> Felt {
    let mut hasher = starknet_crypto::PoseidonHasher::new();
    hasher.update((payload.len() as u64).into());
    for chunk in payload.chunks(16) {
        let mut limb = [0u8; 16];
        let start = 16 - chunk.len();
        limb[start..].copy_from_slice(chunk);
        hasher.update(u128::from_be_bytes(limb).into());
    }
    hasher.finalize()
}

pub fn get_extended_chain_payload_hash_bytes(
    message_kind: &str,
    chain_domain: &[u8; 32],
    payload: &[u8],
) -> Result<[u8; 32], String> {
    let domain_hash = compute_extended_chain_domain_hash_bytes(chain_domain);
    get_extended_chain_payload_hash_bytes_with_domain_hash(message_kind, &domain_hash, payload)
}

pub fn get_extended_chain_payload_hash_bytes_with_domain_hash(
    message_kind: &str,
    domain_hash: &[u8; 32],
    payload: &[u8],
) -> Result<[u8; 32], String> {
    let message_kind = starknet::core::utils::cairo_short_string_to_felt(message_kind)
        .map_err(|e| format!("Invalid message kind: {:?}", e))?;
    Ok(finalize_extended_chain_message_hash(
        message_kind,
        domain_hash,
        hash_payload_bytes(payload),
    ))
}

fn parse_order_type(order_type: &str) -> Result<u8, String> {
    match order_type.to_ascii_lowercase().as_str() {
        "limit" | "0" => Ok(0),
        "market" | "1" => Ok(1),
        other => Err(format!("Invalid order_type: {}", other)),
    }
}

fn parse_time_in_force(time_in_force: &str) -> Result<u8, String> {
    match time_in_force.to_ascii_lowercase().as_str() {
        "fok" | "fillorkill" | "fill_or_kill" | "0" => Ok(0),
        "fak" | "fillandkill" | "fill_and_kill" | "1" => Ok(1),
        "gtt" | "goodtilltime" | "good_till_time" | "2" => Ok(2),
        other => Err(format!("Invalid time_in_force: {}", other)),
    }
}

fn parse_bool_flag(value: &str, field: &str) -> Result<u8, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(1),
        "false" | "0" => Ok(0),
        other => Err(format!("Invalid {}: {}", field, other)),
    }
}

// these functions are designed to be called from other languages, such as Python or JavaScript,
// so they take string arguments.
pub fn get_order_hash(
    account_id: String,
    nonce_channel: String,
    nonce: String,
    base_asset_id_hex: String,
    base_amount: String,
    quote_asset_id_hex: String,
    quote_amount: String,
    fee_asset_id_hex: String,
    fee_amount: String,
    order_type: String,
    time_in_force: String,
    expire_ms: String,
    expiration: String,
    external_id_hex: String,
    post_only: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let base_asset_id = Felt::from_hex(&base_asset_id_hex)
        .map_err(|e| format!("Invalid base_asset_id_hex: {:?}", e))?;
    let quote_asset_id = Felt::from_hex(&quote_asset_id_hex)
        .map_err(|e| format!("Invalid quote_asset_id_hex: {:?}", e))?;
    let fee_asset_id = Felt::from_hex(&fee_asset_id_hex)
        .map_err(|e| format!("Invalid fee_asset_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let account_id =
        u64::from_str_radix(&account_id, 10).map_err(|e| format!("Invalid account_id: {:?}", e))?;
    let nonce_channel = u8::from_str_radix(&nonce_channel, 10)
        .map_err(|e| format!("Invalid nonce_channel: {:?}", e))?;
    let nonce =
        u64::from_str_radix(&nonce, 10).map_err(|e| format!("Invalid nonce: {:?}", e))?;
    let base_amount = i64::from_str_radix(&base_amount, 10)
        .map_err(|e| format!("Invalid base_amount: {:?}", e))?;
    let quote_amount = i64::from_str_radix(&quote_amount, 10)
        .map_err(|e| format!("Invalid quote_amount: {:?}", e))?;
    let fee_amount =
        u64::from_str_radix(&fee_amount, 10).map_err(|e| format!("Invalid fee_amount: {:?}", e))?;
    let order_type = parse_order_type(&order_type)?;
    let time_in_force = parse_time_in_force(&time_in_force)?;
    let expire_ms =
        u64::from_str_radix(&expire_ms, 10).map_err(|e| format!("Invalid expire_ms: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let external_id = Felt::from_hex(&external_id_hex)
        .map_err(|e| format!("Invalid external_id_hex: {:?}", e))?;
    let post_only = parse_bool_flag(&post_only, "post_only")?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let order = Order {
        account_id: AccountId { value: account_id },
        nonce_channel,
        nonce,
        base_asset_id: AssetId {
            value: base_asset_id,
        },
        base_amount,
        quote_asset_id: AssetId {
            value: quote_asset_id,
        },
        quote_amount,
        fee_asset_id: AssetId {
            value: fee_asset_id,
        },
        fee_amount,
        order_type,
        time_in_force,
        expire_ms,
        expiration: Timestamp {
            seconds: expiration,
        },
        external_id,
        post_only,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };
    order
        .message_hash(&domain, user_key)
        .map_err(|e| format!("Failed to compute message hash: {:?}", e))
}

pub fn get_limit_order_hash(
    source_position_id: String,
    receive_position_id: String,
    base_asset_id_hex: String,
    base_amount: String,
    quote_asset_id_hex: String,
    quote_amount: String,
    fee_asset_id_hex: String,
    fee_amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let base_asset_id = Felt::from_hex(&base_asset_id_hex)
        .map_err(|e| format!("Invalid base_asset_id_hex: {:?}", e))?;
    let quote_asset_id = Felt::from_hex(&quote_asset_id_hex)
        .map_err(|e| format!("Invalid quote_asset_id_hex: {:?}", e))?;
    let fee_asset_id = Felt::from_hex(&fee_asset_id_hex)
        .map_err(|e| format!("Invalid fee_asset_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let source_position_id = u32::from_str_radix(&source_position_id, 10)
        .map_err(|e| format!("Invalid source_position_id: {:?}", e))?;
    let receive_position_id = u32::from_str_radix(&receive_position_id, 10)
        .map_err(|e| format!("Invalid receive_position_id: {:?}", e))?;
    let base_amount = i64::from_str_radix(&base_amount, 10)
        .map_err(|e| format!("Invalid base_amount: {:?}", e))?;
    let quote_amount = i64::from_str_radix(&quote_amount, 10)
        .map_err(|e| format!("Invalid quote_amount: {:?}", e))?;
    let fee_amount =
        u64::from_str_radix(&fee_amount, 10).map_err(|e| format!("Invalid fee_amount: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let salt = u64::from_str_radix(&salt, 10).map_err(|e| format!("Invalid salt: {:?}", e))?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let limit_order = LimitOrder {
        source_position: PositionId {
            value: source_position_id,
        },
        receive_position: PositionId {
            value: receive_position_id,
        },
        base_asset_id: AssetId {
            value: base_asset_id,
        },
        base_amount,
        quote_asset_id: AssetId {
            value: quote_asset_id,
        },
        quote_amount,
        fee_asset_id: AssetId {
            value: fee_asset_id,
        },
        fee_amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt: salt
            .try_into()
            .map_err(|e| format!("Invalid salt vault: {:?}", e))?,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };

    limit_order
        .message_hash(&domain, user_key)
        .map_err(|e| format!("Failed to compute message hash: {:?}", e))
}

pub fn get_transfer_hash(
    recipient_position_id: String,
    sender_position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let collateral_id = Felt::from_hex(&collateral_id_hex)
        .map_err(|e| format!("Invalid collateral_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let recipient = u32::from_str_radix(&recipient_position_id, 10)
        .map_err(|e| format!("Invalid recipient_position_id: {:?}", e))?;
    let position_id = u32::from_str_radix(&sender_position_id, 10)
        .map_err(|e| format!("Invalid sender_position_id: {:?}", e))?;
    let amount =
        u64::from_str_radix(&amount, 10).map_err(|e| format!("Invalid amount: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let salt = Felt::from_dec_str(&salt).map_err(|e| format!("Invalid salt: {:?}", e))?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let transfer_args = TransferArgs {
        recipient: PositionId { value: recipient },
        position_id: PositionId { value: position_id },
        collateral_id: AssetId {
            value: collateral_id,
        },
        amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };
    transfer_args
        .message_hash(&domain, user_key)
        .map_err(|e| format!("Failed to compute message hash: {:?}", e))
}

pub fn get_withdrawal_hash(
    recipient_hex: String,
    position_id: String,
    collateral_id_hex: String,
    amount: String,
    expiration: String,
    salt: String,
    user_public_key_hex: String,
    domain_name: String,
    domain_version: String,
    domain_chain_id: String,
    domain_revision: String,
) -> Result<Felt, String> {
    let collateral_id = Felt::from_hex(&collateral_id_hex)
        .map_err(|e| format!("Invalid collateral_id_hex: {:?}", e))?;
    let user_key = Felt::from_hex(&user_public_key_hex)
        .map_err(|e| format!("Invalid user_public_key_hex: {:?}", e))?;

    let recipient =
        Felt::from_hex(&recipient_hex).map_err(|e| format!("Invalid recipient_hex: {:?}", e))?;
    let position_id = u32::from_str_radix(&position_id, 10)
        .map_err(|e| format!("Invalid position_id: {:?}", e))?;
    let amount =
        u64::from_str_radix(&amount, 10).map_err(|e| format!("Invalid amount: {:?}", e))?;
    let expiration =
        u64::from_str_radix(&expiration, 10).map_err(|e| format!("Invalid expiration: {:?}", e))?;
    let salt = Felt::from_dec_str(&salt).map_err(|e| format!("Invalid salt: {:?}", e))?;
    let revision = u32::from_str_radix(&domain_revision, 10)
        .map_err(|e| format!("Invalid domain_revision: {:?}", e))?;

    let withdrawal_args = starknet_messages::WithdrawalArgs {
        recipient,
        position_id: PositionId { value: position_id },
        collateral_id: AssetId {
            value: collateral_id,
        },
        amount,
        expiration: Timestamp {
            seconds: expiration,
        },
        salt,
    };
    let domain = StarknetDomain {
        name: domain_name,
        version: domain_version,
        chain_id: domain_chain_id,
        revision,
    };
    withdrawal_args
        .message_hash(&domain, user_key)
        .map_err(|e| {
            format!(
                "Failed to compute message hash for withdrawal args: {:?}",
                e
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_private_key_from_eth_signature() {
        let signature = "0x9ef64d5936681edf44b4a7ad713f3bc24065d4039562af03fccf6a08d6996eab367df11439169b417b6a6d8ce81d409edb022597ce193916757c7d5d9cbf97301c";
        let result = get_private_key_from_eth_signature(signature);

        match result {
            Ok(private_key) => {
                assert_eq!(private_key, Felt::from_dec_str("3554363360756768076148116215296798451844584215587910826843139626172125285444").unwrap());
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }

    #[test]
    fn test_get_transfer_msg() {
        let recipient_position_id = "1".to_string();
        let sender_position_id = "2".to_string();
        let collateral_id_hex = "0x3".to_string();
        let amount = "4".to_string();
        let expiration = "5".to_string();
        let salt = "6".to_string();
        let user_public_key_hex =
            "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();

        let result = get_transfer_hash(
            recipient_position_id,
            sender_position_id,
            collateral_id_hex,
            amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );

        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_hex(
                        "0x56c7b21d13b79a33d7700dda20e22246c25e89818249504148174f527fc3f8f"
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }

    #[test]
    fn test_get_order_hash() {
        let account_id = "100".to_string();
        let nonce_channel = "2".to_string();
        let nonce = "12345".to_string();
        let base_asset_id_hex = "0x2".to_string();
        let base_amount = "100".to_string();
        let quote_asset_id_hex = "0x1".to_string();
        let quote_amount = "-156".to_string();
        let fee_asset_id_hex = "0x1".to_string();
        let fee_amount = "74".to_string();
        let order_type = "limit".to_string();
        let time_in_force = "gtt".to_string();
        let expire_ms = "1710000000123".to_string();
        let expiration = "100".to_string();
        let external_id_hex = "0x1234567890abcdef1234567890abcdef".to_string();
        let post_only = "true".to_string();
        let user_public_key_hex =
            "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();

        let result = get_order_hash(
            account_id,
            nonce_channel,
            nonce,
            base_asset_id_hex,
            base_amount,
            quote_asset_id_hex,
            quote_amount,
            fee_asset_id_hex,
            fee_amount,
            order_type,
            time_in_force,
            expire_ms,
            expiration,
            external_id_hex,
            post_only,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );

        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_hex(
                        "0x30ff9c73aed80578dc5ab06db65ee140e0dfbb0d7b7d2adff5f6e9f808723fa",
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }

    #[test]
    fn test_get_extended_chain_order_hash_bytes() {
        let result = get_extended_chain_order_hash_bytes(
            &[0xAB; 32],
            100,
            2,
            12345,
            2,
            100,
            1,
            -156,
            1,
            74,
            0,
            2,
            1_710_000_000_123,
            1_710_086_400,
            [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
            true,
        );

        match result {
            Ok(hash) => assert_eq!(
                hash,
                [
                    0x00, 0xab, 0xac, 0x8c, 0x39, 0x69, 0x12, 0xc9, 0x15, 0x7b, 0xe3, 0xfa,
                    0x6e, 0xad, 0x6c, 0x4a, 0x34, 0x64, 0x70, 0xf7, 0xd0, 0xd3, 0xad, 0x73,
                    0xf6, 0x75, 0x37, 0xfd, 0x8e, 0x9c, 0x3d, 0x6b,
                ]
            ),
            Err(err) => panic!("Expected Ok, got Err: {}", err),
        }
    }

    #[test]
    fn test_get_extended_chain_cancel_hash_bytes() {
        let result = get_extended_chain_cancel_hash_bytes(
            &[0xAB; 32],
            100,
            2,
            12345,
            [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
            77,
            9,
        );

        match result {
            Ok(hash) => assert_eq!(
                hash,
                [
                    0x05, 0xd6, 0xb1, 0xe0, 0xa0, 0x6f, 0xb9, 0x75, 0x00, 0x66, 0xaf, 0x2e,
                    0x68, 0xaf, 0x5c, 0x4a, 0x2e, 0xc9, 0xcb, 0x64, 0x86, 0xf4, 0xac, 0xe5,
                    0x40, 0x8c, 0xc8, 0x7d, 0xa1, 0x48, 0x96, 0x87,
                ]
            ),
            Err(err) => panic!("Expected Ok, got Err: {}", err),
        }
    }

    #[test]
    fn test_get_extended_chain_set_market_leverage_hash_bytes() {
        let result = get_extended_chain_set_market_leverage_hash_bytes(
            &[0xAB; 32],
            100,
            2,
            12345,
            7,
            20480,
        );

        match result {
            Ok(hash) => assert_eq!(
                hash,
                [
                    0x06, 0xa4, 0xcc, 0x5e, 0xc4, 0x37, 0xd2, 0x34, 0xf2, 0x3f, 0xf9, 0xbe,
                    0x1b, 0xe9, 0x0d, 0x36, 0xff, 0xf8, 0xa1, 0x78, 0x5d, 0x14, 0xc2, 0x5a,
                    0x34, 0xac, 0xa6, 0x5e, 0xb7, 0xf9, 0x0f, 0x7a,
                ]
            ),
            Err(err) => panic!("Expected Ok, got Err: {}", err),
        }
    }

    #[test]
    fn test_get_extended_chain_create_account_hash_bytes() {
        let result = get_extended_chain_create_account_hash_bytes(
            &[0xAB; 32],
            12345,
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
                0x90, 0xab, 0xcd, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            ],
        );

        match result {
            Ok(hash) => assert_eq!(
                hash,
                [
                    0x07, 0x0e, 0xf3, 0x52, 0xae, 0x2f, 0x35, 0x87, 0x30, 0x59, 0x98, 0xa6,
                    0x5b, 0xb7, 0x43, 0x9d, 0xf5, 0xbb, 0x9d, 0x6e, 0x62, 0x33, 0xd9, 0xfb,
                    0x5d, 0x50, 0xa5, 0xa9, 0xad, 0xbb, 0x71, 0xf4,
                ]
            ),
            Err(err) => panic!("Expected Ok, got Err: {}", err),
        }
    }

    #[test]
    fn test_get_limit_order_hash() {
        let source_position_id = "100".to_string();
        let receive_position_id = "200".to_string();
        let base_asset_id_hex = "0x2".to_string();
        let base_amount = "100".to_string();
        let quote_asset_id_hex = "0x1".to_string();
        let quote_amount = "-156".to_string();
        let fee_asset_id_hex = "0x1".to_string();
        let fee_amount = "74".to_string();
        let expiration = "100".to_string();
        let salt = "123".to_string();
        let user_public_key_hex =
            "0x5d05989e9302dcebc74e241001e3e3ac3f4402ccf2f8e6f74b034b07ad6a904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();

        let result = get_limit_order_hash(
            source_position_id,
            receive_position_id,
            base_asset_id_hex,
            base_amount,
            quote_asset_id_hex,
            quote_amount,
            fee_asset_id_hex,
            fee_amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );

        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_hex(
                        "0xa3740f996ec1fbbe00ba85be37b00fc4f5c3ae3958bcc3081fb731eb7a3c59"
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }

    #[test]
    fn test_get_withdrawal_hash() {
        let recipient_hex = Felt::from_dec_str(
            "206642948138484946401984817000601902748248360221625950604253680558965863254",
        )
        .unwrap()
        .to_hex_string();
        let position_id = "2".to_string();
        let collateral_id_hex = Felt::from_dec_str(
            "1386727789535574059419576650469753513512158569780862144831829362722992755422",
        )
        .unwrap()
        .to_hex_string();
        let amount = "1000".to_string();
        let expiration = "0".to_string();
        let salt = "0".to_string();
        let user_public_key_hex =
            "0x5D05989E9302DCEBC74E241001E3E3AC3F4402CCF2F8E6F74B034B07AD6A904".to_string();
        let domain_name = "Perpetuals".to_string();
        let domain_version = "v0".to_string();
        let domain_chain_id = "SN_SEPOLIA".to_string();
        let domain_revision = "1".to_string();
        let result = get_withdrawal_hash(
            recipient_hex,
            position_id,
            collateral_id_hex,
            amount,
            expiration,
            salt,
            user_public_key_hex,
            domain_name,
            domain_version,
            domain_chain_id,
            domain_revision,
        );
        match result {
            Ok(hash) => {
                assert_eq!(
                    hash,
                    Felt::from_dec_str(
                        "2182119571682827544073774098906745929330860211691330979324731407862023927178"
                    )
                    .unwrap()
                );
            }
            Err(err) => {
                panic!("Expected Ok, got Err: {}", err);
            }
        }
    }
}
