use starknet::core::utils::cairo_short_string_to_felt;

use starknet::core::types::Felt;
use starknet::macros::selector;
use starknet_crypto::PoseidonHasher;

use std::sync::LazyLock;

static MESSAGE_FELT: LazyLock<Felt> =
    LazyLock::new(|| cairo_short_string_to_felt("StarkNet Message").unwrap());
static EXTENDED_CHAIN_DOMAIN_FELT: LazyLock<Felt> =
    LazyLock::new(|| cairo_short_string_to_felt("XC_DOMAIN").unwrap());

pub trait Hashable {
    const SELECTOR: Felt;
    fn hash(&self) -> Felt;
}

pub trait OffChainMessage: Hashable {
    fn message_hash(
        &self,
        stark_domain: &StarknetDomain,
        public_key: Felt,
    ) -> Result<Felt, String> {
        let mut hasher = PoseidonHasher::new();
        hasher.update(*MESSAGE_FELT);
        hasher.update(stark_domain.hash());
        hasher.update(public_key);
        hasher.update(self.hash());
        Ok(hasher.finalize())
    }
}

pub struct StarknetDomain {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub revision: u32,
}

impl Hashable for StarknetDomain {
    const SELECTOR: Felt = selector!("\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(cairo_short_string_to_felt(&self.name).unwrap());
        hasher.update(cairo_short_string_to_felt(&self.version).unwrap());
        hasher.update(cairo_short_string_to_felt(&self.chain_id).unwrap());
        hasher.update(self.revision.into());
        let hash = hasher.finalize();
        return hash;
    }
}

pub struct AssetId {
    pub value: Felt,
}
pub struct AccountId {
    pub value: u64,
}
pub struct PositionId {
    pub value: u32,
}

pub struct AssetAmount {
    pub asset_id: AssetId,
    pub amount: i64,
}

pub struct Timestamp {
    pub seconds: u64,
}

pub struct Order {
    pub account_id: AccountId,
    pub nonce_channel: u8,
    pub nonce: u64,
    pub base_asset_id: AssetId,
    pub base_amount: i64,
    pub quote_asset_id: AssetId,
    pub quote_amount: i64,
    pub fee_asset_id: AssetId,
    pub fee_amount: u64,
    pub order_type: u8,
    pub time_in_force: u8,
    pub expire_ms: u64,
    pub expiration: Timestamp,
    pub external_id: Felt,
    pub post_only: u8,
}

pub struct CancelOrder {
    pub account_id: AccountId,
    pub nonce_channel: u8,
    pub nonce: u64,
    pub external_id: Felt,
    pub order_height: u64,
    pub order_index: u32,
}

pub struct SetMarketLeverage {
    pub account_id: AccountId,
    pub nonce_channel: u8,
    pub nonce: u64,
    pub market_id: u64,
    pub leverage: u32,
}

pub struct LiquidationRequest {
    pub account_id: AccountId,
    pub nonce_channel: u8,
    pub nonce: u64,
    pub target_account_id: AccountId,
    pub external_id: Felt,
}

impl Hashable for LiquidationRequest {
    const SELECTOR: Felt = selector!(
        "\"LiquidationRequest\"(\"account_id\":\"AccountId\",\"nonce_channel\":\"u8\",\"nonce\":\"u64\",\"target_account_id\":\"AccountId\",\"external_id\":\"felt\")\"AccountId\"(\"value\":\"u64\")"
    );
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.account_id.value.into());
        hasher.update(self.nonce_channel.into());
        hasher.update(self.nonce.into());
        hasher.update(self.target_account_id.value.into());
        hasher.update(self.external_id);
        hasher.finalize()
    }
}

impl OffChainMessage for LiquidationRequest {}

pub struct CreateAccount {
    pub nonce: u64,
    pub pubkey: Felt,
}

pub struct LimitOrder {
    pub source_position: PositionId,
    pub receive_position: PositionId,
    // The asset to be bought or sold.
    pub base_asset_id: AssetId,
    // The amount of the asset to be bought or sold.
    pub base_amount: i64,
    // The collateral asset.
    pub quote_asset_id: AssetId,
    // The amount of the collateral asset to be paid or received.
    pub quote_amount: i64,
    // The collateral asset.
    pub fee_asset_id: AssetId,
    // The amount of the collateral asset to be paid.
    pub fee_amount: u64,
    // The expiration time of the order.
    pub expiration: Timestamp,
    // A random value to make each order unique.
    pub salt: Felt,
}

impl Hashable for LimitOrder {
    const SELECTOR: Felt = selector!(
            "\"LimitOrder\"(\"source_position\":\"PositionId\",\"receive_position\":\"PositionId\",\"base_asset_id\":\"AssetId\",\"base_amount\":\"i64\",\"quote_asset_id\":\"AssetId\",\"quote_amount\":\"i64\",\"fee_asset_id\":\"AssetId\",\"fee_amount\":\"u64\",\"expiration\":\"Timestamp\",\"salt\":\"felt\")\"PositionId\"(\"value\":\"u32\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")"
        );

    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.source_position.value.into());
        hasher.update(self.receive_position.value.into());
        hasher.update(self.base_asset_id.value.into());
        hasher.update(self.base_amount.into());
        hasher.update(self.quote_asset_id.value.into());
        hasher.update(self.quote_amount.into());
        hasher.update(self.fee_asset_id.value.into());
        hasher.update(self.fee_amount.into());
        hasher.update(self.expiration.seconds.into());
        hasher.update(self.salt);
        hasher.finalize()
    }
}

impl OffChainMessage for LimitOrder {}

impl Hashable for Order {
    const SELECTOR: Felt = selector!("\"Order\"(\"account_id\":\"AccountId\",\"nonce_channel\":\"u8\",\"nonce\":\"u64\",\"base_asset_id\":\"AssetId\",\"base_amount\":\"i64\",\"quote_asset_id\":\"AssetId\",\"quote_amount\":\"i64\",\"fee_asset_id\":\"AssetId\",\"fee_amount\":\"u64\",\"order_type\":\"u8\",\"time_in_force\":\"u8\",\"expire_ms\":\"u64\",\"expiration\":\"Timestamp\",\"external_id\":\"felt\",\"post_only\":\"u8\")\"AccountId\"(\"value\":\"u64\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.account_id.value.into());
        hasher.update(self.nonce_channel.into());
        hasher.update(self.nonce.into());
        hasher.update(self.base_asset_id.value.into());
        hasher.update(self.base_amount.into());
        hasher.update(self.quote_asset_id.value.into());
        hasher.update(self.quote_amount.into());
        hasher.update(self.fee_asset_id.value.into());
        hasher.update(self.fee_amount.into());
        hasher.update(self.order_type.into());
        hasher.update(self.time_in_force.into());
        hasher.update(self.expire_ms.into());
        hasher.update(self.expiration.seconds.into());
        hasher.update(self.external_id);
        hasher.update(self.post_only.into());
        hasher.finalize()
    }
}
impl OffChainMessage for Order {}

impl Hashable for CancelOrder {
    const SELECTOR: Felt = selector!("\"CancelOrder\"(\"account_id\":\"AccountId\",\"nonce_channel\":\"u8\",\"nonce\":\"u64\",\"external_id\":\"felt\",\"order_height\":\"u64\",\"order_index\":\"u32\")\"AccountId\"(\"value\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.account_id.value.into());
        hasher.update(self.nonce_channel.into());
        hasher.update(self.nonce.into());
        hasher.update(self.external_id);
        hasher.update(self.order_height.into());
        hasher.update(self.order_index.into());
        hasher.finalize()
    }
}

impl Hashable for SetMarketLeverage {
    const SELECTOR: Felt = selector!("\"SetMarketLeverage\"(\"account_id\":\"AccountId\",\"nonce_channel\":\"u8\",\"nonce\":\"u64\",\"market_id\":\"u64\",\"leverage\":\"u32\")\"AccountId\"(\"value\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.account_id.value.into());
        hasher.update(self.nonce_channel.into());
        hasher.update(self.nonce.into());
        hasher.update(self.market_id.into());
        hasher.update(self.leverage.into());
        hasher.finalize()
    }
}

pub struct Noop {
    pub account_id: AccountId,
    pub nonce_channel: u8,
    pub nonce: u64,
}

impl Hashable for Noop {
    const SELECTOR: Felt = selector!("\"Noop\"(\"account_id\":\"AccountId\",\"nonce_channel\":\"u8\",\"nonce\":\"u64\")\"AccountId\"(\"value\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.account_id.value.into());
        hasher.update(self.nonce_channel.into());
        hasher.update(self.nonce.into());
        hasher.finalize()
    }
}

impl OffChainMessage for Noop {}

impl Hashable for CreateAccount {
    const SELECTOR: Felt =
        selector!("\"CreateAccount\"(\"nonce\":\"u64\",\"pubkey\":\"felt\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.nonce.into());
        hasher.update(self.pubkey);
        hasher.finalize()
    }
}

fn split_u256_be(bytes: &[u8; 32]) -> (u128, u128) {
    let mut hi = [0u8; 16];
    hi.copy_from_slice(&bytes[..16]);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&bytes[16..]);
    (u128::from_be_bytes(hi), u128::from_be_bytes(lo))
}

pub fn hash_extended_chain_domain(chain_domain: &[u8; 32]) -> Felt {
    let (hi, lo) = split_u256_be(chain_domain);
    let mut hasher = PoseidonHasher::new();
    hasher.update(*EXTENDED_CHAIN_DOMAIN_FELT);
    hasher.update(hi.into());
    hasher.update(lo.into());
    hasher.finalize()
}

impl OffChainMessage for CancelOrder {}
impl OffChainMessage for SetMarketLeverage {}
impl OffChainMessage for CreateAccount {}

pub struct TransferArgs {
    pub recipient: PositionId,
    pub position_id: PositionId,
    pub collateral_id: AssetId,
    pub amount: u64,
    pub expiration: Timestamp,
    pub salt: Felt,
}

impl Hashable for TransferArgs {
    const SELECTOR: Felt = selector!("\"TransferArgs\"(\"recipient\":\"PositionId\",\"position_id\":\"PositionId\",\"collateral_id\":\"AssetId\",\"amount\":\"u64\",\"expiration\":\"Timestamp\",\"salt\":\"felt\")\"PositionId\"(\"value\":\"u32\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.recipient.value.into());
        hasher.update(self.position_id.value.into());
        hasher.update(self.collateral_id.value.into());
        hasher.update(self.amount.into());
        hasher.update(self.expiration.seconds.into());
        hasher.update(self.salt);
        hasher.finalize()
    }
}

impl OffChainMessage for TransferArgs {}

pub static SEPOLIA_DOMAIN: LazyLock<StarknetDomain> = LazyLock::new(|| StarknetDomain {
    name: "Perpetuals".to_string(),
    version: "v0".to_string(),
    chain_id: "SN_SEPOLIA".to_string(),
    revision: 1,
});

pub struct WithdrawalArgs {
    pub recipient: Felt,
    pub position_id: PositionId,
    pub collateral_id: AssetId,
    pub amount: u64,
    pub expiration: Timestamp,
    pub salt: Felt,
}

impl Hashable for WithdrawalArgs {
    const SELECTOR: Felt = selector!( "\"WithdrawArgs\"(\"recipient\":\"ContractAddress\",\"position_id\":\"PositionId\",\"collateral_id\":\"AssetId\",\"amount\":\"u64\",\"expiration\":\"Timestamp\",\"salt\":\"felt\")\"PositionId\"(\"value\":\"u32\")\"AssetId\"(\"value\":\"felt\")\"Timestamp\"(\"seconds\":\"u64\")");
    fn hash(&self) -> Felt {
        let mut hasher = PoseidonHasher::new();
        hasher.update(Self::SELECTOR);
        hasher.update(self.recipient);
        hasher.update(self.position_id.value.into());
        hasher.update(self.collateral_id.value.into());
        hasher.update(self.amount.into());
        hasher.update(self.expiration.seconds.into());
        hasher.update(self.salt);
        hasher.finalize()
    }
}

impl OffChainMessage for WithdrawalArgs {}

#[cfg(test)]
mod tests {
    use starknet::macros::{felt, felt_hex};

    use super::*;

    #[test]
    fn test_starknet_domain_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210",
        );
        let actual = StarknetDomain::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_starknet_domain_hashing() {
        let domain = StarknetDomain {
            name: "Perpetuals".to_string(),
            version: "v0".to_string(),
            chain_id: "SN_SEPOLIA".to_string(),
            revision: 1,
        };

        let actual = domain.hash();
        let expected =
            felt!("2788850828067604540663615870177667078542240404906059806659101905868929188327");
        assert_eq!(actual, expected, "Hashes do not match for StarknetDomain");
    }

    #[test]
    fn test_order_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x2b4ba53d8bef33971c375421494fa598b7130ab750baa784dc570a667ea9b96",
        );
        let actual = Order::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_transfer_args_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x1db88e2709fdf2c59e651d141c3296a42b209ce770871b40413ea109846a3b4",
        );
        let actual = TransferArgs::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_transfer_args_hashing() {
        let transfer_args = TransferArgs {
            recipient: PositionId { value: 1 },
            position_id: PositionId { value: 2 },
            collateral_id: AssetId {
                value: Felt::from_dec_str("3").unwrap(),
            },
            amount: 4,
            expiration: Timestamp { seconds: 5 },
            salt: Felt::from_dec_str("6").unwrap(),
        };

        let actual = transfer_args.hash();
        let expected = Felt::from_dec_str(
            "2223969487713427665389808888239017784545324676732964616876966103908214316949",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for TransferArgs");
    }

    #[test]
    fn test_message_hash_transfer() {
        let transfer_args = TransferArgs {
            recipient: PositionId { value: 1 },
            position_id: PositionId { value: 2 },
            collateral_id: AssetId {
                value: Felt::from_dec_str("3").unwrap(),
            },
            amount: 4,
            expiration: Timestamp { seconds: 5 },
            salt: Felt::from_dec_str("6").unwrap(),
        };

        let user_key = Felt::from_dec_str(
            "2629686405885377265612250192330550814166101744721025672593857097107510831364",
        )
        .unwrap();

        let actual = transfer_args
            .message_hash(&SEPOLIA_DOMAIN, user_key)
            .unwrap();

        let expected =
            felt_hex!("0x56c7b21d13b79a33d7700dda20e22246c25e89818249504148174f527fc3f8f");
        assert_eq!(actual, expected, "Hashes do not match for TransferArgs");
    }

    #[test]
    fn test_order_hashing() {
        let order = Order {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            base_asset_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            base_amount: 5,
            quote_asset_id: AssetId {
                value: Felt::from_dec_str("6").unwrap(),
            },
            quote_amount: 7,
            fee_asset_id: AssetId {
                value: Felt::from_dec_str("8").unwrap(),
            },
            fee_amount: 9,
            order_type: 0,
            time_in_force: 2,
            expire_ms: 10,
            expiration: Timestamp { seconds: 11 },
            external_id: Felt::from_dec_str("12").unwrap(),
            post_only: 1,
        };

        let actual = order.hash();
        let expected = Felt::from_hex(
            "0x6347c3aeb4691827d871497d1a0751db0a703d4b2d572b6539c2a3b328c43d1",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for Order");
    }

    #[test]
    fn test_message_hash_order() {
        let order = Order {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            base_asset_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            base_amount: 5,
            quote_asset_id: AssetId {
                value: Felt::from_dec_str("6").unwrap(),
            },
            quote_amount: 7,
            fee_asset_id: AssetId {
                value: Felt::from_dec_str("8").unwrap(),
            },
            fee_amount: 9,
            order_type: 0,
            time_in_force: 2,
            expire_ms: 10,
            expiration: Timestamp { seconds: 11 },
            external_id: Felt::from_dec_str("12").unwrap(),
            post_only: 1,
        };

        let user_key = Felt::from_dec_str(
            "1528491859474308181214583355362479091084733880193869257167008343298409336538",
        )
        .unwrap();

        let hash = order.message_hash(&SEPOLIA_DOMAIN, user_key).unwrap();
        let expected_hash = Felt::from_hex(
            "0x797098c0fa2dd0099012f61b5b187b670bb525a385780146c2dda7b95b75187",
        )
        .unwrap();
        println!("{}", expected_hash.to_hex_string());
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_offchain_message_hash_order() {
        let order = Order {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            base_asset_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            base_amount: 5,
            quote_asset_id: AssetId {
                value: Felt::from_dec_str("6").unwrap(),
            },
            quote_amount: 7,
            fee_asset_id: AssetId {
                value: Felt::from_dec_str("8").unwrap(),
            },
            fee_amount: 9,
            order_type: 0,
            time_in_force: 2,
            expire_ms: 10,
            expiration: Timestamp { seconds: 11 },
            external_id: Felt::from_dec_str("12").unwrap(),
            post_only: 1,
        };

        let pubkey = Felt::from(42u64);
        let h1 = order.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        let h2 = order.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        assert_eq!(h1, h2, "OffChainMessage hash must be deterministic");
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_cancel_order_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x283fc2e63c8532d83f52a98dab59b2fa49aa5da4d727e9066b3b9b9e25e94c8",
        );
        let actual = CancelOrder::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_cancel_order_hashing() {
        let cancel = CancelOrder {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            external_id: Felt::from_dec_str("4").unwrap(),
            order_height: 5,
            order_index: 6,
        };

        let actual = cancel.hash();
        let expected = Felt::from_hex(
            "0x1a068e15b5f3d74d5c74497d6abab4fa743f043559b98f0b72ef50f13ae4f87",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for CancelOrder");
    }

    #[test]
    fn test_offchain_message_hash_cancel_order() {
        let cancel = CancelOrder {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            external_id: Felt::from_dec_str("4").unwrap(),
            order_height: 5,
            order_index: 6,
        };

        let pubkey = Felt::from(42u64);
        let h1 = cancel.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        let h2 = cancel.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_set_market_leverage_selector() {
        let expected = Felt::from_hex(
            "0x1653fa9cb360f32c1bedee7f42356fbc3d49edb672d50788b997e8b71f245aa",
        )
        .unwrap();
        let actual = SetMarketLeverage::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_set_market_leverage_hashing() {
        let leverage = SetMarketLeverage {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            market_id: 4,
            leverage: 5,
        };

        let actual = leverage.hash();
        let expected = Felt::from_hex(
            "0x7b2055a0e761f8b867f6d35ac6ad429d1fb7bcba92fd09636eba8ba74ea625f",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for SetMarketLeverage");
    }

    #[test]
    fn test_offchain_message_hash_set_market_leverage() {
        let leverage = SetMarketLeverage {
            account_id: AccountId { value: 1 },
            nonce_channel: 2,
            nonce: 3,
            market_id: 4,
            leverage: 5,
        };

        let pubkey = Felt::from(42u64);
        let h1 = leverage.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        let h2 = leverage.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_create_account_selector() {
        let expected = Felt::from_hex(
            "0x37f447105570862eed0258dec5bfd4c87b3461d3bd81ab2da0b3296c267bcd5",
        )
        .unwrap();
        let actual = CreateAccount::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_create_account_hashing() {
        let create = CreateAccount {
            nonce: 1,
            pubkey: Felt::from(2u64),
        };

        let actual = create.hash();
        let expected = Felt::from_hex(
            "0x7fac07aa3cdcfa9520b7b5209eeb32700c83c8a24fa4e2e515ee50a920bb25",
        )
        .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for CreateAccount");
    }

    #[test]
    fn test_offchain_message_hash_create_account() {
        let create = CreateAccount {
            nonce: 1,
            pubkey: Felt::from(2u64),
        };

        let pubkey = Felt::from(42u64);
        let h1 = create.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        let h2 = create.message_hash(&SEPOLIA_DOMAIN, pubkey).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, Felt::ZERO);
    }

    #[test]
    fn test_withdrawal_args_selector() {
        let expected = Felt::from_hex_unchecked(
            "0x250a5fa378e8b771654bd43dcb34844534f9d1e29e16b14760d7936ea7f4b1d",
        );
        let actual = WithdrawalArgs::SELECTOR;
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_withdrawal_args_hashing() {
        let withdrawal_args = WithdrawalArgs {
            recipient: Felt::from_hex(
                "0x019ec96d4aea6fdc6f0b5f393fec3f186aefa8f0b8356f43d07b921ff48aa5da",
            )
            .unwrap(),
            position_id: PositionId { value: 1 },
            collateral_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            amount: 1000,
            expiration: Timestamp { seconds: 5 },
            salt: Felt::from_dec_str("123").unwrap(),
        };

        let actual = withdrawal_args.hash();
        let expected =
            Felt::from_hex("0x04c22f625c59651e1219c60d03055f11f5dc23959929de35861548d86c0bc4ec")
                .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for WithdrawalArgs");
    }

    #[test]
    fn test_limit_order_hashing() {
        let limit_order = LimitOrder {
            source_position: PositionId { value: 1 },
            receive_position: PositionId { value: 2 },
            base_asset_id: AssetId {
                value: Felt::from_dec_str("2").unwrap(),
            },
            base_amount: 3,
            quote_asset_id: AssetId {
                value: Felt::from_dec_str("4").unwrap(),
            },
            quote_amount: 5,
            fee_asset_id: AssetId {
                value: Felt::from_dec_str("6").unwrap(),
            },
            fee_amount: 7,
            expiration: Timestamp { seconds: 8 },
            salt: Felt::from_dec_str("9").unwrap(),
        };

        let actual = limit_order.hash();
        let expected =
            Felt::from_hex("0x6344a601c7665a748259e9535e66cc753eb88ad28f9bb1419906e8bf2c1edf2")
                .unwrap();
        assert_eq!(actual, expected, "Hashes do not match for LimitOrder");
    }
}
