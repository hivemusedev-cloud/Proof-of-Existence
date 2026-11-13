//! poe-v2 — Version 2, the listed launch (BUILD_FLOW Step 10).
//!
//! Ports of the Liquidity module and Tokenomics Part IV, definition for
//! definition (the kernel's Part K curve law included, which the ledger
//! port had not needed until now):
//!
//! * **The genesis pool**: the reserve on a constant-product curve with
//!   virtual ether `YV` (never paid out), spot never below the genesis
//!   price `P0 = 10^7` wei. Buys clear one at a time or as an order-free
//!   block batch at one price; sales are open only while the pool would
//!   still hold at most the reserve; retirement stops sales and counts
//!   the holdings burned.
//! * **The oracle**: each epoch's price is the mean of its block spots;
//!   the cap price is the highest of the last 8 weekly means, floored at
//!   `P0`; the value cap is `V / pcap` with `V = 0.004 ETH` — at the
//!   genesis price exactly GMAX, the kernel's own grant ceiling.
//! * **The listed launch**: the reserve splits into the curve tranche
//!   `PC` (a quarter of the cap, on its own curve with virtual ether
//!   `YV2`) and the listing tranche `PL` (5%), sold only after a
//!   26-epoch cliff, at most `LRATE` (1% of the tranche) per epoch, at
//!   a price at least the oracle's and the genesis price. Both lanes
//!   share one **allowance** — `10^12 + 3 per 7 granted` — split 5/6 to
//!   the curve and 1/6 to the listing lane, read net of buybacks.
//! * **Bridge lanes**: escrow/wrapped accounting in both directions,
//!   the releaser's fee (1% rounded up, at least 1 unit, at most the
//!   lane cap), per-epoch quotas floored at `QETH`/`QPOE` plus an eighth
//!   of the wrapped/escrow stock.
//!
//! Owed and stated, as in the report: the composition proof (kernel +
//! liquidity + tokenomics as one system) is a Lean-level obligation this
//! crate does not discharge; what is built here is the module itself and
//! its adversarial battery.

use poe_kernel::RESERVE;

/// Virtual ether of the genesis pool: 3,000 ETH in wei (Liq `YV`).
pub const YV: u128 = 3_000_000_000_000_000_000_000;
/// The genesis price: 10^7 wei per coin (Liq `P0`).
pub const P0: u128 = 10_000_000;
/// The value bound of one grant: 0.004 ETH in wei (Liq `V`).
pub const V: u128 = 4_000_000_000_000_000;
/// The oracle's memory in weekly means (Liq `M`).
pub const ORACLE_WEEKS: usize = 8;
/// Ether lane quota floor: 100 ETH in wei (Liq `QETH`).
pub const QETH: u128 = 100_000_000_000_000_000_000;
/// Coin lane quota floor: 10^13 coins, 1% of the cap (Liq `QPOE`).
pub const QPOE: u128 = 10_000_000_000_000;

// -- the curve law (kernel Part K) ---------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pool {
    pub x: u128,
    pub y: u128,
    pub version: u64,
}

/// `floor(a·b / d)` computed through a 256-bit intermediate: pool
/// quantities (virtual ether × trade sizes) overflow u128 long before
/// they overflow the economics.
fn mul_div(a: u128, b: u128, d: u128) -> u128 {
    if d == 0 {
        return 0;
    }
    // 256-bit product in little-endian u64 limbs.
    let a_l = [a as u64, (a >> 64) as u64];
    let b_l = [b as u64, (b >> 64) as u64];
    let mut p = [0u64; 4];
    for i in 0..2 {
        for j in 0..2 {
            let v = a_l[i] as u128 * b_l[j] as u128;
            let mut at = i + j;
            let mut carry = v;
            while carry > 0 && at < 4 {
                let sum = p[at] as u128 + (carry & 0xFFFF_FFFF_FFFF_FFFF);
                p[at] = sum as u64;
                carry = (carry >> 64) + (sum >> 64);
                at += 1;
            }
        }
    }
    // Bitwise long division of the 256-bit product by d.
    let mut rem: [u64; 4] = [0; 4];
    let mut quot: [u64; 4] = [0; 4];
    for bit in (0..256usize).rev() {
        // rem <<= 1, bringing in the product's next bit.
        let mut carry = (p[bit / 64] >> (bit % 64)) & 1;
        for limb in rem.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // rem >= d (d zero-extended to 256 bits)?
        let d_l = [d as u64, (d >> 64) as u64, 0, 0];
        let ge = {
            let mut gt = false;
            let mut lt = false;
            for k in (0..4).rev() {
                if !gt && !lt {
                    if rem[k] > d_l[k] {
                        gt = true;
                    } else if rem[k] < d_l[k] {
                        lt = true;
                    }
                }
            }
            gt || !lt
        };
        if ge {
            let mut borrow = 0u64;
            for k in 0..4 {
                let (v, b1) = rem[k].overflowing_sub(d_l[k]);
                let (v, b2) = v.overflowing_sub(borrow);
                rem[k] = v;
                borrow = (b1 || b2) as u64;
            }
            quot[bit / 64] |= 1u64 << (bit % 64);
        }
    }
    // The quotient of a swap fits u128 (it never exceeds the pool's y);
    // take the low two limbs.
    (quot[0] as u128) | ((quot[1] as u128) << 64)
}

/// Kernel `swapOut`: the floor of `y·dx/(x+dx)`.
pub fn swap_out(p: &Pool, dx: u128) -> u128 {
    let den = p.x.saturating_add(dx);
    if den == 0 {
        0
    } else {
        mul_div(p.y, dx, den)
    }
}

pub fn swap_pool(p: &Pool, dx: u128) -> Pool {
    Pool { x: p.x + dx, y: p.y - swap_out(p, dx), version: p.version + 1 }
}

fn shares(out: u128, total: u128, ds: &[u128]) -> Vec<u128> {
    if total == 0 {
        return ds.iter().map(|_| 0).collect();
    }
    ds.iter().map(|d| out * d / total).collect()
}

/// Kernel `batchShares` / `batchPool`: a block's buys clear as one swap
/// of their total; each intent receives the floor of its pro-rata share;
/// the dust stays in the pool. Order-free by construction.
pub fn batch_shares(p: &Pool, ds: &[u128]) -> Vec<u128> {
    let total: u128 = ds.iter().sum();
    shares(swap_out(p, total), total, ds)
}

pub fn batch_pool(p: &Pool, ds: &[u128]) -> Pool {
    let total: u128 = ds.iter().sum();
    let paid: u128 = batch_shares(p, ds).iter().sum();
    Pool { x: p.x + total, y: p.y - paid, version: p.version + 1 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Curve {
    pub offset: u128,
    pub coins: u128,
    pub tokens: u128,
    pub version: u64,
}

impl Curve {
    pub fn pool(&self) -> Pool {
        Pool { x: self.offset + self.coins, y: self.tokens, version: self.version }
    }
    pub fn buy_out(&self, dx: u128) -> u128 {
        swap_out(&self.pool(), dx)
    }
    pub fn buy(&self, dx: u128) -> Curve {
        Curve {
            offset: self.offset,
            coins: self.coins + dx,
            tokens: self.tokens - self.buy_out(dx),
            version: self.version + 1,
        }
    }
    pub fn sell_out(&self, dy: u128) -> u128 {
        let rev = Pool { x: self.tokens, y: self.offset + self.coins, version: self.version };
        swap_out(&rev, dy)
    }
    pub fn sell(&self, dy: u128) -> Curve {
        Curve {
            offset: self.offset,
            coins: self.coins - self.sell_out(dy),
            tokens: self.tokens + dy,
            version: self.version + 1,
        }
    }
    /// Liq `spot`: wei per coin, floored.
    pub fn spot(&self) -> u128 {
        if self.tokens == 0 {
            0
        } else {
            (self.offset + self.coins) / self.tokens
        }
    }
}

/// Liq `PoolOk`: the genesis pool's invariant.
pub fn pool_ok(c: &Curve) -> bool {
    c.offset == YV && c.tokens <= RESERVE && YV * RESERVE <= (YV + c.coins) * c.tokens
}

/// The genesis curve: the whole reserve priced by the virtual ether.
pub fn genesis_curve() -> Curve {
    Curve { offset: YV, coins: 0, tokens: RESERVE, version: 0 }
}

/// Liq `saleOk`: a sale is open while the pool holds at most the reserve
/// after it.
pub fn sale_ok(c: &Curve, dy: u128) -> bool {
    c.tokens + dy <= RESERVE
}

// -- the genesis pool's acts -----------------------------------------------------

#[derive(Clone, Debug)]
pub enum PoolAct {
    Buy(u128),
    Buys(Vec<u128>),
    Sell(u128),
}

#[derive(Clone, Debug)]
pub struct GPool {
    pub curve: Curve,
    pub retired: bool,
    pub burned: u128,
}

impl GPool {
    pub fn genesis() -> GPool {
        GPool { curve: genesis_curve(), retired: false, burned: 0 }
    }

    /// Liq `GPool.step`. Returns whether the act took effect (a sale past
    /// the reserve is refused — the state is returned unchanged).
    pub fn step(&mut self, act: &PoolAct) -> bool {
        match act {
            PoolAct::Buy(dx) => {
                if self.retired {
                    return false;
                }
                self.curve = self.curve.buy(*dx);
                true
            }
            PoolAct::Buys(ds) => {
                if self.retired {
                    return false;
                }
                let p = batch_pool(&self.curve.pool(), ds);
                self.curve = Curve {
                    offset: self.curve.offset,
                    coins: self.curve.coins + ds.iter().sum::<u128>(),
                    tokens: p.y,
                    version: self.curve.version + 1,
                };
                true
            }
            PoolAct::Sell(dy) => {
                if !sale_ok(&self.curve, *dy) {
                    return false;
                }
                let was_retired = self.retired;
                self.curve = self.curve.sell(*dy);
                if was_retired {
                    self.burned += dy;
                }
                true
            }
        }
    }

    /// Retirement: no more sales of new coin; everything held counts
    /// burned; buybacks continue and count burned too.
    pub fn retire(&mut self) {
        if !self.retired {
            self.retired = true;
            self.burned += self.curve.tokens;
        }
    }

    pub fn held(&self) -> u128 {
        if self.retired {
            0
        } else {
            self.curve.tokens
        }
    }
}

// -- the oracle -------------------------------------------------------------------

/// One epoch's price: the mean of its block spots (Liq `twap`).
pub fn weekly_mean(block_spots: &[u128]) -> u128 {
    if block_spots.is_empty() {
        0
    } else {
        block_spots.iter().sum::<u128>() / block_spots.len() as u128
    }
}

/// Liq `pcap`: the highest of the last 8 weekly means, floored at P0.
pub fn pcap(weekly_means: &[u128]) -> u128 {
    let take = weekly_means.len().min(ORACLE_WEEKS);
    let m = weekly_means[weekly_means.len() - take..].iter().max().copied().unwrap_or(0);
    P0.max(m)
}

/// Liq `vcap`: the value cap in coins — V over the cap price. At the
/// genesis price this is exactly GMAX.
pub fn vcap(weekly_means: &[u128]) -> u128 {
    V / pcap(weekly_means)
}

/// Liq `coinCap`: the coin lane's fee cap, at least one coin.
pub fn coin_cap(weekly_means: &[u128]) -> u128 {
    1.max(vcap(weekly_means))
}

// -- the listed launch --------------------------------------------------------------

/// The curve tranche: a quarter of the cap (Tok `PC`).
pub const PC: u128 = 250_000_000_000_000;
/// The listing tranche: 5% of the cap (Tok `PL`).
pub const PL: u128 = 50_000_000_000_000;
/// The curve tranche's virtual ether (Tok `YV2`).
pub const YV2: u128 = 2_500_000_000_000_000_000_000;
/// The premine's floor: 10^12 coins (Tok `QS`).
pub const QS: u128 = 1_000_000_000_000;
/// The listing cliff in epochs (Tok `CLIFF`).
pub const CLIFF: u64 = 26;
/// The listing lane's per-epoch ceiling: 1% of the tranche (Tok `LRATE`).
pub const LRATE: u128 = 500_000_000_000;

/// Tok `allowance`: 10^12 plus three for every seven granted.
pub fn allowance(grants_to_date: u128) -> u128 {
    QS + 3 * grants_to_date / 7
}
/// The curve lane's share: five sixths.
pub fn curve_allow(grants_to_date: u128) -> u128 {
    allowance(grants_to_date) * 5 / 6
}
/// The listing lane's share: one sixth.
pub fn list_allow(grants_to_date: u128) -> u128 {
    allowance(grants_to_date) / 6
}

/// Version 2's two lanes over the premine.
pub struct ListedLaunch {
    pub curve: Curve,
    pub listing_sold_total: u128,
    listing_sold_epoch: u64,
    listing_sold_this_epoch: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneError {
    BeforeCliff,
    OverRate,
    PriceTooLow,
    OverAllowance,
    OverTranche,
    SaleClosed,
}

impl ListedLaunch {
    pub fn genesis() -> ListedLaunch {
        ListedLaunch {
            curve: Curve { offset: YV2, coins: 0, tokens: PC, version: 0 },
            listing_sold_total: 0,
            listing_sold_epoch: 0,
            listing_sold_this_epoch: 0,
        }
    }

    /// Coins the curve lane has released, net of buybacks (sales return
    /// coins to the curve, lowering the net release by construction).
    pub fn curve_released_net(&self) -> u128 {
        PC - self.curve.tokens
    }

    /// A curve buy (pay `dx` wei). Refused if it would push the lane's
    /// net release past its share of the allowance at the current grants.
    pub fn curve_buy(&mut self, dx: u128, grants_to_date: u128) -> Result<u128, LaneError> {
        let out = self.curve.buy_out(dx);
        if self.curve_released_net() + out > curve_allow(grants_to_date) {
            return Err(LaneError::OverAllowance);
        }
        self.curve = self.curve.buy(dx);
        Ok(out)
    }

    /// A curve sale (return `dy` coins for wei): always open while the
    /// curve would still hold at most its tranche.
    pub fn curve_sell(&mut self, dy: u128) -> Result<u128, LaneError> {
        if self.curve.tokens + dy > PC {
            return Err(LaneError::SaleClosed);
        }
        let out = self.curve.sell_out(dy);
        self.curve = self.curve.sell(dy);
        Ok(out)
    }

    /// A listing-lane sale: after the cliff, at most LRATE per epoch, at
    /// a price at least the oracle's cap price and the genesis price,
    /// within the lane's allowance share and the tranche.
    pub fn listing_sell(
        &mut self,
        amount: u128,
        price_wei: u128,
        epoch: u64,
        weekly_means: &[u128],
        grants_to_date: u128,
    ) -> Result<(), LaneError> {
        if epoch < CLIFF {
            return Err(LaneError::BeforeCliff);
        }
        if self.listing_sold_epoch != epoch {
            self.listing_sold_epoch = epoch;
            self.listing_sold_this_epoch = 0;
        }
        if self.listing_sold_this_epoch + amount > LRATE {
            return Err(LaneError::OverRate);
        }
        if price_wei < pcap(weekly_means).max(P0) {
            return Err(LaneError::PriceTooLow);
        }
        if self.listing_sold_total + amount > PL {
            return Err(LaneError::OverTranche);
        }
        if self.listing_sold_total + amount > list_allow(grants_to_date) {
            return Err(LaneError::OverAllowance);
        }
        self.listing_sold_this_epoch += amount;
        self.listing_sold_total += amount;
        Ok(())
    }
}

// -- bridge lanes ---------------------------------------------------------------------

/// Liq `feeOf`: 1% rounded up, at least 1, at most the cap and the amount.
pub fn fee_of(cap: u128, a: u128) -> u128 {
    a.min(cap.min(1.max((a + 99) / 100)))
}

/// One bridge lane (one asset, both directions), with the books the
/// module keeps: `escrow` coin held against `wrapped` coin outstanding.
#[derive(Default)]
pub struct BridgeLane {
    pub escrow: u128,
    pub wrapped: u128,
    pub fees: u128,
    drained_epoch: u64,
    drained_this_epoch: u128,
}

impl BridgeLane {
    /// The per-epoch drain quota: the lane's floor plus an eighth of the
    /// relevant stock (Liq `Lane.quotaIn`/`quotaOut` shape).
    pub fn quota_in(&self, floor: u128) -> u128 {
        floor + self.wrapped / 8
    }
    pub fn quota_out(&self, floor: u128) -> u128 {
        floor + self.escrow / 8
    }

    /// Deposit coin, receive wrapped (less the fee). Returns the wrapped
    /// amount, or None if the epoch's in-quota is exhausted.
    pub fn deposit(&mut self, amount: u128, fee_cap: u128, epoch: u64, quota_floor: u128) -> Option<u128> {
        if self.drained_epoch != epoch {
            self.drained_epoch = epoch;
            self.drained_this_epoch = 0;
        }
        if self.drained_this_epoch + amount > self.quota_in(quota_floor) {
            return None;
        }
        let fee = fee_of(fee_cap, amount);
        self.escrow += amount;
        self.wrapped += amount - fee;
        self.fees += fee;
        self.drained_this_epoch += amount;
        Some(amount - fee)
    }

    /// Burn wrapped, receive coin back (less the fee), if the escrow
    /// covers it and the epoch's out-quota allows.
    pub fn withdraw(&mut self, wrapped_amount: u128, fee_cap: u128, epoch: u64, quota_floor: u128) -> Option<u128> {
        if self.drained_epoch != epoch {
            self.drained_epoch = epoch;
            self.drained_this_epoch = 0;
        }
        if wrapped_amount > self.wrapped {
            return None;
        }
        if self.drained_this_epoch + wrapped_amount > self.quota_out(quota_floor) {
            return None;
        }
        let fee = fee_of(fee_cap, wrapped_amount);
        let out = wrapped_amount - fee;
        if out > self.escrow {
            return None;
        }
        self.wrapped -= wrapped_amount;
        self.escrow -= out;
        self.fees += fee;
        self.drained_this_epoch += wrapped_amount;
        Some(out)
    }

    /// The lane's conservation law (Liq `LaneOk`'s arithmetic core): the
    /// escrow always covers the wrapped outstanding, and what left the
    /// escrow plus what is in it equals what entered, less fees kept.
    pub fn conserved(&self) -> bool {
        self.escrow >= self.wrapped
    }
}
