use alloc::collections::{BTreeMap, BTreeSet};
use core::convert::TryInto;
use core::convert::TryFrom;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use crate::eligibility_check::ev_lt_phi;
use crate::error::{
    AggregationError, CoreVerifierError, RegisterError, StmAggregateSignatureError,
    StmSignatureError,
};
use crate::key_reg::{ClosedKeyReg, RegParty};
use crate::merkle_tree::{BatchPath, MTLeaf, MerkleTreeCommitmentBatchCompat};
use crate::multi_sig::{Signature, SigningKey, VerificationKey, VerificationKeyPoP};
use blake2::digest::{Digest, FixedOutput};
use rand_core::{CryptoRng, RngCore};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize, Serializer};

/// The quantity of stake held by a party, represented as a `u64`.
pub type Stake = u64;

/// Quorum index for signatures.
/// An aggregate signature (`StmMultiSig`) must have at least `k` unique indices.
pub type Index = u64;

/// Wrapper of the MultiSignature Verification key with proof of possession
pub type StmVerificationKeyPoP = VerificationKeyPoP;

/// Wrapper of the MultiSignature Verification key
pub type StmVerificationKey = VerificationKey;

/// Used to set protocol parameters.
// todo: this is the criteria to consider parameters valid:
// Let A = max assumed adversarial stake
// Let a = A / max_stake
// Let p = φ(a)  // f needs tuning, something close to 0.2 is reasonable
// Then, we're secure if SUM[from i=k to i=m] Binomial(i successes, m experiments, p chance of success) <= 2^-100 or thereabouts.
// The latter turns to 1 - BinomialCDF(k-1,m,p)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StmParameters {
    /// Security parameter, upper bound on indices.
    pub m: u64,
    /// Quorum parameter.
    pub k: u64,
    /// `f` in phi(w) = 1 - (1 - f)^w, where w is the stake of a participant..
    pub phi_f: f64,
}

/// Initializer for `StmSigner`.
/// This is the data that is used during the key registration procedure.
/// Once the latter is finished, this instance is consumed into an `StmSigner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StmInitializer {
    /// This participant's stake.
    pub stake: Stake,
    /// Current protocol instantiation parameters.
    pub params: StmParameters,
    /// Secret key.
    pub(crate) sk: SigningKey,
    /// Verification (public) key + proof of possession.
    pub(crate) pk: StmVerificationKeyPoP,
}

/// Participant in the protocol can sign messages.
/// * If the signer has `closed_reg`, then it can generate Stm certificate.
///     * This kind of signer can only be generated out of an `StmInitializer` and a `ClosedKeyReg`.
///     * This ensures that a `MerkleTree` root is not computed before all participants have registered.
/// * If the signer does not have `closed_reg`, then it is a core signer.
///     * This kind of signer cannot participate certificate generation.
///     * Signature generated can be verified by a full node verifier (core verifier).
#[derive(Debug, Clone)]
pub struct StmSigner<D: Digest> {
    signer_index: u64,
    stake: Stake,
    params: StmParameters,
    sk: SigningKey,
    vk: StmVerificationKey,
    closed_reg: Option<ClosedKeyReg<D>>,
}

/// `StmClerk` can verify and aggregate `StmSig`s and verify `StmMultiSig`s.
/// Clerks can only be generated with the registration closed.
/// This avoids that a Merkle Tree is computed before all parties have registered.
#[derive(Debug, Clone)]
pub struct StmClerk<D: Clone + Digest> {
    pub(crate) closed_reg: ClosedKeyReg<D>,
    pub(crate) params: StmParameters,
}

/// Signature created by a single party who has won the lottery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StmSig {
    /// The signature from the underlying MSP scheme.
    pub sigma: Signature,
    /// The index(es) for which the signature is valid
    pub indexes: Vec<Index>,
    /// Merkle tree index of the signer.
    pub signer_index: Index,
}

/// Stm aggregate key (batch compatible), which contains the merkle tree commitment and the total stake of the system.
/// Batch Compat Merkle tree commitment includes the number of leaves in the tree in order to obtain batch path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "BatchPath<D>: Serialize",
    deserialize = "BatchPath<D>: Deserialize<'de>"
))]
pub struct StmAggrVerificationKey<D: Clone + Digest + FixedOutput> {
    mt_commitment: MerkleTreeCommitmentBatchCompat<D>,
    total_stake: Stake,
}

impl<D: Digest + Clone + FixedOutput> PartialEq for StmAggrVerificationKey<D> {
    fn eq(&self, other: &Self) -> bool {
        self.mt_commitment == other.mt_commitment && self.total_stake == other.total_stake
    }
}

impl<D: Digest + Clone + FixedOutput> Eq for StmAggrVerificationKey<D> {}

/// Signature with its registered party.
#[derive(Debug, Clone, Hash, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct StmSigRegParty {
    /// Stm signature
    pub sig: StmSig,
    /// Registered party
    pub reg_party: RegParty,
}

impl Serialize for StmSigRegParty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.sig)?;
        tuple.serialize_element(&self.reg_party)?;
        tuple.end()
    }
}

/// `StmMultiSig` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "BatchPath<D>: Serialize",
    deserialize = "BatchPath<D>: Deserialize<'de>"
))]
pub struct StmAggrSig<D: Clone + Digest + FixedOutput> {
    pub(crate) signatures: Vec<StmSigRegParty>,
    /// The list of unique merkle tree nodes that covers path for all signatures.
    pub batch_proof: BatchPath<D>,
}

/// Full node verifier including the list of eligible signers and the total stake of the system.
pub struct CoreVerifier {
    /// List of registered parties.
    pub eligible_parties: Vec<RegParty>,
    /// Total stake of registered parties.
    pub total_stake: Stake,
}

impl StmParameters {
    /// Convert to bytes
    /// # Layout
    /// * Security parameter, `m` (as u64)
    /// * Quorum parameter, `k` (as u64)
    /// * Phi f, as (f64)
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut out = [0; 24];
        out[..8].copy_from_slice(&self.m.to_be_bytes());
        out[8..16].copy_from_slice(&self.k.to_be_bytes());
        out[16..].copy_from_slice(&self.phi_f.to_be_bytes());
        out
    }

    /// Extract the `StmParameters` from a byte slice.
    /// # Error
    /// The function fails if the given string of bytes is not of required size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RegisterError> {
        if bytes.len() != 24 {
            return Err(RegisterError::SerializationError);
        }

        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(&bytes[..8]);
        let m = u64::from_be_bytes(u64_bytes);
        u64_bytes.copy_from_slice(&bytes[8..16]);
        let k = u64::from_be_bytes(u64_bytes);
        u64_bytes.copy_from_slice(&bytes[16..]);
        let phi_f = f64::from_be_bytes(u64_bytes);

        Ok(Self { m, k, phi_f })
    }
}

impl StmInitializer {
    /// Builds an `StmInitializer` that is ready to register with the key registration service.
    /// This function generates the signing and verification key with a PoP, and initialises the structure.
    pub fn setup<R: RngCore + CryptoRng>(params: StmParameters, stake: Stake, rng: &mut R) -> Self {
        let sk = SigningKey::gen(rng);
        let pk = StmVerificationKeyPoP::from(&sk);
        Self {
            stake,
            params,
            sk,
            pk,
        }
    }

    /// Extract the verification key.
    pub fn verification_key(&self) -> StmVerificationKeyPoP {
        self.pk
    }

    /// Build the `avk` for the given list of parties.
    ///
    /// Note that if this StmInitializer was modified *between* the last call to `register`,
    /// then the resulting `StmSigner` may not be able to produce valid signatures.
    ///
    /// Returns an `StmSigner` specialized to
    /// * this `StmSigner`'s ID and current stake
    /// * this `StmSigner`'s parameter valuation
    /// * the `avk` as built from the current registered parties (according to the registration service)
    /// * the current total stake (according to the registration service)
    /// # Error
    /// This function fails if the initializer is not registered.
    pub fn new_signer<D: Digest + Clone>(
        self,
        closed_reg: ClosedKeyReg<D>,
    ) -> Result<StmSigner<D>, RegisterError> {
        let mut my_index = None;
        for (i, rp) in closed_reg.reg_parties.iter().enumerate() {
            if rp.0 == self.pk.vk {
                my_index = Some(i as u64);
                break;
            }
        }
        if my_index.is_none() {
            return Err(RegisterError::UnregisteredInitializer);
        }

        Ok(StmSigner {
            signer_index: my_index.unwrap(),
            stake: self.stake,
            params: self.params,
            sk: self.sk,
            vk: self.pk.vk,
            closed_reg: Some(closed_reg),
        })
    }

    /// Creates a new core signer that does not include closed registration.
    /// Takes `eligible_parties` as a parameter and determines the signer's index in the parties.
    /// `eligible_parties` is verified and trusted which is only run by a full-node
    /// that has already verified the parties.
    pub fn new_core_signer<D: Digest + Clone>(
        self,
        eligible_parties: &[RegParty],
    ) -> Option<StmSigner<D>> {
        let mut parties = eligible_parties.to_vec();
        parties.sort_unstable();
        let mut my_index = None;
        for (i, rp) in parties.iter().enumerate() {
            if rp.0 == self.pk.vk {
                my_index = Some(i as u64);
                break;
            }
        }
        if let Some(index) = my_index {
            Some(StmSigner {
                signer_index: index,
                stake: self.stake,
                params: self.params,
                sk: self.sk,
                vk: self.pk.vk,
                closed_reg: None,
            })
        } else {
            None
        }
    }

    /// Convert to bytes
    /// # Layout
    /// * Stake (u64)
    /// * Params
    /// * Secret Key
    /// * Public key (including PoP)
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[..8].copy_from_slice(&self.stake.to_be_bytes());
        out[8..32].copy_from_slice(&self.params.to_bytes());
        out[32..64].copy_from_slice(&self.sk.to_bytes());
        out[64..].copy_from_slice(&self.pk.to_bytes());
        out
    }

    /// Convert a slice of bytes to an `StmInitializer`
    /// # Error
    /// The function fails if the given string of bytes is not of required size.
    pub fn from_bytes(bytes: &[u8]) -> Result<StmInitializer, RegisterError> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(&bytes[..8]);
        let stake = u64::from_be_bytes(u64_bytes);
        let params = StmParameters::from_bytes(&bytes[8..32])?;
        let sk = SigningKey::from_bytes(&bytes[32..])?;
        let pk = StmVerificationKeyPoP::from_bytes(&bytes[64..])?;

        Ok(Self {
            stake,
            params,
            sk,
            pk,
        })
    }
}

impl<D: Clone + Digest + FixedOutput> StmSigner<D> {
    /// This function produces a signature following the description of Section 2.4.
    /// Once the signature is produced, this function checks whether any index in `[0,..,self.params.m]`
    /// wins the lottery by evaluating the dense mapping.
    /// It records all the winning indexes in `Self.indexes`.
    /// If it wins at least one lottery, it stores the signer's merkle tree index. The proof of membership
    /// will be handled by the aggregator.
    pub fn sign(&self, msg: &[u8]) -> Option<StmSig> {
        let closed_reg = self.closed_reg.as_ref().expect("Closed registration not found! Cannot produce StmSignatures. Use core_sign to produce core signatures (not valid for an StmCertificate).");
        let msgp = closed_reg
            .merkle_tree
            .to_commitment_batch_compat()
            .concat_with_msg(msg);
        let signature = self.core_sign(&msgp, closed_reg.total_stake)?;

        Some(StmSig {
            sigma: signature.sigma,
            signer_index: self.signer_index,
            indexes: signature.indexes,
        })
    }

    /// Extract the verification key.
    pub fn verification_key(&self) -> StmVerificationKey {
        self.vk
    }

    /// Extract stake from the signer.
    pub fn get_stake(&self) -> Stake {
        self.stake
    }

    /// A core signature generated without closed registration.
    /// The core signature can be verified by core verifier.
    /// Once the signature is produced, this function checks whether any index in `[0,..,self.params.m]`
    /// wins the lottery by evaluating the dense mapping.
    /// It records all the winning indexes in `Self.indexes`.
    pub fn core_sign(&self, msg: &[u8], total_stake: Stake) -> Option<StmSig> {
        let sigma = self.sk.sign(msg);

        let indexes = self.check_lottery(msg, &sigma, total_stake);
        if !indexes.is_empty() {
            Some(StmSig {
                sigma,
                indexes,
                signer_index: self.signer_index,
            })
        } else {
            None
        }
    }

    /// Collects and returns the winning indices.
    pub fn check_lottery(&self, msg: &[u8], sigma: &Signature, total_stake: Stake) -> Vec<u64> {
        let mut indexes = Vec::new();
        for index in 0..self.params.m {
            if ev_lt_phi(
                self.params.phi_f,
                sigma.eval(msg, index),
                self.stake,
                total_stake,
            ) {
                indexes.push(index);
            }
        }
        indexes
    }
}

impl<D: Digest + Clone + FixedOutput> StmClerk<D> {
    /// Create a new `Clerk` from a closed registration instance.
    pub fn from_registration(params: &StmParameters, closed_reg: &ClosedKeyReg<D>) -> Self {
        Self {
            params: *params,
            closed_reg: closed_reg.clone(),
        }
    }

    /// Create a Clerk from a signer.
    pub fn from_signer(signer: &StmSigner<D>) -> Self {
        let closed_reg = signer
            .closed_reg
            .clone()
            .expect("Core signer does not include closed registration. StmClerk, and so, the Stm certificate cannot be built without closed registration!");

        Self {
            params: signer.params,
            closed_reg,
        }
    }

    /// Aggregate a set of signatures for their corresponding indices.
    ///
    /// This function first deduplicates the repeated signatures, and if there are enough signatures, it collects the merkle tree indexes of unique signatures.
    /// The list of merkle tree indexes is used to create a batch proof, to prove that all signatures are from eligible signers.
    ///
    /// It returns an instance of `StmAggrSig`.
    pub fn aggregate(
        &self,
        sigs: &[StmSig],
        msg: &[u8],
    ) -> Result<StmAggrSig<D>, AggregationError> {
        let sig_reg_list = sigs
            .iter()
            .map(|sig| StmSigRegParty {
                sig: sig.clone(),
                reg_party: self.closed_reg.reg_parties[sig.signer_index as usize],
            })
            .collect::<Vec<StmSigRegParty>>();

        let avk = StmAggrVerificationKey::from(&self.closed_reg);
        let msgp = avk.mt_commitment.concat_with_msg(msg);
        let mut unique_sigs = CoreVerifier::dedup_sigs_for_indices(
            &self.closed_reg.total_stake,
            &self.params,
            &msgp,
            &sig_reg_list,
        )?;

        unique_sigs.sort_unstable();

        let mt_index_list = unique_sigs
            .iter()
            .map(|sig_reg| sig_reg.sig.signer_index as usize)
            .collect::<Vec<usize>>();

        let batch_proof = self.closed_reg.merkle_tree.get_batched_path(mt_index_list);

        Ok(StmAggrSig {
            signatures: unique_sigs,
            batch_proof,
        })
    }

    /// Compute the `StmAggrVerificationKey` related to the used registration.
    pub fn compute_avk(&self) -> StmAggrVerificationKey<D> {
        StmAggrVerificationKey::from(&self.closed_reg)
    }

    /// Get the (VK, stake) of a party given its index.
    pub fn get_reg_party(&self, party_index: &Index) -> Option<(StmVerificationKey, Stake)> {
        self.closed_reg
            .reg_parties
            .get(*party_index as usize)
            .map(|&r| r.into())
    }
}

impl StmSig {
    /// Verify an stm signature by checking that the lottery was won, the merkle path is correct,
    /// the indexes are in the desired range and the underlying multi signature validates.
    pub fn verify<D: Clone + Digest + FixedOutput>(
        &self,
        params: &StmParameters,
        pk: &StmVerificationKey,
        stake: &Stake,
        avk: &StmAggrVerificationKey<D>,
        msg: &[u8],
    ) -> Result<(), StmSignatureError> {
        let msgp = avk.mt_commitment.concat_with_msg(msg);
        self.verify_core(params, pk, stake, &msgp, &avk.total_stake)?;
        Ok(())
    }

    /// Verify that all indices of a signature are valid.
    pub(crate) fn check_indices(
        &self,
        params: &StmParameters,
        stake: &Stake,
        msg: &[u8],
        total_stake: &Stake,
    ) -> Result<(), StmSignatureError> {
        for &index in &self.indexes {
            if index > params.m {
                return Err(StmSignatureError::IndexBoundFailed(index, params.m));
            }

            let ev = self.sigma.eval(msg, index);

            if !ev_lt_phi(params.phi_f, ev, *stake, *total_stake) {
                return Err(StmSignatureError::LotteryLost);
            }
        }

        Ok(())
    }

    /// Convert an `StmSig` into bytes
    ///
    /// # Layout
    /// * Stake
    /// * Number of valid indexes (as u64)
    /// * Indexes of the signature
    /// * Public Key
    /// * Signature
    /// * Merkle index of the signer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&(self.indexes.len() as u64).to_be_bytes());

        for index in &self.indexes {
            output.extend_from_slice(&index.to_be_bytes());
        }

        output.extend_from_slice(&self.sigma.to_bytes());

        output.extend_from_slice(&self.signer_index.to_be_bytes());
        output
    }

    /// Extract a batch compatible `StmSig` from a byte slice.
    pub fn from_bytes<D: Clone + Digest + FixedOutput>(
        bytes: &[u8],
    ) -> Result<StmSig, StmSignatureError> {
        let mut u64_bytes = [0u8; 8];

        u64_bytes.copy_from_slice(&bytes[0..8]);
        let nr_indexes = u64::from_be_bytes(u64_bytes) as usize;

        let mut indexes = Vec::new();
        for i in 0..nr_indexes {
            u64_bytes.copy_from_slice(&bytes[8 + i * 8..16 + i * 8]);
            indexes.push(u64::from_be_bytes(u64_bytes));
        }

        let offset = 8 + nr_indexes * 8;
        let sigma = Signature::from_bytes(&bytes[offset..offset + 48])?;

        u64_bytes.copy_from_slice(&bytes[offset + 48..offset + 56]);
        let signer_index = u64::from_be_bytes(u64_bytes);

        Ok(StmSig {
            sigma,
            indexes,
            signer_index,
        })
    }

    /// Compare two `StmSig` by their signers' merkle tree indexes.
    pub fn cmp_stm_sig(&self, other: &Self) -> Ordering {
        self.signer_index.cmp(&other.signer_index)
    }

    /// Verify a core signature by checking that the lottery was won,
    /// the indexes are in the desired range and the underlying multi signature validates.
    pub fn verify_core(
        &self,
        params: &StmParameters,
        pk: &StmVerificationKey,
        stake: &Stake,
        msg: &[u8],
        total_stake: &Stake,
    ) -> Result<(), StmSignatureError> {
        self.sigma.verify(msg, pk)?;
        self.check_indices(params, stake, msg, total_stake)?;

        Ok(())
    }
}

impl Hash for StmSig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash_slice(&self.sigma.to_bytes(), state)
    }
}

impl PartialEq for StmSig {
    fn eq(&self, other: &Self) -> bool {
        self.sigma == other.sigma
    }
}

impl Eq for StmSig {}

impl PartialOrd for StmSig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(core::cmp::Ord::cmp(self, other))
    }
}

impl Ord for StmSig {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_stm_sig(other)
    }
}

impl<D: Clone + Digest + FixedOutput> From<&ClosedKeyReg<D>> for StmAggrVerificationKey<D> {
    fn from(reg: &ClosedKeyReg<D>) -> Self {
        Self {
            mt_commitment: reg.merkle_tree.to_commitment_batch_compat(),
            total_stake: reg.total_stake,
        }
    }
}

impl StmSigRegParty {
    /// Convert StmSigRegParty to bytes
    /// # Layout
    /// * RegParty
    /// * Signature
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.reg_party.to_bytes());
        out.extend_from_slice(&self.sig.to_bytes());

        out
    }
    ///Extract a `StmSigRegParty` from a byte slice.
    pub fn from_bytes<D: Digest + Clone + FixedOutput>(
        bytes: &[u8],
    ) -> Result<StmSigRegParty, StmSignatureError> {
        let reg_party = RegParty::from_bytes(&bytes[0..104])?;
        let sig = StmSig::from_bytes::<D>(&bytes[104..])?;

        Ok(StmSigRegParty { sig, reg_party })
    }
}

impl<D: Clone + Digest + FixedOutput + Send + Sync> StmAggrSig<D> {
    /// Verify all checks from signatures, except for the signature verification itself.
    ///
    /// Indices and quorum are checked by `CoreVerifier::preliminary_verify` with `msgp`.
    /// It collects leaves from signatures and checks the batch proof.
    /// After batch proof is checked, it collects and returns the signatures and
    /// verification keys to be used by aggregate verification.
    fn preliminary_verify(
        &self,
        msg: &[u8],
        avk: &StmAggrVerificationKey<D>,
        parameters: &StmParameters,
    ) -> Result<(Vec<Signature>, Vec<VerificationKey>), StmAggregateSignatureError<D>> {
        let msgp = avk.mt_commitment.concat_with_msg(msg);
        CoreVerifier::preliminary_verify(&avk.total_stake, &self.signatures, parameters, &msgp)?;

        let leaves = self
            .signatures
            .iter()
            .map(|r| r.reg_party)
            .collect::<Vec<RegParty>>();

        avk.mt_commitment.check(&leaves, &self.batch_proof)?;

        Ok(CoreVerifier::collect_sigs_vks(&self.signatures))
    }

    /// Verify aggregate signature, by checking that
    /// * each signature contains only valid indices,
    /// * the lottery is indeed won by each one of them,
    /// * the merkle tree path is valid,
    /// * the aggregate signature validates with respect to the aggregate verification key
    /// (aggregation is computed using functions `MSP.BKey` and `MSP.BSig` as described in Section 2.4 of the paper).
    pub fn verify(
        &self,
        msg: &[u8],
        avk: &StmAggrVerificationKey<D>,
        parameters: &StmParameters,
    ) -> Result<(), StmAggregateSignatureError<D>> {
        let msgp = avk.mt_commitment.concat_with_msg(msg);
        let (sigs, vks) = self.preliminary_verify(msg, avk, parameters)?;

        Signature::verify_aggregate(msgp.as_slice(), &vks, &sigs)?;
        Ok(())
    }

    /// Convert multi signature to bytes
    /// # Layout
    /// * Number of the pairs of Signatures and Registered Parties (SigRegParty) (as u64)
    /// * Size of a pair of Signature and Registered Party
    /// * Pairs of Signatures and Registered Parties
    /// * Batch proof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u64::try_from(self.signatures.len()).unwrap().to_be_bytes());
        out.extend_from_slice(
            &u64::try_from(self.signatures[0].to_bytes().len())
                .unwrap()
                .to_be_bytes(),
        );
        for sig_reg in &self.signatures {
            out.extend_from_slice(&sig_reg.to_bytes());
        }
        let proof = &self.batch_proof;
        out.extend_from_slice(&proof.to_bytes());

        out
    }

    ///Extract a `StmAggrSig` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<StmAggrSig<D>, StmAggregateSignatureError<D>> {
        let mut u64_bytes = [0u8; 8];

        u64_bytes.copy_from_slice(&bytes[..8]);
        let size = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| StmAggregateSignatureError::SerializationError)?;

        u64_bytes.copy_from_slice(&bytes[8..16]);
        let sig_reg_size = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| StmAggregateSignatureError::SerializationError)?;

        let mut sig_reg_list = Vec::with_capacity(size);
        for i in 0..size {
            let sig_reg = StmSigRegParty::from_bytes::<D>(
                &bytes[16 + (sig_reg_size * i)..16 + (sig_reg_size * (i + 1))],
            )?;
            sig_reg_list.push(sig_reg);
        }

        let offset = 16 + sig_reg_size * size;
        let batch_proof = BatchPath::from_bytes(&bytes[offset..])?;

        Ok(StmAggrSig {
            signatures: sig_reg_list,
            batch_proof,
        })
    }
}

impl CoreVerifier {
    /// Setup a core verifier for given list of signers.
    ///     * Collect the unique signers in a hash set,
    ///     * Calculate the total stake of the eligible signers,
    ///     * Sort the eligible signers.
    pub fn setup(public_signers: &[(VerificationKey, Stake)]) -> Self {
        let mut total_stake: Stake = 0;
        let mut unique_parties = BTreeSet::new();
        for signer in public_signers.iter() {
            let (res, overflow) = total_stake.overflowing_add(signer.1);
            if overflow {
                panic!("Total stake overflow");
            }
            total_stake = res;
            unique_parties.insert(MTLeaf(signer.0, signer.1));
        }

        let mut eligible_parties: Vec<_> = unique_parties.into_iter().collect();
        eligible_parties.sort_unstable();
        CoreVerifier {
            eligible_parties,
            total_stake,
        }
    }

    /// Preliminary verification that checks whether indices are unique and the quorum is achieved.
    fn preliminary_verify(
        total_stake: &Stake,
        signatures: &[StmSigRegParty],
        parameters: &StmParameters,
        msg: &[u8],
    ) -> Result<(), CoreVerifierError> {
        let mut nr_indices = 0;
        let mut unique_indices = BTreeSet::new();

        for sig_reg in signatures {
            sig_reg
                .sig
                .check_indices(parameters, &sig_reg.reg_party.1, msg, total_stake)?;
            for &index in &sig_reg.sig.indexes {
                unique_indices.insert(index);
                nr_indices += 1;
            }
        }

        if nr_indices != unique_indices.len() {
            return Err(CoreVerifierError::IndexNotUnique);
        }
        if (nr_indices as u64) < parameters.k {
            return Err(CoreVerifierError::NoQuorum(nr_indices as u64, parameters.k));
        }

        Ok(())
    }

    /// Given a slice of `sig_reg_list`, this function returns a new list of `sig_reg_list` with only valid indices.
    /// In case of conflict (having several signatures for the same index)
    /// it selects the smallest signature (i.e. takes the signature with the smallest scalar).
    /// The function selects at least `self.k` indexes.
    ///  # Error
    /// If there is no sufficient signatures, then the function fails.
    // todo: We need to agree on a criteria to dedup (by default we use a BTreeMap that guarantees keys order)
    // todo: not good, because it only removes index if there is a conflict (see benches)
    pub fn dedup_sigs_for_indices(
        total_stake: &Stake,
        params: &StmParameters,
        msg: &[u8],
        sigs: &[StmSigRegParty],
    ) -> Result<Vec<StmSigRegParty>, AggregationError> {
        let mut sig_by_index: BTreeMap<Index, &StmSigRegParty> = BTreeMap::new();
        let mut removal_idx_by_vk: BTreeMap<&StmSigRegParty, Vec<Index>> = BTreeMap::new();

        for sig_reg in sigs.iter() {
            if sig_reg
                .sig
                .verify_core(
                    params,
                    &sig_reg.reg_party.0,
                    &sig_reg.reg_party.1,
                    msg,
                    total_stake,
                )
                .is_err()
            {
                continue;
            }
            for index in sig_reg.sig.indexes.iter() {
                let mut insert_this_sig = false;
                if let Some(&previous_sig) = sig_by_index.get(index) {
                    let sig_to_remove_index = if sig_reg.sig.sigma < previous_sig.sig.sigma {
                        insert_this_sig = true;
                        previous_sig
                    } else {
                        sig_reg
                    };

                    if let Some(indexes) = removal_idx_by_vk.get_mut(sig_to_remove_index) {
                        indexes.push(*index);
                    } else {
                        removal_idx_by_vk.insert(sig_to_remove_index, vec![*index]);
                    }
                } else {
                    insert_this_sig = true;
                }

                if insert_this_sig {
                    sig_by_index.insert(*index, sig_reg);
                }
            }
        }

        let mut dedup_sigs: BTreeSet<StmSigRegParty> = BTreeSet::new();
        let mut count: u64 = 0;

        for (_, &sig_reg) in sig_by_index.iter() {
            if dedup_sigs.contains(sig_reg) {
                continue;
            }
            let mut deduped_sig = sig_reg.clone();
            if let Some(indexes) = removal_idx_by_vk.get(sig_reg) {
                deduped_sig.sig.indexes = deduped_sig
                    .sig
                    .indexes
                    .clone()
                    .into_iter()
                    .filter(|i| !indexes.contains(i))
                    .collect();
            }

            let size: Result<u64, _> = deduped_sig.sig.indexes.len().try_into();
            if let Ok(size) = size {
                if dedup_sigs.contains(&deduped_sig) {
                    panic!("Should not reach!");
                }
                dedup_sigs.insert(deduped_sig);
                count += size;

                if count >= params.k {
                    return Ok(dedup_sigs.into_iter().collect());
                }
            }
        }

        Err(AggregationError::NotEnoughSignatures(count, params.k))
    }

    /// Collect and return `Vec<Signature>, Vec<VerificationKey>` which will be used
    /// by the aggregate verification.
    fn collect_sigs_vks(sig_reg_list: &[StmSigRegParty]) -> (Vec<Signature>, Vec<VerificationKey>) {
        let sigs = sig_reg_list
            .iter()
            .map(|sig_reg| sig_reg.sig.sigma)
            .collect::<Vec<Signature>>();
        let vks = sig_reg_list
            .iter()
            .map(|sig_reg| sig_reg.reg_party.0)
            .collect::<Vec<VerificationKey>>();

        (sigs, vks)
    }

    /// Core verification
    ///
    /// Verify a list of signatures with respect to given message with given parameters.
    pub fn verify(
        &self,
        signatures: &[StmSig],
        parameters: &StmParameters,
        msg: &[u8],
    ) -> Result<(), CoreVerifierError> {
        let sig_reg_list = signatures
            .iter()
            .map(|sig| StmSigRegParty {
                sig: sig.clone(),
                reg_party: self.eligible_parties[sig.signer_index as usize],
            })
            .collect::<Vec<StmSigRegParty>>();

        let unique_sigs =
            Self::dedup_sigs_for_indices(&self.total_stake, parameters, msg, &sig_reg_list)?;

        Self::preliminary_verify(&self.total_stake, &unique_sigs, parameters, msg)?;

        let (sigs, vks) = Self::collect_sigs_vks(&unique_sigs);

        Signature::verify_aggregate(msg.to_vec().as_slice(), &vks, &sigs)?;

        Ok(())
    }
}