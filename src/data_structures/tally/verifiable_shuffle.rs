// Copyright © 2025 Denis Morel
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

use super::super::{
    deserialize_option_string_base64_to_option_integer, deserialize_seq_ciphertext,
    deserialize_seq_string_base64_to_seq_integer, deserialize_string_base64_to_integer,
};
use rust_ev_system_library::rust_ev_crypto_primitives::prelude::{
    EmptyContext, HashableMessage, Integer, VerifyDomainTrait,
    elgamal::Ciphertext,
    mix_net::{
        HadamardArgument as CryptoHadamardArgument, MixnetError,
        MultiExponentiationArgument as CryptoMultiExponentiationArgument,
        ProductArgument as CryptoProductArgument, ShuffleArgument as CryptoShuffleArgument,
        SingleValueProductArgument as CryptoSingleValueProductArgument,
        ZeroArgument as CryptoZeroArgument,
    },
};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableShuffle {
    #[serde(deserialize_with = "deserialize_seq_ciphertext")]
    pub shuffled_ciphertexts: Vec<Ciphertext>,
    pub shuffle_argument: ShuffleArgument,
}

pub fn verifiy_domain_for_verifiable_shuffle(value: &VerifiableShuffle) -> Vec<String> {
    value.verifiy_domain(&EmptyContext)
}

impl VerifyDomainTrait<EmptyContext, String> for VerifiableShuffle {
    fn verifiy_domain(&self, context: &EmptyContext) -> Vec<String> {
        self.shuffle_argument.verifiy_domain(context)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ShuffleArgument {
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_A")]
    pub c_a: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_B")]
    pub c_b: Vec<Integer>,
    #[serde(rename = "productArgument")]
    pub product_argument: ProductArgument,
    #[serde(rename = "multiExponentiationArgument")]
    pub multi_exponentiation_argument: MultiExponentiationArgument,
}

impl VerifyDomainTrait<EmptyContext, String> for ShuffleArgument {
    fn verifiy_domain(&self, _context: &EmptyContext) -> Vec<String> {
        match CryptoShuffleArgument::try_from(self) {
            Ok(_) => Vec::default(),
            Err(e) => vec![e.to_string()],
        }
    }
}

impl<'a> TryFrom<&'a ShuffleArgument> for CryptoShuffleArgument<'a> {
    type Error = MixnetError;

    fn try_from(value: &'a ShuffleArgument) -> Result<Self, Self::Error> {
        Self::new(
            &value.c_a,
            &value.c_b,
            CryptoProductArgument::try_from(&value.product_argument)?,
            CryptoMultiExponentiationArgument::try_from(&value.multi_exponentiation_argument)?,
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ProductArgument {
    #[serde(
        default,
        deserialize_with = "deserialize_option_string_base64_to_option_integer"
    )]
    pub c_b: Option<Integer>,
    #[serde(rename = "hadamardArgument")]
    pub hadamard_argument: Option<HadamardArgument>,
    #[serde(rename = "singleValueProductArgument")]
    pub single_value_product_argument: SingleValueProductArgument,
}

impl<'a> TryFrom<&'a ProductArgument> for CryptoProductArgument<'a> {
    type Error = MixnetError;
    fn try_from(value: &'a ProductArgument) -> Result<Self, Self::Error> {
        Self::new(
            value.c_b.as_ref(),
            match &value.hadamard_argument {
                Some(a) => Some(CryptoHadamardArgument::try_from(a)?),
                None => None,
            },
            CryptoSingleValueProductArgument::try_from(&value.single_value_product_argument)?,
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct HadamardArgument {
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub c_b: Vec<Integer>,
    #[serde(rename = "zeroArgument")]
    pub zero_argument: ZeroArgument,
}

impl<'a> TryFrom<&'a HadamardArgument> for CryptoHadamardArgument<'a> {
    type Error = MixnetError;

    fn try_from(value: &'a HadamardArgument) -> Result<Self, Self::Error> {
        Self::new(
            &value.c_b,
            CryptoZeroArgument::try_from(&value.zero_argument)?,
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ZeroArgument {
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    #[serde(rename = "c_A_0")]
    pub c_upper_a_0: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    #[serde(rename = "c_B_m")]
    pub c_upper_b_m: Integer,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_d")]
    pub cs_d: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "a_prime")]
    pub as_prime: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "b_prime")]
    pub bs_prime: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub r_prime: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub s_prime: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub t_prime: Integer,
}

impl<'a> TryFrom<&'a ZeroArgument> for CryptoZeroArgument<'a> {
    type Error = MixnetError;

    fn try_from(value: &'a ZeroArgument) -> Result<Self, Self::Error> {
        Self::new(
            &value.c_upper_a_0,
            &value.c_upper_b_m,
            &value.cs_d,
            &value.as_prime,
            &value.bs_prime,
            &value.r_prime,
            &value.s_prime,
            &value.t_prime,
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct SingleValueProductArgument {
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub c_d: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub c_delta: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    #[serde(rename = "c_Delta")]
    pub c_upper_delta: Integer,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub a_tilde: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub b_tilde: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub r_tilde: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub s_tilde: Integer,
}

impl<'a> TryFrom<&'a SingleValueProductArgument> for CryptoSingleValueProductArgument<'a> {
    type Error = MixnetError;
    fn try_from(value: &'a SingleValueProductArgument) -> Result<Self, Self::Error> {
        CryptoSingleValueProductArgument::new(
            &value.c_d,
            &value.c_delta,
            &value.c_upper_delta,
            &value.a_tilde,
            &value.b_tilde,
            &value.r_tilde,
            &value.s_tilde,
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MultiExponentiationArgument {
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    #[serde(rename = "c_A_0")]
    pub c_a_0: Integer,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_B")]
    pub c_b: Vec<Integer>,
    #[serde(rename = "E")]
    #[serde(deserialize_with = "deserialize_seq_ciphertext")]
    pub e: Vec<Ciphertext>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub a: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub r: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub b: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub s: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub tau: Integer,
}

impl<'a> TryFrom<&'a MultiExponentiationArgument> for CryptoMultiExponentiationArgument<'a> {
    type Error = MixnetError;
    fn try_from(value: &'a MultiExponentiationArgument) -> Result<Self, Self::Error> {
        CryptoMultiExponentiationArgument::new(
            &value.c_a_0,
            &value.c_b,
            &value.e,
            &value.a,
            &value.r,
            &value.b,
            &value.s,
            &value.tau,
        )
    }
}

impl<'a> From<&'a VerifiableShuffle> for HashableMessage<'a> {
    fn from(value: &'a VerifiableShuffle) -> Self {
        Self::from(vec![
            Self::from(
                value
                    .shuffled_ciphertexts
                    .iter()
                    .map(HashableMessage::from)
                    .collect::<Vec<Self>>(),
            ),
            Self::from(&value.shuffle_argument),
        ])
    }
}

impl<'a> From<&'a ShuffleArgument> for HashableMessage<'a> {
    fn from(value: &'a ShuffleArgument) -> Self {
        Self::from(vec![
            Self::from(value.c_a.as_slice()),
            Self::from(value.c_b.as_slice()),
            Self::from(&value.product_argument),
            Self::from(&value.multi_exponentiation_argument),
        ])
    }
}

impl<'a> From<&'a ProductArgument> for HashableMessage<'a> {
    fn from(value: &'a ProductArgument) -> Self {
        let mut res_vec = vec![];
        if let Some(x) = &value.c_b {
            res_vec.push(Self::from(x));
        }
        if let Some(x) = &value.hadamard_argument {
            res_vec.push(Self::from(x));
        }
        res_vec.push(Self::from(&value.single_value_product_argument));
        Self::from(res_vec)
    }
}

impl<'a> From<&'a HadamardArgument> for HashableMessage<'a> {
    fn from(value: &'a HadamardArgument) -> Self {
        Self::from(vec![
            Self::from(value.c_b.as_slice()),
            Self::from(&value.zero_argument),
        ])
    }
}

impl<'a> From<&'a ZeroArgument> for HashableMessage<'a> {
    fn from(value: &'a ZeroArgument) -> Self {
        Self::from(vec![
            Self::from(&value.c_upper_a_0),
            Self::from(&value.c_upper_b_m),
            Self::from(value.cs_d.as_slice()),
            Self::from(value.as_prime.as_slice()),
            Self::from(value.bs_prime.as_slice()),
            Self::from(&value.r_prime),
            Self::from(&value.s_prime),
            Self::from(&value.t_prime),
        ])
    }
}

impl<'a> From<&'a SingleValueProductArgument> for HashableMessage<'a> {
    fn from(value: &'a SingleValueProductArgument) -> Self {
        Self::from(vec![
            Self::from(&value.c_d),
            Self::from(&value.c_delta),
            Self::from(&value.c_upper_delta),
            Self::from(value.a_tilde.as_slice()),
            Self::from(value.b_tilde.as_slice()),
            Self::from(&value.r_tilde),
            Self::from(&value.s_tilde),
        ])
    }
}

impl<'a> From<&'a MultiExponentiationArgument> for HashableMessage<'a> {
    fn from(value: &'a MultiExponentiationArgument) -> Self {
        Self::from(vec![
            Self::from(&value.c_a_0),
            Self::from(value.c_b.as_slice()),
            Self::from(
                value
                    .e
                    .iter()
                    .map(HashableMessage::from)
                    .collect::<Vec<Self>>(),
            ),
            Self::from(value.a.as_slice()),
            Self::from(&value.r),
            Self::from(&value.b),
            Self::from(&value.s),
            Self::from(&value.tau),
        ])
    }
}
