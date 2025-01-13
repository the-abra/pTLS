use crate::crypto::{
    encryption::{Decrypt, Encrypt},
    signature::{Signing, Verifying},
};
use rsa::{
    sha2::{Sha224, Sha256, Sha384, Sha512},
    RsaPrivateKey, RsaPublicKey,
};

macro_rules! hash_enums {
    ($hash_functions:tt, [$( ($struct:ident, $new_arg:ty ) ),*]) => {
        hash_enums!(@define_hash_functions $hash_functions);

        $(
            hash_enums!(@define_hash_fields $hash_functions, $struct, $new_arg);
        )*
    };
    (@define_hash_functions [$( ($hash_function:ident, $id:expr) ),*]) => {
        /// Hash functions supported by pTLS.
        #[allow(unused)]
        pub enum HashFunction {
            $(
                $hash_function = $id
            ),*
        }
    };
    (@define_hash_fields [$( ($hash_function:ident, $id:expr) ),*], $struct:ident, $new_arg:ty) => {
        paste::paste! {
            #[allow(unused)]
            #[doc = "[`" $struct "`] hash functions."]
            pub enum [<$struct Function>] {
                $(
                    #[doc = "[`" $hash_function "`] hash funciton for [`" $struct "`]."]
                    $hash_function($struct<$hash_function>)
                ),*
            }

            #[allow(unused)]
            impl [<$struct Function>] {
                pub fn new(
                    hash_function: HashFunction,
                    [< $new_arg:snake >]: $new_arg,
                ) -> Result<Self, crate::crypto::Error> {
                    match hash_function {
                        $(
                            HashFunction::$hash_function => $struct::<$hash_function>::try_new([< $new_arg:snake >]).map(Self::$hash_function)
                        ),*
                    }
                }
            }
        }
    }
}

hash_enums!(
    [(Sha224, 0), (Sha256, 1), (Sha384, 2), (Sha512, 3)],
    [
        (Encrypt, RsaPublicKey),
        (Decrypt, RsaPrivateKey),
        (Signing, RsaPrivateKey),
        (Verifying, RsaPublicKey)
    ]
);
