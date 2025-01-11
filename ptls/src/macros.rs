// Implements From<$error> for $self
macro_rules! error_impl_from {
    ($self:ident; $( $ident:ident ),*) => {
        $(
            paste::paste! {
                impl From<[<$ident Error>]> for $self {
                    fn from(error: [<$ident Error>]) -> Self {
                        Self::$ident(error)
                    }
                }
            }
        )*
    };
}

#[cfg(test)]
macro_rules! random_private_key {
    () => {{
        use rsa::RsaPrivateKey;
        RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap()
    }};
    ($bits:expr) => {{
        use rsa::RsaPrivateKey;
        RsaPrivateKey::new(&mut rand::thread_rng(), $bits).unwrap()
    }};
}
