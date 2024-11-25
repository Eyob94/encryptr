#[derive(Debug, Clone)]
pub struct Config {
    pub in_file: String,
    pub out_file: Option<String>,
    pub enc_algorithm: Algorithm,
}

#[derive(Debug, Clone)]
pub enum Algorithm {
    ChaChaPoly,
    AesGcm,
}
