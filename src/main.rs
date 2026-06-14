#![forbid(unsafe_code)]

use clap::{Arg, Command};

mod error;
mod protocol;
mod proxy;

#[tokio::main]
async fn main() {
    let matches = Command::new("trojan-rs")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .required(true)
                .num_args(1)
                .help(".toml config file name"),
        )
        .author("Developed by @p4gefau1t (Page Fault)")
        .about("An unidentifiable mechanism that helps you bypass GFW")
        .get_matches();
    let filename = matches.get_one::<String>("config").unwrap().to_string();
    if let Err(e) = proxy::launch_from_config_filename(filename).await {
        eprintln!("failed to launch proxy: {}", e);
        std::process::exit(1);
    }
}
