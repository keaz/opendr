#![no_main]

use ldap_parser::parse_ldap_messages;
use libfuzzer_sys::fuzz_target;
use opendr::ber_decoder_fsm::{BerDecoderConfig, BerDecoderFsmImpl};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }

    let _ = parse_ldap_messages(data);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let mut decoder = BerDecoderFsmImpl::with_config(BerDecoderConfig {
            max_message_size: 16 * 1024,
            max_buffer_size: 32 * 1024,
            message_timeout: Some(Duration::from_millis(100)),
            strict_validation: true,
        });
        let _ = decoder.decode_available_messages(data).await;
    });
});
