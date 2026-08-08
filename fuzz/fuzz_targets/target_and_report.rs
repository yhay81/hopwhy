#![no_main]

use hopwhy::model::InspectionOptions;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    let _ = hopwhy::offline::parse_report_document(data);
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(target) = hopwhy::policy::parse_target(text, &InspectionOptions::default()) {
            if let Ok(address) = target.summary.host.parse::<Ipv6Addr>() {
                let address = IpAddr::V6(address);
                let _ = hopwhy::policy::classify_ip(address);
                let _ = hopwhy::policy::is_ip_permitted(address, false);
            }
        }
    }
});
