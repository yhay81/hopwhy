#![no_main]

use hopwhy::model::InspectionOptions;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hopwhy::offline::parse_report_document(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = hopwhy::policy::parse_target(text, &InspectionOptions::default());
    }
});
