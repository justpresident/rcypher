use chrono::{Local, TimeZone};

pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "N/A".to_string();
    }
    let dt = Local
        .timestamp_opt(ts.try_into().expect("invalid timestamp"), 0)
        .unwrap();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}
