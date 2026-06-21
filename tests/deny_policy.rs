#[test]
fn rustsec_ignores_have_explicit_expiry_dates() {
    let deny = include_str!("../deny.toml");
    for line in deny
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("{ id = \"RUSTSEC-"))
    {
        let Some(expiry_start) = line.find("expires=") else {
            panic!("advisory ignore is missing expires=YYYY-MM-DD: {line}");
        };
        let expiry = &line[expiry_start + "expires=".len()..];
        let date = &expiry[..expiry.len().min(10)];
        assert!(
            is_iso_date(date),
            "advisory ignore expiry must use YYYY-MM-DD, got {date:?}: {line}"
        );
    }
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}
