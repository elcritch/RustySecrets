extern crate rusty_secrets;

use rusty_secrets::sss::generate_shares_format;
use rusty_secrets::sss::ShareFormatKind;

#[test]
fn test_generate_basic_share() {
    let share1 = "some super duper secret".to_string().into_bytes();

    let res = generate_shares_format(2, 2, &share1, false, ShareFormatKind::Json).unwrap();

    println!("TEST_RESULT: test_generate_basic_share: {:?}", res);

    assert_eq!(s.get_secret().to_owned(), secret);
}

// #[test]
// #[should_panic(expected = "Threshold K can not be larger than N")]
// fn test_generate_invalid_k() {
//     let share1 = "2-1-1YAYwmOHqZ69jA".to_string().into_bytes();
//
//     generate_shares(10, 5, share1.as_slice(), true).unwrap();
// }
