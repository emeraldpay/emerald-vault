use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;
use regex::Regex;

pub(crate) fn try_vault_file(file: &Path, suffix: &str) -> Result<Uuid, ()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?P<id>[0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\.(?P<suffix>[a-z]+)").unwrap();
    }

    match file.file_name() {
        Some(name) => {
            let file_name = name.to_str().unwrap();
            match RE.captures(file_name) {
                Some(caps) => {
                    let act_suffix = caps.name("suffix").unwrap().as_str();
                    if act_suffix.eq(suffix) {
                        let id: &str = caps.name("id").unwrap().as_str();
                        let uuid = Uuid::from_str(id).unwrap();
                        if format!("{}.{}", &uuid, suffix).eq(file_name) {
                            Ok(uuid)
                        } else {
                            Err(())
                        }
                    } else {
                        Err(())
                    }
                }
                None => Err(()),
            }
        }
        None => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn try_vault_file_from_standard() {
        let act = try_vault_file(Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key"), "key");
        assert!(act.is_ok());
        assert_eq!(
            Uuid::from_str("3221aabc-b3ff-4235-829f-9599aba04cb5").unwrap(),
            act.unwrap()
        );
    }

    #[test]
    fn try_vault_file_from_invalid_suffix() {
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.seed"),
            "key",
        );
        assert!(act.is_err());
    }

    #[test]
    fn try_vault_file_from_invalid_name() {
        let act = try_vault_file(Path::new("9599aba04cb5.key"), "key");
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key.bak"),
            "key",
        );
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("~3221aabc-b3ff-4235-829f-9599aba04cb5.key"),
            "key",
        );
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.~key"),
            "key",
        );
        assert!(act.is_err());
        let act = try_vault_file(
            Path::new("3221aabc-b3ff-4235-829f-9599aba04cb5.key~"),
            "key",
        );
        assert!(act.is_err());
    }
}
