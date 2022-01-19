use chrono::{DateTime, TimeZone, Utc};

lazy_static! {
    pub static ref ZERO_TS: DateTime<Utc> = Utc.timestamp_millis(100);
}

#[macro_export]
macro_rules! ord_by_date_id {
    ($name:ident) => {
        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                let zero = &crate::structs::utils::ZERO_TS;
                if self.created_at.eq(zero) && other.created_at.ne(zero) {
                    std::cmp::Ordering::Less
                } else if self.created_at.ne(zero) && other.created_at.eq(zero) {
                    std::cmp::Ordering::Greater
                } else if self.created_at.eq(&other.created_at) {
                    self.id.cmp(&other.id)
                } else {
                    self.created_at.cmp(&other.created_at)
                }
            }
        }

        impl std::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use std::cmp::Ordering;
    use uuid::Uuid;

    #[derive(PartialEq, Eq, Debug)]
    struct TestData {
        pub id: Uuid,
        pub created_at: DateTime<Utc>,
    }

    ord_by_date_id!(TestData);

    #[test]
    fn ord_by_date() {
        chrono::TimeZone::timestamp_millis(&Utc, 0);
        let value1 = TestData {
            id: Default::default(),
            created_at: Utc.timestamp_millis(100),
        };
        let value2 = TestData {
            id: Default::default(),
            created_at: Utc.timestamp_millis(200),
        };

        assert_eq!(value1.cmp(&value2), Ordering::Less);
        assert_eq!(value2.cmp(&value1), Ordering::Greater);
    }

    #[test]
    fn ord_greater_with_date() {
        let value1 = TestData {
            id: Default::default(),
            created_at: Utc.timestamp_millis(0),
        };
        let value2 = TestData {
            id: Default::default(),
            created_at: Utc.timestamp_millis(200),
        };

        assert_eq!(value1.cmp(&value2), Ordering::Less);
        assert_eq!(value2.cmp(&value1), Ordering::Greater);
    }

    #[test]
    fn ord_same_date_by_id() {
        let value1 = TestData {
            id: Uuid::parse_str("46805dff-a6e0-434d-be7d-5ef7931522d0").unwrap(),
            created_at: Utc.timestamp_millis(0),
        };
        let value2 = TestData {
            id: Uuid::parse_str("36805dff-a6e0-434d-be7d-5ef7931522d0").unwrap(),
            created_at: Utc.timestamp_millis(200),
        };

        assert_eq!(value1.cmp(&value2), Ordering::Less);
        assert_eq!(value2.cmp(&value1), Ordering::Greater);
    }
}
