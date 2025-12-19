use kernel::id::Id;

pub struct UserMarker;
pub type UserId = Id<UserMarker>;

impl UserMarker {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_new() {
        let user_id = UserId::new();
        let uuid = user_id.as_uuid();
        assert_eq!(uuid.get_version_num(), 4); // UUIDv4
    }

    #[test]
    fn test_from_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let user_id = UserId::from_uuid(uuid);
        assert_eq!(user_id.as_uuid(), &uuid);
    }
}
