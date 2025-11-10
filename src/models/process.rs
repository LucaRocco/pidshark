use zerocopy::{Immutable, KnownLayout, TryFromBytes};

type EventType = u8;

#[repr(C)]
#[derive(
    Debug, Copy, Clone, serde::Serialize, serde::Deserialize, TryFromBytes, KnownLayout, Immutable,
)]
pub struct Namespaces {
    pub uts: u32,
    pub ipc: u32,
    pub mnt: u32,
    pub pid: u32,
    pub net: u32,
    pub time: u32,
    pub cgroup: u32,
}

#[repr(C)]
#[derive(
    Debug, Copy, Clone, serde::Serialize, serde::Deserialize, TryFromBytes, KnownLayout, Immutable,
)]
pub struct Process {
    pub event_type: EventType,
    #[serde(with = "u8_array_16_as_string")]
    pub name: [u8; 16usize],
    pub tid: i32,
    pub pid: i32,
    pub ppid: i32,
    pub ns_tid: i32,
    pub ns_pid: i32,
    pub ns_ppid: i32,
    pub uid: u32,
    pub gid: u32,
    pub start_time: u64,
    pub parent_start_time: u64,
    pub namespaces: Namespaces,
}

mod u8_array_16_as_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let trimmed = match value.iter().position(|&b| b == 0) {
            Some(pos) => &value[..pos],
            None => value,
        };

        let s = String::from_utf8_lossy(trimmed).to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = s.as_bytes();

        let mut arr = [0u8; 16];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(arr)
    }
}
