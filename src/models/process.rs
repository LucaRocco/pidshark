use zerocopy::{Immutable, KnownLayout, TryFromBytes};

const MAX_DIM: usize = 16000;

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
#[derive(Debug, Copy, Clone, TryFromBytes, KnownLayout, Immutable)]
pub struct DynamicString {
    pub start: u32,
    pub end: u32,
    pub string: [u8; MAX_DIM],
}

impl serde::Serialize for DynamicString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let slice = &self.string[self.start as usize..self.end as usize];

        let s = slice
            .split(|&b| b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part))
            .collect::<Vec<_>>()
            .join(" ");

        serializer.serialize_str(&s)
    }
}

impl<'de> serde::Deserialize<'de> for DynamicString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        let bytes = s.as_bytes();

        let mut arr = [0u8; MAX_DIM];
        let len = bytes.len().min(MAX_DIM);
        arr[..len].copy_from_slice(&bytes[..len]);

        Ok(DynamicString {
            start: 0,
            end: len as u32,
            string: arr,
        })
    }
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
    #[serde(with = "u8_array_16_as_string")]
    pub filename: [u8; 16usize],

    pub namespaces: Namespaces,

    pub args: DynamicString,
    pub envs: DynamicString,
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
