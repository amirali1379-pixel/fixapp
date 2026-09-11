#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketAction {
    Pass,
    Drop,
    Modify,
    Reinject,
}
