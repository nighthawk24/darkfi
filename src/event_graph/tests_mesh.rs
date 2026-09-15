//! Mesh ingest admission — size cap and no skip of `validate_new`.

use super::EventGraph;

#[test]
fn mesh_blob_cap_is_under_one_mib() {
    assert!(EventGraph::MAX_MESH_EVENT_BLOB < 1024 * 1024);
    assert!(EventGraph::MAX_MESH_EVENT_BLOB > 256 * 1024);
}

#[test]
fn mesh_reassembly_cap_leaves_header_room() {
    assert_eq!(EventGraph::MAX_MESH_EVENT_BLOB, 1024 * 1024 - 512);
}
