//! Struct offsets of the game's objects, resolved from the signature table (`[[field]]`
//! entries, read from the operands of instructions of the client's own code) instead of being
//! written into the DLL. The values of the supported build are the table's `value` fields; the DLL never
//! uses them as a fallback: a field that does not resolve switches the features that list it
//! off (`sigs::Loaded::feature_ok`).
//!
//! Not in the table (still literal in the code, and listed in docs/architecture/client-dll.md):
//! the four terrain cell-grid vectors (+0xd0/+0xe8/+0x100/+0x118; the export checks each
//! vector's size against the grid size and writes nothing on a mismatch), the tile record
//! internals (the export recomputes the client's tile hash from them), the object layouts the
//! generator trace reads (research, off by default), the packet object's opcode (+8), the
//! stream socket (+0), and diagnostic-only reads of the movement log and entity probe.

use poe_hook_sig::Resolution;

macro_rules! offsets {
    ($($field:ident => $name:literal),* $(,)?) => {
        /// Resolved struct offsets (0 for a field that did not resolve).
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct Offsets {
            $(pub $field: usize,)*
        }

        impl Offsets {
            /// Table field names this struct reads.
            pub const NAMES: &'static [&'static str] = &[$($name),*];

            pub fn from_resolution(r: &Resolution) -> Self {
                Self { $($field: r.field($name).unwrap_or(0) as usize,)* }
            }
        }
    };
}

offsets! {
    // Entity (the component loop of Entity_ReadInitialState, Entity_Destroy, Entity_Update)
    entity_type => "entity.type",
    type_lookup => "type.lookup",
    lookup_serialized_count => "lookup.serialized_count",
    lookup_names_begin => "lookup.names_begin",
    lookup_names_end => "lookup.names_end",
    entity_components_begin => "entity.components_begin",
    entity_components_end => "entity.components_end",
    component_owner => "component.owner",
    component_vt_reader => "component.vt_reader",
    entity_tick_base => "entity.tick_base",
    entity_world => "entity.world",
    entity_id => "entity.id",
    // Positioned component
    positioned_grid_x => "positioned.grid_x",
    positioned_grid_y => "positioned.grid_y",
    positioned_facing => "positioned.facing",
    positioned_facing_lock => "positioned.facing_lock",
    positioned_world_x => "positioned.world_x",
    positioned_world_y => "positioned.world_y",
    world_vt_terrain => "world.vt_terrain",
    // Actor component
    actor_action0 => "actor.action0",
    actor_action1 => "actor.action1",
    action_type => "action.type",
    actor_dir_x => "actor.dir_x",
    actor_dir_y => "actor.dir_y",
    actor_sprint_flags => "actor.sprint_flags",
    // World
    world_frame_mode => "world.frame_mode",
    world_pause => "world.pause",
    world_frame_queue => "world.frame_queue",
    game_update_accumulator => "game.update_accumulator",
    world_area => "world.area",
    area_kind => "area.kind",
    world_tile_hash => "world.tile_hash",
    world_doodad_hash => "world.doodad_hash",
    // gen_batch: a synthetic world (docs/re/terrain/batch.md)
    world_stats => "world.stats",
    world_gen_flag => "world.gen_flag",
    world_gen_state => "world.gen_state",
    world_gen_seed => "world.gen_seed",
    world_league_mode => "world.league_mode",
    world_vt_delete => "world.vt_delete",
    generator_validate => "generator.validate",
    area_topology_count => "area.topology_count",
    area_topology_list => "area.topology_list",
    world_area_table => "world.area_table",
    resource_state => "resource.state",
    resource_refs => "resource.refs",
    table_rows => "table.rows",
    // Generator and terrain
    generator_world => "generator.world",
    generator_terrain => "generator.terrain",
    generator_state => "generator.state",
    state_seed => "state.seed",
    terrain_width => "terrain.width",
    terrain_height => "terrain.height",
    terrain_tiles => "terrain.tiles",
    // Network stream and session
    stream_error => "stream.error",
    stream_msg_read => "stream.msg_read",
    stream_recv_base => "stream.recv_base",
    stream_recv_end => "stream.recv_end",
    stream_recv_head => "stream.recv_head",
    stream_send_len => "stream.send_len",
    stream_send_buf => "stream.send_buf",
    stream_send_sent => "stream.send_sent",
    session_stream => "session.stream",
    // Crypto session
    crypto_key_buffer => "crypto.key_buffer",
}

#[cfg(test)]
mod tests {
    use super::*;
    use poe_hook_sig::embedded;

    /// Every field the code reads exists in the shipped table, and every table field is read
    /// (except the second reading of a member, which only checks the first).
    #[test]
    fn struct_and_table_agree() {
        let tables = embedded::tables().unwrap();
        for t in &tables {
            for n in Offsets::NAMES {
                assert!(
                    t.field(n).is_some(),
                    "table {} has no field {n}",
                    t.build.version
                );
            }
            for f in &t.field {
                if f.agrees_with.is_some() {
                    continue; // a cross-check of another field
                }
                assert!(
                    Offsets::NAMES.contains(&f.name.as_str()),
                    "table field {} is not used by Offsets",
                    f.name
                );
            }
        }
    }

    #[test]
    fn names_are_unique() {
        let mut n = Offsets::NAMES.to_vec();
        n.sort();
        n.dedup();
        assert_eq!(n.len(), Offsets::NAMES.len());
    }
}
