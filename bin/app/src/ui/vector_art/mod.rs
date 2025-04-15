/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2025 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use async_trait::async_trait;
use rand::{rngs::OsRng, Rng};
use std::sync::{Arc, Mutex as SyncMutex, OnceLock, Weak};

use crate::{
    error::{Error, Result},
    expr::{Op, SExprCode, SExprMachine, SExprVal},
    gfx::{
        GfxBufferId, GfxDrawCall, GfxDrawInstruction, GfxDrawMesh, Rectangle, RenderApi, Vertex,
    },
    mesh::Color,
    prop::{
        PropertyAtomicGuard, PropertyBool, PropertyFloat32, PropertyPtr, PropertyRect,
        PropertyUint32, Role,
    },
    scene::{Pimpl, SceneNodePtr, SceneNodeWeak},
    util::{enumerate, unixtime},
    ExecutorPtr,
};

use super::{DrawUpdate, OnModify, UIObject};

pub mod shape;
use shape::VectorShape;

macro_rules! d { ($($arg:tt)*) => { debug!(target: "ui::vector_art", $($arg)*); } }
macro_rules! t { ($($arg:tt)*) => { trace!(target: "ui::vector_art", $($arg)*); } }

pub type VectorArtPtr = Arc<VectorArt>;

pub struct VectorArt {
    node: SceneNodeWeak,
    render_api: RenderApi,
    tasks: OnceLock<Vec<smol::Task<()>>>,

    shape: VectorShape,
    dc_key: u64,

    is_visible: PropertyBool,
    rect: PropertyRect,
    z_index: PropertyUint32,
    priority: PropertyUint32,

    parent_rect: SyncMutex<Option<Rectangle>>,
}

impl VectorArt {
    pub async fn new(
        node: SceneNodeWeak,
        shape: VectorShape,
        render_api: RenderApi,
        ex: ExecutorPtr,
    ) -> Pimpl {
        t!("VectorArt::new()");

        let node_ref = &node.upgrade().unwrap();
        let is_visible = PropertyBool::wrap(node_ref, Role::Internal, "is_visible", 0).unwrap();
        let rect = PropertyRect::wrap(node_ref, Role::Internal, "rect").unwrap();
        let z_index = PropertyUint32::wrap(node_ref, Role::Internal, "z_index", 0).unwrap();
        let priority = PropertyUint32::wrap(node_ref, Role::Internal, "priority", 0).unwrap();

        let node_name = node_ref.name.clone();
        let node_id = node_ref.id;

        let self_ = Arc::new(Self {
            node,
            render_api,
            tasks: OnceLock::new(),

            shape,
            dc_key: OsRng.gen(),

            is_visible,
            rect,
            z_index,
            priority,

            parent_rect: SyncMutex::new(None),
        });

        Pimpl::VectorArt(self_)
    }

    fn node_path(&self) -> String {
        format!("{:?}", self.node.upgrade().unwrap())
    }

    async fn redraw(self: Arc<Self>) {
        let trace_id = rand::random();
        let timest = unixtime();
        trace!(target: "ui::vector_art", "VectorArt::redraw({}) [trace_id={trace_id}]", self.node_path());
        let Some(parent_rect) = self.parent_rect.lock().unwrap().clone() else { return };

        let Some(draw_update) = self.get_draw_calls(parent_rect, trace_id).await else {
            error!(target: "ui::vector_art", "Mesh failed to draw [trace_id={trace_id}]");
            return
        };
        self.render_api.replace_draw_calls(timest, draw_update.draw_calls);
    }

    fn get_draw_instrs(&self) -> Vec<GfxDrawInstruction> {
        if !self.is_visible.get() {
            t!("Skipping draw for invisible {}", self.node_path());
            return vec![]
        }

        let rect = self.rect.get();
        let verts = self.shape.eval(rect.w, rect.h).expect("bad shape");

        //debug!(target: "ui::vector_art", "=> {verts:#?}");
        let vertex_buffer = self.render_api.new_vertex_buffer(verts);
        let index_buffer = self.render_api.new_index_buffer(self.shape.indices.clone());
        let mesh = GfxDrawMesh {
            vertex_buffer,
            index_buffer,
            texture: None,
            num_elements: self.shape.indices.len() as i32,
        };

        vec![GfxDrawInstruction::Move(rect.pos()), GfxDrawInstruction::Draw(mesh)]
    }

    async fn get_draw_calls(&self, parent_rect: Rectangle, trace_id: u32) -> Option<DrawUpdate> {
        if let Err(e) = self.rect.eval(&parent_rect) {
            warn!(target: "ui::vector_art", "Rect eval failure: {e} [trace_id={trace_id}]");
            return None
        }
        let instrs = self.get_draw_instrs();
        Some(DrawUpdate {
            key: self.dc_key,
            draw_calls: vec![(
                self.dc_key,
                GfxDrawCall { instrs, dcs: vec![], z_index: self.z_index.get() },
            )],
        })
    }
}

#[async_trait]
impl UIObject for VectorArt {
    fn priority(&self) -> u32 {
        self.priority.get()
    }

    async fn start(self: Arc<Self>, ex: ExecutorPtr) {
        let me = Arc::downgrade(&self);

        let mut on_modify = OnModify::new(ex, self.node.clone(), me.clone());
        on_modify.when_change(self.is_visible.prop(), Self::redraw);
        on_modify.when_change(self.rect.prop(), Self::redraw);
        on_modify.when_change(self.z_index.prop(), Self::redraw);

        self.tasks.set(on_modify.tasks);
    }

    async fn draw(
        &self,
        parent_rect: Rectangle,
        trace_id: u32,
        atom: &mut PropertyAtomicGuard,
    ) -> Option<DrawUpdate> {
        t!("VectorArt::draw({}) [trace_id={trace_id}]", self.node_path());
        *self.parent_rect.lock().unwrap() = Some(parent_rect);
        self.get_draw_calls(parent_rect, trace_id).await
    }
}

impl Drop for VectorArt {
    fn drop(&mut self) {
        self.render_api.replace_draw_calls(unixtime(), vec![(self.dc_key, Default::default())]);
    }
}
