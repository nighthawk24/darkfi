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

use async_lock::Mutex as AsyncMutex;
use std::{
    cell::RefCell,
    sync::{Arc, OnceLock},
};

use crate::mesh::Color;

pub mod atlas;
mod editor;
pub use editor::Editor;
mod render;
pub use render::{render_layout, DebugRenderOptions};

thread_local! {
    static TEXT_CTX2: RefCell<TextContext> = RefCell::new(TextContext::new());
}

static TEXT_CTX: OnceLock<AsyncMutex<TextContext>> = OnceLock::new();

pub async fn get_ctx() -> async_lock::MutexGuard<'static, TextContext> {
    TEXT_CTX.get_or_init(|| AsyncMutex::new(TextContext::new())).lock().await
}

pub struct TextContext {
    font_ctx: parley::FontContext,
    layout_ctx: parley::LayoutContext<Color>,
}

impl TextContext {
    fn new() -> Self {
        let mut font_ctx = parley::FontContext::new();

        let font_data = include_bytes!("../../ibm-plex-mono-regular.otf") as &[u8];
        let font_inf =
            font_ctx.collection.register_fonts(peniko::Blob::new(Arc::new(font_data)), None);

        let font_data = include_bytes!("../../NotoColorEmoji.ttf") as &[u8];
        let font_inf =
            font_ctx.collection.register_fonts(peniko::Blob::new(Arc::new(font_data)), None);

        for (family_id, _) in font_inf {
            let family_name = font_ctx.collection.family_name(family_id).unwrap();
            trace!(target: "text", "Loaded font: {family_name}");
        }

        Self { font_ctx, layout_ctx: Default::default() }
    }

    pub fn borrow(&mut self) -> (&mut parley::FontContext, &mut parley::LayoutContext<Color>) {
        (&mut self.font_ctx, &mut self.layout_ctx)
    }

    pub fn make_layout(
        &mut self,
        text: &str,
        text_color: Color,
        font_size: f32,
        lineheight: f32,
        window_scale: f32,
        width: Option<f32>,
    ) -> parley::Layout<Color> {
        let mut builder = self.layout_ctx.ranged_builder(&mut self.font_ctx, &text, window_scale);
        builder.push_default(parley::StyleProperty::LineHeight(lineheight));
        builder.push_default(parley::StyleProperty::FontSize(font_size));
        builder.push_default(parley::StyleProperty::FontStack(parley::FontStack::List(
            FONT_STACK.into(),
        )));
        builder.push_default(parley::StyleProperty::Brush(text_color));

        let mut layout: parley::Layout<Color> = builder.build(&text);
        layout.break_all_lines(width);
        layout.align(width, parley::Alignment::Start, parley::AlignmentOptions::default());
        layout
    }
}

pub const FONT_STACK: &[parley::FontFamily<'_>] = &[
    parley::FontFamily::Named(std::borrow::Cow::Borrowed("IBM Plex Mono")),
    parley::FontFamily::Named(std::borrow::Cow::Borrowed("Noto Color Emoji")),
];
