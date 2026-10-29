//! Game log tab: this process's lines of the game's own `logs/Client.txt`.

use imgui::{ListClipper, Ui};

use super::follow::Follow;

pub struct GameLogView {
    filter: String,
    follow: Follow,
}

impl GameLogView {
    pub fn new() -> Self {
        Self {
            filter: String::new(),
            follow: Follow::new(),
        }
    }

    pub fn draw(&mut self, ui: &Ui) {
        ui.set_next_item_width(320.0);
        ui.input_text("Filter##gamelog", &mut self.filter).build();
        let f = self.filter.to_lowercase();
        let lines: Vec<String> = crate::gamelog::lines()
            .into_iter()
            .filter(|l| f.is_empty() || l.to_lowercase().contains(&f))
            .collect();
        ui.same_line();
        let mut follow = self.follow.following();
        if ui.checkbox("Follow##gamelog", &mut follow) {
            if follow {
                self.follow.jump();
            } else {
                self.follow.pause(lines.len());
            }
        }
        ui.text_disabled(format!(
            "{} lines (logs/Client.txt, this process)",
            lines.len()
        ));
        ui.child_window("gamelog_lines")
            .flags(imgui::WindowFlags::HORIZONTAL_SCROLLBAR)
            .build(ui, || {
                self.follow.begin(ui, lines.len());
                let mut clipper = ListClipper::new(lines.len()).begin(ui);
                while clipper.step() {
                    for i in clipper.display_start()..clipper.display_end() {
                        let l = &lines[i as usize];
                        let color = if l.contains("[CRIT") || l.contains("[ERROR") {
                            super::theme::DANGER
                        } else if l.contains("[WARN") {
                            super::theme::WARN
                        } else {
                            super::theme::TEXT
                        };
                        ui.text_colored(color, l);
                    }
                }
                self.follow.end(ui, lines.len());
            });
    }
}
