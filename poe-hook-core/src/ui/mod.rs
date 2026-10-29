//! The overlay's windows: the main debug window with its tabs, the read-only badge and
//! short notices. Each tab keeps its own state in [`App`].

mod commands_tab;
mod coverage_tab;
mod features_tab;
mod follow;
mod game_tab;
mod gamelog_tab;
mod hooks_tab;
mod inspect_tab;
mod instances_tab;
mod layout_form;
mod log_tab;
mod minimap_tab;
mod notes_tab;
mod packets_tab;
mod protocol_tab;
mod scanner_tab;
mod server_tab;
mod status_tab;
pub mod theme;
mod timing_tab;

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use imgui::{Condition, Ui, WindowFlags};

static NOTICES: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());
const NOTICE_TIME: Duration = Duration::from_secs(5);

/// A short message shown at the top of the screen for a few seconds (also logged).
pub fn notice(text: String) {
    log::info!("{text}");
    NOTICES.lock().unwrap().push((text, Instant::now()));
}

pub fn has_notices() -> bool {
    let mut n = NOTICES.lock().unwrap();
    n.retain(|(_, t)| t.elapsed() < NOTICE_TIME);
    !n.is_empty()
}

/// Whether features that talk to our server are shown: never while the read-only latch is on
/// (an official server), and only while every connection the game made is trusted (loopback
/// or `trusted_servers`, `poe_hook_shared::trust`), so nothing in the overlay can send to an
/// official server. The latch already covers the second condition; it is checked again here.
pub fn custom_server() -> bool {
    !crate::host::read_only() && crate::host::connections().iter().all(|c| c.trusted())
}

/// Plain-text summary of the client state (snapshots).
pub fn state_text() -> String {
    status_tab::state_text()
}

pub struct App {
    log: log_tab::LogView,
    packets: packets_tab::PacketsView,
    coverage: coverage_tab::CoverageView,
    timing: timing_tab::TimingView,
    gamelog: gamelog_tab::GameLogView,
    entities: inspect_tab::EntitiesView,
    watches: inspect_tab::WatchesView,
    hooks: hooks_tab::HooksView,
    protocol: protocol_tab::ProtocolView,
    scanner: scanner_tab::ScannerView,
    stats: game_tab::StatsView,
    minimap: minimap_tab::MinimapView,
    server: server_tab::ServerView,
    commands: commands_tab::CommandsView,
    instances: instances_tab::InstancesView,
    /// The heading font (Cinzel), when it loaded.
    heading: Option<imgui::FontId>,
    page: Page,
    /// The sub-page last shown per sidebar entry (an entry with tabs opens on it again).
    last_tab: Vec<(&'static str, Page)>,
    page_search: String,
    palette_query: String,
}

impl App {
    pub fn new(heading: Option<imgui::FontId>) -> Self {
        Self {
            heading,
            log: log_tab::LogView::new(),
            packets: packets_tab::PacketsView::new(),
            coverage: coverage_tab::CoverageView::new(),
            timing: timing_tab::TimingView::new(),
            gamelog: gamelog_tab::GameLogView::new(),
            entities: inspect_tab::EntitiesView::new(),
            watches: inspect_tab::WatchesView::new(),
            hooks: hooks_tab::HooksView::new(),
            protocol: protocol_tab::ProtocolView::new(),
            scanner: scanner_tab::ScannerView::new(),
            stats: game_tab::StatsView::new(),
            minimap: minimap_tab::MinimapView::new(),
            server: server_tab::ServerView::new(),
            commands: commands_tab::CommandsView::new(),
            instances: instances_tab::InstancesView::new(),
            page: load_page(),
            last_tab: Vec::new(),
            page_search: String::new(),
            palette_query: String::new(),
        }
    }

    pub fn draw(&mut self, ui: &Ui, visible: bool, plots: &dear_implot::PlotContext) {
        // Logs are pulled every drawn frame so nothing is missed while hidden.
        self.log.pull();
        self.scanner.update();
        if crate::host::read_only() {
            badge(ui);
        }
        notices(ui);
        if !visible {
            return;
        }
        let toggle = crate::config().overlay.toggle_key;
        ui.window("poe-hook##main2")
            .size([1500.0, 780.0], Condition::FirstUseEver)
            .position([40.0, 80.0], Condition::FirstUseEver)
            .build(|| {
                self.palette(ui);
                let avail = ui.content_region_avail();
                ui.child_window("nav")
                    .size([180.0, avail[1]])
                    .border(true)
                    .build(ui, || {
                        self.nav(ui);
                    });
                ui.same_line();
                ui.child_window("page").size([0.0, avail[1]]).build(ui, || {
                    self.draw_page(ui, plots);
                });
            });
        let _ = toggle;
    }

    /// The sidebar: groups (folding headers; Research starts folded) and their entries (our
    /// server's group hidden while read-only). With text in the search box: the matching pages.
    fn nav(&mut self, ui: &Ui) {
        ui.set_next_item_width(-1.0);
        ui.input_text("##page_search", &mut self.page_search)
            .hint("search pages")
            .build();
        ui.text_disabled("Ctrl+P: palette");
        let f = self.page_search.to_lowercase();
        if !f.is_empty() {
            let found: Vec<(Page, &str)> = pages()
                .filter(|(_, p, n)| {
                    visible(*p)
                        && (n.to_lowercase().contains(&f)
                            || format!("{p:?}").to_lowercase().contains(&f))
                })
                .map(|(_, p, n)| (p, n))
                .collect();
            ui.spacing();
            for (page, name) in found {
                if ui
                    .selectable_config(name)
                    .selected(self.page == page)
                    .build()
                {
                    self.go(page);
                }
            }
            return;
        }
        for g in GROUPS {
            if g.custom && !custom_server() {
                continue;
            }
            ui.spacing();
            let here = g
                .entries
                .iter()
                .any(|e| e.pages.iter().any(|(p, _)| *p == self.page));
            let flags = if g.folded && !here {
                imgui::TreeNodeFlags::empty()
            } else {
                imgui::TreeNodeFlags::DEFAULT_OPEN
            };
            let open = {
                // Separate bindings: tokens drop in reverse order (an array would drop them
                // first-to-last, which ImGui's scope check refuses).
                let _c0 = ui.push_style_color(imgui::StyleColor::Header, [0.0; 4]);
                let _c1 = ui.push_style_color(imgui::StyleColor::HeaderHovered, theme::SURFACE_2);
                let _c2 = ui.push_style_color(imgui::StyleColor::HeaderActive, theme::SURFACE_3);
                let _c3 = ui.push_style_color(imgui::StyleColor::Text, theme::GOLD);
                ui.collapsing_header(g.name, flags)
            };
            if !open {
                continue;
            }
            for e in g.entries {
                let selected = e.pages.iter().any(|(p, _)| *p == self.page);
                let _c =
                    selected.then(|| ui.push_style_color(imgui::StyleColor::Text, theme::GOLD_2));
                if ui
                    .selectable_config(format!("  {}##nav", e.name))
                    .selected(selected)
                    .build()
                    && !selected
                {
                    let last = self
                        .last_tab
                        .iter()
                        .find(|(n, _)| *n == e.name)
                        .map(|(_, p)| *p);
                    self.go(last.unwrap_or(e.pages[0].0));
                }
            }
        }
    }

    fn go(&mut self, page: Page) {
        self.page = page;
        if let Some(e) = entry_of(page) {
            match self.last_tab.iter_mut().find(|(n, _)| *n == e.name) {
                Some(slot) => slot.1 = page,
                None => self.last_tab.push((e.name, page)),
            }
        }
        save_page(page);
    }

    /// The page's heading and, for an entry with several pages, its tabs.
    fn page_head(&mut self, ui: &Ui) {
        let Some(e) = entry_of(self.page) else {
            return;
        };
        theme::heading(ui, self.heading, e.name);
        if e.pages.len() > 1 {
            let mut first = true;
            for (page, name) in e.pages {
                if !first {
                    ui.same_line();
                }
                first = false;
                let on = *page == self.page;
                let w = ui.calc_text_size(name)[0] + 20.0;
                // Separate bindings: tokens drop in reverse order (an array would drop them
                // first-to-last, which ImGui's scope check refuses).
                let _c0 = ui.push_style_color(
                    imgui::StyleColor::Text,
                    if on { theme::GOLD_2 } else { theme::MUTED },
                );
                let _c1 = ui.push_style_color(
                    imgui::StyleColor::Header,
                    theme::with_alpha(theme::CRIMSON, 0.4),
                );
                if ui
                    .selectable_config(format!("{name}##tab"))
                    .selected(on)
                    .size([w, 0.0])
                    .build()
                    && !on
                {
                    self.go(*page);
                }
            }
        }
        ui.separator();
        ui.spacing();
    }

    fn draw_page(&mut self, ui: &Ui, plots: &dear_implot::PlotContext) {
        // A page of our server only, while connected to an official one: back home.
        if page_is_custom(self.page) && !custom_server() {
            self.page = Page::Status;
        }
        self.page_head(ui);
        match self.page {
            Page::Status => status_tab::draw(ui),
            Page::Log => self.log.draw(ui),
            Page::GameLog => self.gamelog.draw(ui),
            Page::Instances => self.instances.draw(ui),
            Page::Commands => self.commands.draw(ui),
            Page::Server => self.server.draw_server(ui),
            Page::Desync => self.server.draw_desync(ui, plots),
            Page::Packets => self.packets.draw(ui),
            Page::Protocol => self.protocol.draw(ui),
            Page::Coverage => self.coverage.draw(ui),
            Page::Notes => notes_tab::draw(ui),
            Page::Timing => self.timing.draw(ui, plots),
            Page::Player => inspect_tab::draw_player(ui),
            Page::Stats => self.stats.draw(ui),
            Page::Actions => game_tab::draw_actions(ui),
            Page::Entities => self.entities.draw(ui),
            Page::Watches => self.watches.draw(ui),
            Page::Minimap => self.minimap.draw(ui),
            Page::Scanner => self.scanner.draw(ui),
            Page::Hooks => self.hooks.draw(ui),
            Page::Features => features_tab::draw(ui),
        }
    }

    /// Ctrl+P: jump to a page, or run a server command line (`transfer G1_6 ...`).
    fn palette(&mut self, ui: &Ui) {
        if ui.io().key_ctrl() && ui.is_key_pressed(imgui::Key::P) {
            self.palette_query.clear();
            ui.open_popup("##palette");
        }
        let Some(_p) = ui.begin_popup("##palette") else {
            return;
        };
        if ui.is_window_appearing() {
            let [w, _] = ui.io().display_size();
            ui.set_window_pos([w * 0.5 - 300.0, 120.0]);
            ui.set_window_size([600.0, 420.0]);
            ui.set_keyboard_focus_here();
        }
        ui.set_next_item_width(-1.0);
        let enter = ui
            .input_text("##palette_query", &mut self.palette_query)
            .hint("page name, or a server command line")
            .enter_returns_true(true)
            .build();
        let q = self.palette_query.trim().to_lowercase();
        let first_word = q.split_whitespace().next().unwrap_or("").to_string();
        let mut chosen: Option<PaletteItem> = None;
        let mut first: Option<PaletteItem> = None;
        for (entry, page, name) in pages() {
            if !visible(page) {
                continue;
            }
            if !q.is_empty()
                && !name.to_lowercase().contains(&q)
                && !entry.to_lowercase().contains(&q)
            {
                continue;
            }
            first.get_or_insert(PaletteItem::Page(page));
            let label = if entry == name {
                format!("Page: {name}")
            } else {
                format!("Page: {entry} / {name}")
            };
            if ui.selectable(label) {
                chosen = Some(PaletteItem::Page(page));
            }
        }
        if custom_server() {
            let (cmds, me) = crate::devlink::registry();
            let admin = me.is_some_and(|m| m.admin);
            for c in cmds.iter().filter(|c| admin || !c.admin) {
                if !q.is_empty() && !c.name.starts_with(&first_word) && !c.name.contains(&q) {
                    continue;
                }
                let line = if q.starts_with(&c.name) {
                    self.palette_query.trim().to_string()
                } else {
                    c.name.clone()
                };
                first.get_or_insert(PaletteItem::Command(
                    line.clone(),
                    c.args.iter().any(|a| !a.optional),
                ));
                let usage: Vec<String> = c
                    .args
                    .iter()
                    .map(|a| {
                        if a.optional {
                            format!("[{}]", a.name)
                        } else {
                            format!("<{}>", a.name)
                        }
                    })
                    .collect();
                if ui.selectable(format!(
                    "Run: {} {}  - {}##cmd{}",
                    c.name,
                    usage.join(" "),
                    c.help,
                    c.name
                )) {
                    chosen = Some(PaletteItem::Command(line, false));
                }
            }
        }
        if enter {
            chosen = first;
        }
        if ui.is_key_pressed(imgui::Key::Escape) {
            ui.close_current_popup();
            return;
        }
        match chosen {
            Some(PaletteItem::Page(p)) => {
                self.go(p);
                ui.close_current_popup();
            }
            // A bare command that needs arguments: open its form instead of running it.
            Some(PaletteItem::Command(line, needs_args)) if needs_args && !line.contains(' ') => {
                self.go(Page::Commands);
                ui.close_current_popup();
            }
            Some(PaletteItem::Command(line, _)) => {
                crate::devlink::command(&line);
                ui.close_current_popup();
            }
            None => {}
        }
    }
}

enum PaletteItem {
    Page(Page),
    /// The command line to run, and whether it still needs arguments.
    Command(String, bool),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Page {
    Status,
    Log,
    GameLog,
    Instances,
    Commands,
    Server,
    Desync,
    Packets,
    Protocol,
    Coverage,
    Notes,
    Timing,
    Player,
    Stats,
    Actions,
    Entities,
    Watches,
    Minimap,
    Scanner,
    Hooks,
    Features,
}

/// A sidebar entry: its pages show as tabs when there are several.
struct Entry {
    name: &'static str,
    pages: &'static [(Page, &'static str)],
}

/// A sidebar group: a folding header.
struct Group {
    name: &'static str,
    /// Pages of our server only (hidden while read-only).
    custom: bool,
    /// Starts folded (the research tools).
    folded: bool,
    entries: &'static [Entry],
}

const GROUPS: &[Group] = &[
    Group {
        name: "PLAY",
        custom: false,
        folded: false,
        entries: &[
            Entry {
                name: "Status",
                pages: &[(Page::Status, "Status")],
            },
            Entry {
                name: "Game",
                pages: &[
                    (Page::Player, "Player"),
                    (Page::Stats, "Stats"),
                    (Page::Actions, "Actions"),
                    (Page::Entities, "Entities"),
                    (Page::Watches, "Watches"),
                ],
            },
            Entry {
                name: "Minimap",
                pages: &[(Page::Minimap, "Minimap")],
            },
        ],
    },
    Group {
        name: "SERVER",
        custom: true,
        folded: false,
        entries: &[
            Entry {
                name: "Instances",
                pages: &[(Page::Instances, "Instances")],
            },
            Entry {
                name: "Commands",
                pages: &[(Page::Commands, "Commands")],
            },
            Entry {
                name: "Sync",
                pages: &[(Page::Server, "Sync state"), (Page::Desync, "Desync")],
            },
        ],
    },
    Group {
        name: "LOGS",
        custom: false,
        folded: false,
        entries: &[Entry {
            name: "Live logs",
            pages: &[(Page::Log, "Log"), (Page::GameLog, "Game log")],
        }],
    },
    Group {
        name: "RESEARCH",
        custom: false,
        folded: true,
        entries: &[
            Entry {
                name: "Network",
                pages: &[
                    (Page::Packets, "Packets"),
                    (Page::Protocol, "Protocol"),
                    (Page::Coverage, "Coverage"),
                    (Page::Notes, "Notes"),
                    (Page::Timing, "Timing"),
                ],
            },
            Entry {
                name: "RE tools",
                pages: &[(Page::Scanner, "Scanner"), (Page::Hooks, "Hooks")],
            },
        ],
    },
    Group {
        name: "SETTINGS",
        custom: false,
        folded: false,
        entries: &[Entry {
            name: "Features",
            pages: &[(Page::Features, "Features")],
        }],
    },
];

/// Every page with its entry's name and its own name, in sidebar order.
fn pages() -> impl Iterator<Item = (&'static str, Page, &'static str)> {
    GROUPS
        .iter()
        .flat_map(|g| g.entries.iter())
        .flat_map(|e| e.pages.iter().map(move |(p, n)| (e.name, *p, *n)))
}

fn entry_of(page: Page) -> Option<&'static Entry> {
    GROUPS
        .iter()
        .flat_map(|g| g.entries.iter())
        .find(|e| e.pages.iter().any(|(p, _)| *p == page))
}

fn page_is_custom(page: Page) -> bool {
    GROUPS.iter().any(|g| {
        g.custom
            && g.entries
                .iter()
                .any(|e| e.pages.iter().any(|(p, _)| *p == page))
    })
}

/// Whether the page may be shown now (our server's pages only while on our server).
fn visible(page: Page) -> bool {
    !page_is_custom(page) || custom_server()
}

fn page_path() -> std::path::PathBuf {
    poe_hook_shared::exe_dir()
        .join("logs")
        .join("poe-hook")
        .join("overlay_page.txt")
}

fn save_page(page: Page) {
    let _ = std::fs::write(page_path(), format!("{page:?}"));
}

/// The page selected last time (kept across sessions).
fn load_page() -> Page {
    let name = std::fs::read_to_string(page_path()).unwrap_or_default();
    pages()
        .map(|(_, p, _)| p)
        .find(|p| format!("{p:?}") == name.trim())
        .unwrap_or(Page::Status)
}

/// Table options for the overlay's tables: columns fit their contents, resizable, striped.
pub fn table_opts() -> imgui::TableOptions {
    imgui::TableOptions::from(imgui::TableFlags::RESIZABLE | imgui::TableFlags::ROW_BG)
        .sizing_policy(imgui::TableSizingPolicy::FixedFit)
}

/// Shows a memory region in the Scanner tab.
pub fn scanner_request(expr: String, len: usize) {
    scanner_tab::request(expr, len);
}

/// Copies text to the system clipboard.
pub fn set_clipboard(text: &str) {
    let c = std::ffi::CString::new(text.replace('\0', "?")).unwrap_or_default();
    unsafe { imgui::sys::igSetClipboardText(c.as_ptr()) };
}

/// Top-left position that centres a one-line window of `text` horizontally.
fn centred(ui: &Ui, text: &str, y: f32) -> [f32; 2] {
    let [w, _] = ui.io().display_size();
    let tw = ui.calc_text_size(text)[0];
    [(w - tw) * 0.5 - 8.0, y]
}

const BADGE: &str = "OFFICIAL: read-only";

fn badge(ui: &Ui) {
    ui.window("##read-only")
        .position(centred(ui, BADGE, 6.0), Condition::Always)
        .flags(
            WindowFlags::NO_DECORATION
                | WindowFlags::NO_INPUTS
                | WindowFlags::ALWAYS_AUTO_RESIZE
                | WindowFlags::NO_SAVED_SETTINGS
                | WindowFlags::NO_FOCUS_ON_APPEARING
                | WindowFlags::NO_NAV,
        )
        .bg_alpha(0.75)
        .build(|| {
            ui.text_colored(theme::WARN, BADGE);
        });
}

fn notices(ui: &Ui) {
    let list: Vec<String> = {
        let mut n = NOTICES.lock().unwrap();
        n.retain(|(_, t)| t.elapsed() < NOTICE_TIME);
        n.iter().map(|(s, _)| s.clone()).collect()
    };
    if list.is_empty() {
        return;
    }
    let longest = list
        .iter()
        .max_by_key(|s| s.len())
        .cloned()
        .unwrap_or_default();
    ui.window("##notices")
        .position(centred(ui, &longest, 44.0), Condition::Always)
        .flags(
            WindowFlags::NO_DECORATION
                | WindowFlags::NO_INPUTS
                | WindowFlags::ALWAYS_AUTO_RESIZE
                | WindowFlags::NO_SAVED_SETTINGS
                | WindowFlags::NO_FOCUS_ON_APPEARING
                | WindowFlags::NO_NAV,
        )
        .bg_alpha(0.8)
        .build(|| {
            for s in &list {
                ui.text(s);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_is_in_the_sidebar_once() {
        let all = [
            Page::Status,
            Page::Log,
            Page::GameLog,
            Page::Instances,
            Page::Commands,
            Page::Server,
            Page::Desync,
            Page::Packets,
            Page::Protocol,
            Page::Coverage,
            Page::Notes,
            Page::Timing,
            Page::Player,
            Page::Stats,
            Page::Actions,
            Page::Entities,
            Page::Watches,
            Page::Minimap,
            Page::Scanner,
            Page::Hooks,
            Page::Features,
        ];
        for p in all {
            assert_eq!(pages().filter(|(_, q, _)| *q == p).count(), 1, "{p:?}");
        }
        assert_eq!(pages().count(), all.len());
    }

    #[test]
    fn groups_fold_and_hide_as_agreed() {
        assert!(GROUPS.iter().find(|g| g.name == "RESEARCH").unwrap().folded);
        assert!(page_is_custom(Page::Desync));
        assert!(!page_is_custom(Page::Log));
        assert_eq!(entry_of(Page::GameLog).unwrap().name, "Live logs");
    }
}
