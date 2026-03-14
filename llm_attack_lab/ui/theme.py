from __future__ import annotations

THEMES = ["Fluent Light", "Fluent Dark", "Cyber Punk", "Midnight Hacker", "Blood Red"]


def _qss(scale: float = 1.0, theme_name: str = "Fluent Light") -> str:
    s = max(0.75, min(2.5, float(scale)))
    fs = int(round(12 * s))
    fs_small = int(round(10 * s))
    pad_v = int(round(6 * s))
    pad_h = int(round(10 * s))
    tab_pad_v = int(round(9 * s))
    tab_pad_h = int(round(14 * s))
    min_edit_h = int(round(32 * s))
    edit_pad_h = int(round(12 * s))
    te_pad = int(round(8 * s))
    radius = int(round(6 * s))
    radius_sm = int(round(4 * s))

    if theme_name == "Fluent Dark":
        bg="#1e1e1e"; fg="#d4d4d4"; pane_bg="#252526"; border="#3c3c3c"
        tab_bg="transparent"; tab_hover="#2a2d2e"; tab_sel="#1e1e1e"
        accent="#569cd6"; accent_hover="#4e8fc4"; accent_pressed="#3a78b5"; accent_fg="#ffffff"
        input_bg="#1e1e1e"; sb_bg="#424242"; sb_hover="#686868"; header_bg="#252526"
        group_title="#569cd6"; dock_title="#252526"; btn_secondary="#3c3c3c"
        btn_sec_fg="#d4d4d4"; btn_sec_hover="#4a4a4a"; status_bar="#007acc"
        status_fg="#ffffff"; sel_bg="#264f78"; row_alt="#2a2a2a"
        font_family="'Segoe UI Variable','Segoe UI','Inter',sans-serif"
        font_family_mono="'Cascadia Code','Consolas','Courier New',monospace"

    elif theme_name == "Cyber Punk":
        bg="#09090d"; fg="#e0e0f0"; pane_bg="#0f0f1a"; border="#2a0a4a"
        tab_bg="transparent"; tab_hover="#1a0a2e"; tab_sel="#0f0f1a"
        accent="#ff00ff"; accent_hover="#dd00dd"; accent_pressed="#aa0099"; accent_fg="#ffffff"
        input_bg="#050510"; sb_bg="#3a0060"; sb_hover="#6600aa"; header_bg="#0a0a14"
        group_title="#ff00ff"; dock_title="#0f0f1a"; btn_secondary="#1a0a2e"
        btn_sec_fg="#cc00ff"; btn_sec_hover="#220a3e"; status_bar="#330066"
        status_fg="#ff00ff"; sel_bg="#550088"; row_alt="#0d0d1c"
        font_family="'Consolas','Courier New','Lucida Console',monospace"
        font_family_mono="'Consolas','Courier New',monospace"

    elif theme_name == "Midnight Hacker":
        bg="#030508"; fg="#c8e0ff"; pane_bg="#060b12"; border="#0d2040"
        tab_bg="transparent"; tab_hover="#0a1828"; tab_sel="#060b12"
        accent="#00d4ff"; accent_hover="#00b8de"; accent_pressed="#008fb0"; accent_fg="#000000"
        input_bg="#020408"; sb_bg="#0d2a40"; sb_hover="#1a4870"; header_bg="#040810"
        group_title="#00d4ff"; dock_title="#060b12"; btn_secondary="#0a1828"
        btn_sec_fg="#00d4ff"; btn_sec_hover="#0d2040"; status_bar="#00263a"
        status_fg="#00d4ff"; sel_bg="#003850"; row_alt="#080d14"
        font_family="'Consolas','Courier New','Lucida Console',monospace"
        font_family_mono="'Consolas','Courier New',monospace"

    elif theme_name == "Blood Red":
        bg="#0d0505"; fg="#f0d0d0"; pane_bg="#140808"; border="#3a0a0a"
        tab_bg="transparent"; tab_hover="#200808"; tab_sel="#140808"
        accent="#ff2244"; accent_hover="#dd1a33"; accent_pressed="#aa1222"; accent_fg="#ffffff"
        input_bg="#0a0303"; sb_bg="#400a0a"; sb_hover="#700f0f"; header_bg="#0f0505"
        group_title="#ff2244"; dock_title="#140808"; btn_secondary="#200808"
        btn_sec_fg="#ff4466"; btn_sec_hover="#2a0a0a"; status_bar="#1a0505"
        status_fg="#ff2244"; sel_bg="#500a0a"; row_alt="#110606"
        font_family="'Consolas','Courier New','Lucida Console',monospace"
        font_family_mono="'Consolas','Courier New',monospace"

    else:  # Fluent Light
        bg="#f3f3f3"; fg="#202020"; pane_bg="#ffffff"; border="#e0e0e0"
        tab_bg="transparent"; tab_hover="#ededed"; tab_sel="#ffffff"
        accent="#0067c0"; accent_hover="#005a9e"; accent_pressed="#004c87"; accent_fg="#ffffff"
        input_bg="#ffffff"; sb_bg="#c0c0c0"; sb_hover="#a0a0a0"; header_bg="#f3f3f3"
        group_title="#0067c0"; dock_title="#f3f3f3"; btn_secondary="#e8e8e8"
        btn_sec_fg="#202020"; btn_sec_hover="#d8d8d8"; status_bar="#0067c0"
        status_fg="#ffffff"; sel_bg="#cce4ff"; row_alt="#f9f9f9"
        font_family="'Segoe UI Variable','Segoe UI','Inter',sans-serif"
        font_family_mono="'Cascadia Code','Consolas','Courier New',monospace"

    glow_focus = f"border: 2px solid {accent}; background-color: {input_bg};"
    btn_glow = "text-shadow: 0 0 8px currentColor;" if theme_name == "Cyber Punk" else ""

    return f'''
QWidget {{ background-color: {bg}; color: {fg}; font-family: {font_family}; font-size: {fs}px; }}
QMainWindow, QDialog {{ background-color: {bg}; }}
QDockWidget {{ background-color: {dock_title}; border: 1px solid {border}; font-weight: 600; font-size: {fs_small}px; }}
QDockWidget::title {{ background-color: {dock_title}; padding: {pad_v}px {pad_h}px; color: {group_title}; border-bottom: 1px solid {border}; letter-spacing: 1px; }}
QDockWidget::close-button, QDockWidget::float-button {{ background: transparent; border: none; padding: 2px; }}
QTabWidget::pane {{ border: 1px solid {border}; background-color: {pane_bg}; border-radius: {radius}px; margin-top: -1px; }}
QTabBar::tab {{ background-color: {tab_bg}; color: {fg}; padding: {tab_pad_v}px {tab_pad_h}px; margin-right: 2px; border-radius: {radius_sm}px {radius_sm}px 0 0; font-size: {fs_small}px; letter-spacing: 0.5px; }}
QTabBar::tab:hover {{ background-color: {tab_hover}; color: {accent}; }}
QTabBar::tab:selected {{ background-color: {tab_sel}; color: {accent}; border-bottom: 3px solid {accent}; font-weight: 700; }}
QGroupBox {{ border: 1px solid {border}; border-radius: {radius}px; margin-top: {int(round(22*s))}px; font-weight: 700; font-size: {fs_small}px; letter-spacing: 1px; background-color: {pane_bg}; padding-top: {int(round(8*s))}px; }}
QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top left; left: {int(round(12*s))}px; top: -{int(round(10*s))}px; padding: 0 6px; color: {group_title}; font-size: {fs_small}px; font-weight: 700; letter-spacing: 1.5px; }}
QPushButton {{ background-color: {accent}; border: none; border-radius: {radius_sm}px; padding: {pad_v}px {pad_h}px; color: {accent_fg}; font-weight: 600; font-size: {fs_small}px; min-height: {int(round(28*s))}px; {btn_glow} }}
QPushButton:hover {{ background-color: {accent_hover}; }}
QPushButton:pressed {{ background-color: {accent_pressed}; }}
QPushButton:disabled {{ background-color: {border}; color: {sb_bg}; }}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {{ background-color: {input_bg}; border: 1px solid {border}; border-radius: {radius_sm}px; color: {fg}; selection-background-color: {sel_bg}; selection-color: {fg}; }}
QLineEdit, QComboBox, QSpinBox {{ min-height: {min_edit_h}px; padding: 0px {edit_pad_h}px; }}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ {glow_focus} }}
QPlainTextEdit, QTextEdit {{ padding: {te_pad}px; border-radius: {radius}px; font-family: {font_family_mono}; font-size: {fs_small}px; }}
QListWidget, QTreeWidget, QTableWidget {{ background-color: {input_bg}; border: 1px solid {border}; border-radius: {radius_sm}px; color: {fg}; selection-background-color: {sel_bg}; alternate-background-color: {row_alt}; gridline-color: {border}; outline: none; }}
QListWidget::item, QTreeWidget::item {{ padding: {int(round(4*s))}px {int(round(6*s))}px; border-bottom: 1px solid {border}; }}
QListWidget::item:hover, QTreeWidget::item:hover {{ background-color: {tab_hover}; color: {accent}; }}
QListWidget::item:selected, QTreeWidget::item:selected, QTableWidget::item:selected {{ background-color: {sel_bg}; color: {fg}; }}
QHeaderView::section {{ background-color: {header_bg}; color: {group_title}; border: none; border-bottom: 2px solid {border}; border-right: 1px solid {border}; padding: {int(round(6*s))}px {int(round(8*s))}px; font-weight: 700; font-size: {fs_small}px; letter-spacing: 1px; text-transform: uppercase; }}
QTableWidget {{ gridline-color: {border}; border-radius: {radius_sm}px; }}
QScrollBar:vertical {{ background: transparent; width: {int(round(10*s))}px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {sb_bg}; min-height: 20px; border-radius: {int(round(5*s))}px; margin: 2px; }}
QScrollBar::handle:vertical:hover {{ background: {sb_hover}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: {int(round(10*s))}px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {sb_bg}; min-width: 20px; border-radius: {int(round(5*s))}px; margin: 2px; }}
QScrollBar::handle:horizontal:hover {{ background: {sb_hover}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QMenuBar {{ background-color: {bg}; color: {fg}; border-bottom: 1px solid {border}; padding: 2px; font-size: {fs_small}px; }}
QMenuBar::item:selected {{ background-color: {tab_hover}; color: {accent}; border-radius: {radius_sm}px; }}
QMenu {{ background-color: {pane_bg}; border: 1px solid {border}; color: {fg}; padding: 4px; border-radius: {radius_sm}px; }}
QMenu::item {{ padding: {int(round(5*s))}px {int(round(20*s))}px; border-radius: {radius_sm}px; }}
QMenu::item:selected {{ background-color: {accent}; color: {accent_fg}; }}
QMenu::separator {{ height: 1px; background: {border}; margin: 4px; }}
QStatusBar {{ background-color: {status_bar}; color: {status_fg}; font-size: {fs_small}px; font-weight: 600; letter-spacing: 0.5px; border-top: 1px solid {border}; padding: 2px 8px; }}
QStatusBar::item {{ border: none; }}
QSplitter::handle {{ background-color: {border}; }}
QSplitter::handle:horizontal {{ width: 2px; }}
QSplitter::handle:vertical {{ height: 2px; }}
QToolTip {{ background-color: {pane_bg}; color: {fg}; border: 1px solid {accent}; padding: 4px 8px; border-radius: {radius_sm}px; font-size: {fs_small}px; }}
QCheckBox, QRadioButton {{ spacing: {int(round(6*s))}px; font-size: {fs_small}px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: {int(round(16*s))}px; height: {int(round(16*s))}px; border: 2px solid {border}; border-radius: {radius_sm}px; background: {input_bg}; }}
QCheckBox::indicator:checked {{ background-color: {accent}; border-color: {accent}; }}
QRadioButton::indicator {{ border-radius: {int(round(8*s))}px; }}
QRadioButton::indicator:checked {{ background-color: {accent}; border-color: {accent}; }}
QSlider::groove:horizontal {{ height: {int(round(4*s))}px; background: {border}; border-radius: 2px; }}
QSlider::handle:horizontal {{ background: {accent}; width: {int(round(16*s))}px; height: {int(round(16*s))}px; margin: -{int(round(6*s))}px 0; border-radius: {int(round(8*s))}px; }}
QSlider::sub-page:horizontal {{ background: {accent}; border-radius: 2px; }}
QProgressBar {{ background: {border}; border: 1px solid {border}; border-radius: {radius_sm}px; text-align: center; color: {fg}; font-size: {fs_small}px; font-weight: 600; height: {int(round(16*s))}px; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {accent_hover},stop:1 {accent}); border-radius: {radius_sm}px; }}
'''


def apply_theme(app, scale: float = 1.0, theme_name: str = "Fluent Light"):
    app.setStyleSheet(_qss(scale, theme_name))


def theme_list() -> list:
    return list(THEMES)
