"""
Theme selection for the GUI: builds a QPalette and a QMenu/QMenuBar
stylesheet from a vendored qt_themes.Theme, and persists the chosen one.
"""

from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QColor, QPalette

from peepdf.gui._vendor.qt_themes import Theme, get_themes, update_palette

SETTINGS_ORGANIZATION = "digitalsleuth"
SETTINGS_APPLICATION = "peepdf-3"
THEME_KEY = "appearance/theme"

CLASSIC_NAME = "Classic"

CLASSIC_MENU_STYLESHEET = """
QMenu {
    background-color: white; color: black; border: 1px solid black; margin: 0;
}
QMenu::item {
    background-color: white; color: black; margin: 0; padding: 4px 20px 4px 20px;
}
QMenu::item:selected {
    background-color: #1644b9; color: white; margin: 0; padding: 4px 20px 4px 20px;
}
QMenuBar {
    background-color: white; color: black;
}
QMenuBar::item {
    background-color: white; color: black;
}
QMenuBar::item:selected {
    background-color: #1644b9; color: white;
}
"""

def _relativeLuminance(color: QColor) -> float:
    def linear(channel):
        c = channel / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = linear(color.red()), linear(color.green()), linear(color.blue())
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrastRatio(a: QColor, b: QColor) -> float:
    lumA, lumB = _relativeLuminance(a), _relativeLuminance(b)
    lighter, darker = max(lumA, lumB), min(lumA, lumB)
    return (lighter + 0.05) / (darker + 0.05)


def _bestContrastText(background: QColor, candidates) -> QColor:
    """Whichever of 'candidates' reads best against 'background', instead of
    guessing from the background's own brightness: that guess picks the
    wrong one for several themes (e.g. GitHub Light, Modern Light), making
    selected text nearly unreadable."""
    return max(candidates, key=lambda candidate: _contrastRatio(background, candidate))


NAME_WORDS = {"github": "GitHub"}


def _displayName(name):
    return " ".join(NAME_WORDS.get(word, word.title()) for word in name.split("_"))


def availableThemes():
    """{display name: Theme}, sorted, for every vendored built-in theme."""
    return dict(sorted((_displayName(name), theme) for name, theme in get_themes().items()))


def settings():
    return QSettings(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        SETTINGS_ORGANIZATION,
        SETTINGS_APPLICATION,
    )


def savedThemeName():
    name = settings().value(THEME_KEY)
    return name if isinstance(name, str) else CLASSIC_NAME


def saveThemeName(name):
    store = settings()
    store.setValue(THEME_KEY, name)
    store.sync()


def buildPalette(theme: Theme) -> QPalette:
    palette = QPalette()
    update_palette(palette, theme)
    highlightedText = _bestContrastText(
        theme.primary, (theme.text, theme.mantle, theme.crust, theme.base)
    )
    palette.setColor(QPalette.ColorRole.HighlightedText, highlightedText)
    return palette


def menuStylesheet(theme: Theme | None) -> str:
    """The QMenu/QMenuBar stylesheet for 'theme', or the original hardcoded
    one when 'theme' is None (the Classic look, unchanged from before
    theming existed)."""
    if theme is None:
        return CLASSIC_MENU_STYLESHEET
    dark = theme.is_dark_theme()
    background = theme.mantle.name() if dark else theme.crust.name()
    border = theme.surface1.name()
    text = theme.text.name()
    highlight = theme.primary.name()
    highlightText = _bestContrastText(
        theme.primary, (theme.text, theme.mantle, theme.crust, theme.base)
    ).name()
    return f"""
QMenu {{
    background-color: {background}; color: {text}; border: 1px solid {border}; margin: 0;
}}
QMenu::item {{
    background-color: {background}; color: {text}; margin: 0; padding: 4px 20px 4px 20px;
}}
QMenu::item:selected {{
    background-color: {highlight}; color: {highlightText}; margin: 0; padding: 4px 20px 4px 20px;
}}
QMenuBar {{
    background-color: {background}; color: {text};
}}
QMenuBar::item {{
    background-color: {background}; color: {text};
}}
QMenuBar::item:selected {{
    background-color: {highlight}; color: {highlightText};
}}
"""
