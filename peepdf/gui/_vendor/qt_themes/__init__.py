# Vendored from the qt-themes package (https://pypi.org/project/qt-themes/), v0.4.1.
# Unmodified from upstream; update by replacing this directory wholesale.

from ._theme import (
    Theme,
    get_theme,
    get_themes,
    set_theme,
    set_widget_theme,
    update_palette,
)

__all__ = [
    'Theme',
    'get_theme',
    'get_themes',
    'set_theme',
    'set_widget_theme',
    'update_palette',
]

__version__ = '0.4.1'
