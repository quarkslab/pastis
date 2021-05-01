import dash

from typing import List, Callable, Tuple, Any
from libpastis.agent import MessageType


class WidgetBase:
    def __init__(self, app: dash.Dash):
        self.app = app

    def callbacks(self) -> List[Tuple[MessageType, Callable]]:
        return []

    def widget(self):
        raise NotImplementedError()
