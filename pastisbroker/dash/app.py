from pathlib import Path

import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_daq as daq

from pastisbroker.broker import PastisBroker, BrokingMode
from libpastis.types import SeedType, FuzzingEngine, LogLevel, Arch, State, SeedInjectLoc, CheckMode, CoverageMode, ExecMode, AlertData, PathLike


external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']



class BrokerDash(PastisBroker):
    def __init__(self, workspace: PathLike, debug: bool=False):
        super(BrokerDash, self).__init__(workspace, Path(workspace) / self.BINS_DIR, BrokingMode.FULL)

        # Local attributes
        self.debug = debug

        # Instanciate the Dash app
        self.app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
        self.configure_ui()

        # Start the broker (thus agent etc)
        self.start(running=False)

    def go_button_click(self):
        pass
        # TODO: (binaries should have already been put in the right directory and added
        # TODO: set broking_mode (with widget value)
        # TODO: set check_mode (with widget value)
        # TODO: (klocwork should have been put by the upload form
        # TODO: (initiale seeds should have been set by the upload form)
        # TODO: set argv with the value from the
        # TODO: envoyer le start_client_and_send_corpus (à tous les node connectés)
        # TODO: Send the timer widget the Go !

    def stop_button_clicked(self):
        pass
        # TODO: Send stop to timer

        # TODO: Traditional stopping (send stop clients etc..)

    def run(self):
        self.app.run_server(debug=self.debug)

    def configure_ui(self):
        # TODO: Insanciate the main layout with all the widgets etc.
        pass