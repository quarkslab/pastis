import json
from pathlib import Path
import base64
import logging
import tempfile
from typing import Optional

# Third-party imports
import dash_html_components as html
import dash_core_components as dcc
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc


from pastisbroker.dash.widgets.base import WidgetBase
from pastisbroker.broker import BrokingMode
from pastisbroker.utils import read_binary_infos
from pastisbroker.workspace import Workspace


from libpastis.types import CheckMode, SeedType
from klocwork import KlocworkReport


class MainConfigurationWidget(WidgetBase):
    def __init__(self, app, workspace):
        super(MainConfigurationWidget, self).__init__(app)
        self.started = False
        # self.broker = broker
        # self.workspace = self.broker.workspace
        self.workspace = workspace

        # Define all widgets
        self._radio_check_mode = None
        self._radio_broke_mode = None
        self._argv_widget = None
        self._widget = None
        self.mk_widget()

        # Local variables
        self.uploaded_bins = []  # List of binaries uploaded
        self.kl_report = None

        # Register all actions on the app
        self.register_callback()

    @property
    def klocwork_report(self) -> Optional[KlocworkReport]:
        return self.kl_report

    @property
    def argv(self) -> str:
        return self._argv_widget.value

    @property
    def widget(self):
        return self._widget

    @property
    def check_mode(self) -> CheckMode:
        return CheckMode(self._radio_check_mode.value)

    def mk_widget(self):
        self._radio_check_mode = dcc.RadioItems(
                    options=[{'label': x.name, 'value': x.value} for x in CheckMode],
                    value=CheckMode.CHECK_ALL.value
                )

        self._radio_broke_mode = dcc.RadioItems(
                    options=[{'label': x.name, 'value': x.value} for x in BrokingMode],
                    value=BrokingMode.FULL.value
                )
        self._argv_widget = dcc.Input(id="argv-input", value="")

        self._widget = html.Div([
            html.Div(children='Binaries:'),
            dcc.Upload(
                id='upload-binary',
                children=html.Div(['Drag and Drop or ', html.A('Select Files')]),
                style={
                    # 'width': '100%',
                    'height': '30px',
                    'lineHeight': '30px',
                    'borderWidth': '1px',
                    'borderStyle': 'dashed',
                    'borderRadius': '3px',
                    'textAlign': 'center',
                    'margin': '5px'
                },
                # Allow multiple files to be uploaded
                multiple=True
            ),
            html.Div(id='output-data-upload'),
            html.Div(children=["Klocwork Report: ",
                               dcc.Upload(id="kl-report-upload", children=dcc.Input(id="kl-report-input")),
                               html.Span(id="kl-count")]),
            html.Div(children=["Initial seeds: ",
                               dcc.Upload(id="seed-upload",
                                          children=html.A('Select Files'),
                                          style={
                                              # 'width': '100%',
                                              'height': '30px',
                                              'lineHeight': '30px',
                                              'borderWidth': '1px',
                                              'borderStyle': 'dashed',
                                              'borderRadius': '3px',
                                              'textAlign': 'center',
                                              'margin': '5px'
                                          },
                                          multiple=True),
                               html.Span(id="seed-count")]),
            html.Div(children=["argv: ", self._argv_widget]),
            html.Div(children=["Check Mode: ", self._radio_check_mode]),
            html.Div(children=["Broking Mode: ", self._radio_broke_mode]),
            html.Button('Go', id='go-button', n_clicks=0),
        ], style={"border": "1px solid #e1e1e1", "padding": "10px"})

    def register_callback(self):
        # Callback for go-button clicked !
        self.app.callback(Output("go-button", "children"), [Input("go-button", "n_clicks")])(self.button_clicked)
        self.app.callback(Output('output-data-upload', 'children'),
                          Input('upload-binary', 'contents'),
                          State('upload-binary', 'filename'), prevent_initial_call=True)(self.file_uploaded_callback)
        self.app.callback([Output('kl-report-input', 'value'),
                           Output('kl-count', 'children')],
                          Input('kl-report-upload', 'contents'),
                          State('kl-report-upload', 'filename'), prevent_initial_call=True)(self.kl_report_uploaded_callback)
        self.app.callback(Output('seed-count', 'children'),
                          Input('seed-upload', 'contents'),
                          State('seed-upload', 'filename'), prevent_initial_call=True)(self.seed_uploaded_callback)

    def button_clicked(self, n_clicks) -> str:
        if n_clicks != 0:
            print(f"Go button clicked: {self.started} [{n_clicks}]")
            if self.started:
                self.started = False
                return "Go"
            else:
                self.started = True
                return "Stop"
        return "Go"

    def add_engine_configuration(self, widget) -> None:
        self._widget.children.insert(-1, widget)

    def file_uploaded_callback(self, list_of_contents, list_of_names):
        if list_of_names and list_of_contents:
            for name, content in zip(list_of_names, list_of_contents):
                logging.info(f"receive uploaded binary: {name}")
                raw_data = self.parse_file(name, content)
                if raw_data:
                    # save binary in workspace
                    bin_file = self.workspace.add_binary_data(name, raw_data)

                    # Read binary infos to print it on UI
                    data = read_binary_infos(bin_file)
                    arch, engine, exmode = data
                    self.uploaded_bins.append(html.Div([
                        html.Span(name),
                        html.Span([
                            dbc.Badge(engine.name, color="primary", className="mr-1"),
                            dbc.Badge(arch.name, color="warning", className="mr-1"),
                            dbc.Badge(exmode.name, color="info", className="mr-1"),
                        ]),
                    ]))
            return html.Div(self.uploaded_bins)

    def parse_file(self, name, content) -> Optional[bytes]:
        magic = "data:application/octet-stream;base64,"
        if not content.startswith(magic):
            logging.warning(f"ignore: {name}")
        else:
            return base64.b64decode(content[len(magic):])

    def kl_report_uploaded_callback(self, content: str, name: str):
        magic = "data:application/json;base64,"
        if not content.startswith(magic):
            logging.warning(f"ignore Klocwork report {name} (invalid format)")
            raise PreventUpdate
        raw_data = base64.b64decode(content[len(magic):])
        if raw_data:
            try:
                self.kl_report = KlocworkReport.from_json(raw_data)
                logging.info(f"received Klocwork report: {name}")

                # save binary in workspace
                self.workspace.add_klocwork_report(self.kl_report)
                if not self.kl_report.has_binding():
                    self.kl_report.auto_bind()

                # Return on first entry as there is only one
                return name, f"{self.kl_report.counted_alerts_count} alerts"
            except json.JSONDecoder:
                logging.error(f"invalid Klocwork report: {name} (not json)")
        raise PreventUpdate

    def seed_uploaded_callback(self, list_of_contents, list_of_names):
        if list_of_names and list_of_contents:
            for name, content in zip(list_of_names, list_of_contents):
                raw_data = self.parse_file(name, content)
                if raw_data:
                    logging.info(f"Initial seed received: {name}")
                    # save binary in workspace
                    self.workspace.save_seed(SeedType.INPUT, name, raw_data)

            return f"{self.workspace.count_corpus_directory(SeedType.INPUT)} seeds"


if __name__ == "__main__":
    import dash
    logging.basicConfig(level=logging.DEBUG)
    from pastisbroker.dash.app import BrokerDash
    external_stylesheets = [dbc.themes.BOOTSTRAP, 'https://codepen.io/chriddyp/pen/bWLwgP.css']
    app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
    w = Workspace(Path("/tmp/coucou"))

    widget = MainConfigurationWidget(app, w)
    app.layout = widget.widget

    app.run_server(debug=True)
