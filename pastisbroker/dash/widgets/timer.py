# built-in imports
import time
import datetime

# Third-party imports
import dash_html_components as html
import dash_core_components as dcc
import dash_daq as daq
import dash_bootstrap_components as dbc

# Local imports
from pastisbroker.dash.widgets import WidgetBase


class TimerWidget(WidgetBase):
    def __init__(self, app):
        super(TimerWidget, self).__init__(app)

        # local variables
        self._started = False
        self._start_time = None

        self._widget = self.mk_widget()

        # Register all actions on the app
        self.register_callback()

    def start(self):
        self._start_time = int(time.time())
        self._started = True

    def stop(self):
        self._started = False

    def mk_widget(self):
        return html.Div(children=[html.H5(children='Timer', style={"textAlign": "center"}),
                                  daq.LEDDisplay(id='timer-display',
                                                 value="00:00",
                                                 backgroundColor="#000000",
                                                 color="#33a300",
                                                 style={"paddingLeft": "15px", "paddingRight": "15px", "paddingBottom": "5px"}),
                                  daq.GraduatedBar(id='timer-bar', value=0, max=86400, showCurrentValue=True,),
                                  dcc.Interval(
                                      id='timer-interval',
                                      interval=1000,  # in milliseconds
                                      n_intervals=0
                                  )
                                  ],
                        style={"border": "1px solid #e1e1e1", "padding": "10px", "align": "center"})

    @property
    def widget(self):
        return self._widget

    def register_callback(self):
        self.app.callback(
            [dash.dependencies.Output('timer-display', 'value'),
             dash.dependencies.Output('timer-bar', 'value'), ],
            [dash.dependencies.Input('timer-interval', 'n_intervals')])(self.timer_ticker)

    def timer_ticker(self, value):
        if self._started:
            elapsed = int(time.time()) - self._start_time
            delta = datetime.timedelta(seconds=elapsed)
            return str(delta), delta.seconds



if __name__ == "__main__":
    import dash
    external_stylesheets = [dbc.themes.BOOTSTRAP, 'https://codepen.io/chriddyp/pen/bWLwgP.css']
    app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

    widget = TimerWidget(app)
    app.layout = widget.widget
    widget.start()

    app.run_server(debug=True)
