# built-in imports
from pathlib import Path
from typing import Generator, Optional, Union, List
import matplotlib.pyplot as plt


# local imports
from pastisbenchmark.replayer import ReplayType
from pastisbenchmark.results import InputCovDelta, CampaignResult



class Plotter(object):

    LABEL_SZ = 20
    TICK_SZ = 13
    FONT_SZ = 15
    LEGEND_SZ = 14

    SEED_FUZZER = "seeds"
    ALL_FUZZER = "all"
    PLOT_DIR = "plots"

    def __init__(self, name: str):
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2)
        self.name = name

        # self._configure_plot(self.ax1, ylabel="coverage (edge)")
        # self._configure_plot(self.ax2, ylabel="coverage (edge)", is_log=True)

    def _configure_plot(self, plot, ylabel: str, is_log: bool = False):
        plot.tick_params(axis='both', which='major', labelsize=self.TICK_SZ)
        plot.tick_params(axis='both', which='minor', labelsize=self.TICK_SZ)
        plot.set_title(f"{self.name} {'(logscale)' if is_log else ''}", fontsize=self.FONT_SZ)
        plot.set(xlabel='seconds', ylabel=ylabel)
        plot.yaxis.label.set_size(self.LABEL_SZ)
        plot.xaxis.label.set_size(self.LABEL_SZ)
        plot.legend(prop={'size': self.LEGEND_SZ})
        if is_log:
            plot.set_xscale("log")

    def add_campaign_to_plot(self, campaign: CampaignResult):
        """ Iterate all stat_items and generate coverage plot."""
        for fuzzer, results in campaign.results:
            if fuzzer == self.SEED_FUZZER:
                continue
            self.add_to_plot(self.ax1, fuzzer, results)
            self.add_to_plot(self.ax2, fuzzer, results)

    def add_to_plot(self, plot, fuzzer: str, results: List[InputCovDelta], annotate_tt=False, label_tt=False):
        X = [x.time_elapsed for x in results]
        Y = [x.total_coverage for x in results]

        F = [x.fuzzer for x in results]
        plot.plot(X, Y, label=fuzzer, linewidth=2)

        # if annotate_tt:
        #     T, Y = find_tt_inp(X, Y, F)
        #     if label_tt:
        #         ax.plot(T, Y, 'bo', label="TT input")
        #     else:
        #         ax.plot(T, Y, 'bo')

    # @staticmethod
    # def find_tt_inp(X, Y, F):
    #     t = []
    #     y = []
    #     for i in range(len(X)):
    #         if F[i] and "TT" in F[i]:
    #             t.append(X[i])
    #             y.append(Y[i])
    #
    #     return t, y

    def show(self):
        self._configure_plot(self.ax1, ylabel="coverage (edge)")
        self._configure_plot(self.ax2, ylabel="coverage (edge)", is_log=True)
        plt.show()

    def save_to(self, dir: Union[str, Path]) -> None:
        # TODO: to implement !
        pass