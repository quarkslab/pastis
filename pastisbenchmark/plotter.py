# built-in imports
import logging
from pathlib import Path
from typing import Generator, Optional, Union, List
import matplotlib.pyplot as plt
import json
import datetime

# local imports
from pastisbenchmark.replayer import ReplayType
from pastisbenchmark.results import InputCovDelta, CampaignResult
from tritondse import Config, CoverageStrategy, SmtSolver, BranchSolvingStrategy


class Plotter(object):

    LABEL_SZ = 20
    TICK_SZ = 13
    FONT_SZ = 15
    LEGEND_SZ = 8

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
            self.add_to_plot(self.ax1, self.format_fuzzer_name(campaign, fuzzer), results)
            self.add_to_plot(self.ax2, self.format_fuzzer_name(campaign, fuzzer), results)

    def add_to_plot(self, plot, fuzzer: str, results: List[InputCovDelta], annotate_tt=False, label_tt=False):
        X = [x.time_elapsed for x in results]
        Y = [x.total_coverage for x in results]

        F = [x.fuzzer for x in results]
        plot.plot(X, Y, label=fuzzer, linewidth=2)

    def format_fuzzer_name(self, campaign: CampaignResult, fuzzer: str) -> str:
        if fuzzer == self.ALL_FUZZER:
            return campaign.slug_name
        elif fuzzer == self.SEED_FUZZER:
            return self.SEED_FUZZER
        elif "TT" in fuzzer:
            config = campaign.fuzzers_config[fuzzer]
            cov_name = {CoverageStrategy.BLOCK: "B", CoverageStrategy.EDGE: "E", CoverageStrategy.PREFIXED_EDGE: "PE",
                        CoverageStrategy.PATH: "P"}[config.coverage_strategy]
            param = [
                "R" if BranchSolvingStrategy.COVER_SYM_READ in config.branch_solving_strategy else "-",
                "W" if BranchSolvingStrategy.COVER_SYM_WRITE in config.branch_solving_strategy else "-",
                "J" if BranchSolvingStrategy.COVER_SYM_DYNJUMP in config.branch_solving_strategy else "-"
            ]
            solver = {SmtSolver.Z3: "Z3", SmtSolver.BITWUZLA: "BZLA"}[config.smt_solver]
            return f"TritonDSE[{cov_name}][{''.join(param)}][{solver}]"
        elif "AFLPP" in fuzzer:
            return "AFL++"
        elif "HF" in fuzzer:
            return "Honggfuzz"
        else:
            return fuzzer

    def add_triton_input(self, campaign: CampaignResult):
        if campaign.is_full_duplex:
            results = campaign.fuzzers_items[campaign.ALL_FUZZER]
            X = [x.time_elapsed for x in results if "TT" in x.input_name]
            Y = [x.total_coverage for x in results if "TT" in x.input_name]
            self.ax1.plot(X, Y, 'bo', label="TT input")
            self.ax2.plot(X, Y, 'bo', label="TT input")
        else:
            logging.warning(f"campaign:{campaign.workspace.root} not full duplex do not show triton inputs")

    def show(self):
        self._configure_plot(self.ax1, ylabel="coverage (edge)")
        self._configure_plot(self.ax2, ylabel="coverage (edge)", is_log=True)
        plt.show()

    def save_to(self, dir: Union[str, Path]) -> None:
        plt.savefig(dir / "plot.pdf", dpi=600)

    def print_input_number_stats(self, campaign: CampaignResult):
        tot_input = sum(len(y) for x, y in campaign.results)

        stats = {}  # Fuzzer -> count

        for fuzzer, results in campaign.results:
            for item in results:
                if fuzzer == campaign.ALL_FUZZER:
                    date, elapsed, fuzzer_id, hash = campaign.parse_filename(item.input_name)
                    if fuzzer_id in stats:
                        stats[fuzzer_id] += 1
                    else:
                        stats[fuzzer_id] = 1
                else:
                    if fuzzer in stats:
                        stats[fuzzer] += 1
                    else:
                        stats[fuzzer] = 1
        print("Input number stats:")
        for fuzzer, n in stats.items():
            print(f"- {self.format_fuzzer_name(campaign, fuzzer)}: {n}  [{n / tot_input:.2%}]")
        print(f"Total: {tot_input}")


    def print_coverage_stats(self, campaign: CampaignResult):
        tot_input = sum(len(z.unique_coverage) for x, y in campaign.results for z in y)

        stats = {}  # Fuzzer -> count

        for fuzzer, results in campaign.results:
            for item in results:
                if fuzzer == campaign.ALL_FUZZER:
                    date, elapsed, fuzzer_id, hash = campaign.parse_filename(item.input_name)
                    if fuzzer_id in stats:
                        stats[fuzzer_id] += len(item.unique_coverage)
                    else:
                        stats[fuzzer_id] = len(item.unique_coverage)
                else:
                    if fuzzer in stats:
                        stats[fuzzer] += len(item.unique_coverage)
                    else:
                        stats[fuzzer] = len(item.unique_coverage)
        print("Coverage stats:")
        for fuzzer, n in stats.items():
            print(f"- {self.format_fuzzer_name(campaign, fuzzer)}: {n}  [{n / tot_input:.2%}]")
        print(f"Total: {tot_input}")


    def print_triton_stats(self, campaign: CampaignResult) -> None:
        def tt(secs):
            return str(datetime.timedelta(seconds=int(secs)))

        for fuzzer, config in campaign.fuzzers_config.items():
            try:
                if campaign.is_triton(fuzzer):
                    workdir = (campaign.workspace.root / "clients_ws") / Path(config.workspace).name
                    pstats = json.loads((workdir / "pastidse-stats.json").read_text())
                    sstats = json.loads((workdir / "metadata/solving_stats.json").read_text())
                    print(f"---- {fuzzer}: {self.format_fuzzer_name(campaign, fuzzer)} ----")

                    # Timing stats
                    tot, replay_time = pstats["total_time"], pstats["replay_time"]
                    sovt = sstats['total_solving_time']
                    dse = tot - replay_time - sovt
                    print(f"Total: {tt(tot)} | DSE: {tt(dse)} ({dse/tot:.2%}) | SMT: {tt(sovt)} ({sovt/tot:.2%}) | REPLAY: {tt(replay_time)} ({replay_time/tot:.2%})")

                    # Input stats
                    tots, accs, rejs = pstats["seed_received"], pstats["seed_accepted"], pstats["seed_rejected"]
                    print(f"Total: {tots} | Accepted: {accs} ({accs/tots:.2%}) |  Rejected: {rejs} ({rejs/tots:.2%})")

                    # Solving stats
                    stot, sat, unsat, to = sstats["total_solving_attempt"], sstats["SAT"], sstats["UNSAT"], sstats["TIMEOUT"]
                    print(f"Total: {stot}  SAT: {sat} ({sat/stot:.2%}) | UNSAT: {unsat} ({unsat/stot:.2%}) | TIMEOUT: {to} ({to/stot:.2%})")

                    coved, uncoved = len(sstats["branch_reverted"]), len(sstats["branch_not_solved"])
                    print(f"Branch resolved: {coved} | Branch not solved: {uncoved}")
            except FileNotFoundError:
                logging.error(f"can't find Triton stats for {fuzzer}")
