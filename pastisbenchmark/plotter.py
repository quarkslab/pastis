# built-in imports
import logging
from pathlib import Path
from typing import Union, List, Dict
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import json
from datetime import timedelta
from hashlib import md5
import base64
from collections import Counter

# third-party imports
from rich.console import Console
from rich.table import Table

# local imports
from pastisbenchmark.results import InputCovDelta, CampaignResult
from pastisbenchmark.models import CampaignStats, InputEntry, CoverageEntry, ExecEntry, SeedSharingEntry, SmtEntry
from tritondse import CoverageStrategy, SmtSolver, BranchSolvingStrategy


class Plotter(object):

    LABEL_SZ = 18
    TICK_SZ = 13
    FONT_SZ = 18
    LEGEND_SZ = 8

    PLOT_DIR = "plots"

    def __init__(self, name: str, timeout: int):
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2)
        self.name = name
        self._timeout = timeout

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

    def add_campaign_to_plot(self, campaign: CampaignResult, show_union: bool=True):
        """ Iterate all stat_items and generate coverage plot."""
        for fuzzer, results in campaign.results:
            is_all_fuzzer = bool(fuzzer == CampaignResult.ALL_FUZZER)
            if fuzzer == CampaignResult.SEED_FUZZER:
                continue
            if is_all_fuzzer and campaign.is_half_duplex and not show_union:
                continue
            if campaign.is_full_duplex and not is_all_fuzzer:  # Only print the ALL fuzzer in fullduplex
                continue
            name = self.format_fuzzer_name(campaign, fuzzer)
            # fmt = self.format_plot(fuzzer, campaign.is_full_duplex)

            marker = "--" if campaign.is_half_duplex and is_all_fuzzer else "-"
            color = self.format_plot(campaign, fuzzer)

            self.add_to_plot(self.ax1, name, results, is_all_fuzzer, linestyle=marker, color=color)
            self.add_to_plot(self.ax2, name, results, is_all_fuzzer, linestyle=marker, color=color)

    def add_to_plot(self, plot, fuzzer: str, results: List[InputCovDelta], use_global: bool, **kwargs):
        xaxe = [x.time_elapsed for x in results]
        yaxe = [(x.overall_coverage_sum if use_global else x.fuzzer_coverage_sum) for x in results]

        if not yaxe:
            print(f"no plot for {fuzzer}")
            return

        # Add dummy value to make horizontal line
        xaxe.append(self._timeout)
        yaxe.append(yaxe[-1])

        plot.plot(xaxe, yaxe, label=fuzzer, linewidth=2, **kwargs)

    def format_fuzzer_name(self, campaign: CampaignResult, fuzzer: str, short: bool=False) -> str:
        if fuzzer == CampaignResult.ALL_FUZZER:
            return campaign.slug_name
        elif fuzzer == CampaignResult.SEED_FUZZER:
            return CampaignResult.SEED_FUZZER
        elif "TT" in fuzzer:
            if short:
                return "TritonDSE"
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

    def format_plot(self, campaign, fuzzer) -> str:
        green = "#30a230"
        grey = "#1f77b4"
        brown = "#944b0c"
        if fuzzer == CampaignResult.ALL_FUZZER:
            if campaign.is_full_duplex:
                return green if campaign.has_honggfuzz() else brown
            else:
                return grey
        elif "TT" in fuzzer:
            return "#d62728"
        elif "AFLPP" in fuzzer:
            return "#ff8214"
        elif "HF" in fuzzer:
            return "#9467bd"
        else:
            return ""


    def add_triton_input(self, campaign: CampaignResult):
        if campaign.is_full_duplex:
            results = campaign.fuzzers_items[campaign.ALL_FUZZER]
            X = [x.time_elapsed for x in results if "TT" in x.fuzzer]
            Y = [x.overall_coverage_sum for x in results if "TT" in x.fuzzer]
            self.ax1.plot(X, Y, 'b.', label="TT input")
            self.ax2.plot(X, Y, 'b.', label="TT input")
        else:
            logging.warning(f"campaign:{campaign.workspace.root} not full duplex do not show triton inputs")

    def show(self):
        self._configure_plot(self.ax1, ylabel="coverage (edge)")
        self._configure_plot(self.ax2, ylabel="coverage (edge)", is_log=True)
        plt.show()

    def save_to(self, dir: Union[str, Path]) -> None:
        plt.savefig(dir / "plot.pdf", dpi=600)


    def calculate_stats(self, campaign: CampaignResult) -> CampaignStats:
        input_stats = self._calcul_input_stats(campaign)
        coverage_stats = self._calcul_coverage_stats(campaign)
        exec_stats = self._calcul_exec_stats(campaign)
        seed_sharing_stats = self._calcul_seed_sharing_stats(campaign)
        smt_stats = self._calcul_smt_stats(campaign, coverage_stats)
        return CampaignStats(input_stats=input_stats, coverage_stats=coverage_stats, exec_stats=exec_stats,
                             seed_sharing_stats=seed_sharing_stats, smt_stats=smt_stats)


    def _calcul_triton_input_to_broker(self, campaign: CampaignResult) -> Dict[str, str]:
        mapping = {}

        def iter_input_dir(conf, dirname):
            tt_workspace = campaign.workspace.root / conf.workspace
            for file in (tt_workspace / dirname).iterdir():
                try:
                     raw = base64.b64decode(json.loads(file.read_text())['files']['input_file'])
                except:
                    raw = file.read_bytes()
                mapping[md5(raw).hexdigest()] = str(file)

        for fuzzer, items in campaign.results:
            if campaign.is_triton(fuzzer):
                conf = campaign.fuzzers_config[fuzzer]
                iter_input_dir(conf, "corpus")
                iter_input_dir(conf, "worklist")
                iter_input_dir(conf, "crashes")

        return mapping

    def _calcul_input_stats(self, campaign: CampaignResult) -> List[InputEntry]:
        entries = []

        # FIXME: Compute uniquness
        useless_ctrs = Counter()

        for fuzzer, items in campaign.results:
            num = len(items)
            for item in items:
                if not len(item.overall_new_items_covered):
                    useless_ctrs[fuzzer] += 1
            syms = {"CC": 0, "SR": 0, "SW": 0, "DYN": 0}
            if campaign.is_triton(fuzzer):
                conf = campaign.fuzzers_config[fuzzer]
                tt_workspace = campaign.workspace.root / conf.workspace
                for file in (tt_workspace / "corpus").iterdir():
                    for s in syms:
                        if s in str(file):
                            syms[s] += 1
                for file in (tt_workspace / "worklist").iterdir():
                    for s in syms:
                        if s in str(file):
                            syms[s] += 1
                for file in (tt_workspace / "crashes").iterdir():
                    for s in syms:
                        if s in str(file):
                            syms[s] += 1

            entry = InputEntry(engine=fuzzer, number=num, unique=-1, useless=useless_ctrs[fuzzer], condition=syms["CC"],
                               symread=syms["SR"], symwrite=syms["SW"], symjump=syms["DYN"])
            entries.append(entry)
        return entries

    def _calcul_coverage_stats(self, campaign: CampaignResult) -> List[CoverageEntry]:
        # all_cov = campaign.fuzzers_items[campaign.ALL_FUZZER]
        seed_cov = campaign.fuzzers_coverage[campaign.SEED_FUZZER]

        entries = []

        firsts = Counter()
        for entry in campaign.delta_items:
            firsts[entry.fuzzer] += len(entry.overall_new_items_covered)

        for fuzzer, items in campaign.results:
            cov = campaign.fuzzers_coverage[fuzzer]
            num = len(cov.difference(seed_cov)) if fuzzer != campaign.SEED_FUZZER else cov.unique_covitem_covered

            # FIXME: Compute unique & first
            first = firsts[fuzzer]
            entry = CoverageEntry(engine=fuzzer, number=num, unique=-1, first=first, total=cov.unique_covitem_covered)
            entries.append(entry)
        return entries

    def _calcul_exec_stats(self, campaign: CampaignResult) -> List[ExecEntry]:
        entries = []

        for fuzzer, config in campaign.fuzzers_config.items():
            try:
                if campaign.is_triton(fuzzer):
                    workdir = (campaign.workspace.root / "clients_ws") / Path(config.workspace).name
                    pstats = json.loads((workdir / "metadata/pastidse-stats.json").read_text())

                    # Timing stats
                    tot, replay_time = pstats["total_time"], pstats["replay_time"]
                    emu_time = pstats.get("emulation_time", 0)

                    solv_time = pstats.get("solving_time")
                    if solv_time is None:
                        sstats = json.loads((workdir / "metadata/solving_stats.json").read_text())
                        solv_time = sstats['total_solving_time']

                    dse = emu_time - replay_time
                    run_time = dse + replay_time + solv_time
                    wait = tot - run_time

                    entry = ExecEntry(engine=fuzzer, dse=dse, smt=solv_time, replay=replay_time, total=run_time, wait=wait)
                    entries.append(entry)
            except FileNotFoundError:
                logging.error(f"can't find Triton stats for {fuzzer}")
        return entries

    def _calcul_seed_sharing_stats(self, campaign: CampaignResult) -> List[SeedSharingEntry]:
        entries = []

        for fuzzer, config in campaign.fuzzers_config.items():
            try:
                if campaign.is_triton(fuzzer):
                    workdir = (campaign.workspace.root / "clients_ws") / Path(config.workspace).name
                    pstats = json.loads((workdir / "metadata/pastidse-stats.json").read_text())
                    tots, accs, rejs = pstats["seed_received"], pstats["seed_accepted"], pstats["seed_rejected"]
                    ratio = accs/tots if rejs else 1

                    entry = SeedSharingEntry(engine=fuzzer, accepted=accs, rejected=rejs, total=tots, ratio=ratio)
                    entries.append(entry)
            except FileNotFoundError:
                logging.error(f"can't find Triton stats for {fuzzer}")
        return entries


    def _calcul_smt_stats(self, campaign: CampaignResult, cov_results: List[CoverageEntry]) -> List[SmtEntry]:
        cov_data = {cov.engine: cov for cov in cov_results}

        entries = []

        for fuzzer, config in campaign.fuzzers_config.items():
            try:
                if campaign.is_triton(fuzzer):
                    cov_number = cov_data[fuzzer].number if fuzzer in cov_data else 0
                    workdir = (campaign.workspace.root / "clients_ws") / Path(config.workspace).name
                    sstats = json.loads((workdir / "metadata/solving_stats.json").read_text())

                    # Solving stats
                    sovt = sstats['total_solving_time']
                    stot, sat, unsat, to = sstats["total_solving_attempt"], sstats["SAT"], sstats["UNSAT"], sstats["TIMEOUT"]
                    coved, uncoved = len(sstats["branch_reverted"]), len(sstats["branch_not_solved"])
                    ratio = cov_number / sat if sat else cov_number
                    entry = SmtEntry(engine=fuzzer, sat=sat, unsat=unsat, timeout=to, total=stot, avg_query=sovt/stot,
                                     cov_sat_ratio=ratio, branch_solved=coved, branch_not_solved=uncoved)
                    entries.append(entry)
            except FileNotFoundError:
                logging.error(f"can't find Triton stats for {fuzzer}")
        return entries


    def print_stats(self, campaign: CampaignResult, stats: CampaignStats):
        console = Console()

        def sfmt(seconds, total, w = True) -> str:
            m, s = divmod(seconds, 60)
            h, m = divmod(m, 60)
            s = int(s) if int(s) > 0 else f"{s:.2f}"
            t = (f"{int(h)}h" if h else '') + f"{int(m)}m{s}s"
            perc = f"{seconds / total:.2%}"
            return f"{t} ({perc})" if w else t


        # InputEntry
        table = Table(show_header=True, title="INPUT", header_style="bold magenta")
        for name in ["engine", "number", "unique", "useless", "CC", "SR", "SW", "SDYN"]:
            table.add_column(name)
        for it in stats.input_stats:
            fname = self.format_fuzzer_name(campaign, it.engine, False)
            useless = f"{it.useless} ({it.useless / it.number:.2%})"
            table.add_row(fname, str(it.number), str(it.unique), useless, str(it.condition), str(it.symread), str(it.symwrite), str(it.symjump))
        console.print(table)

        # Coverage
        table = Table(show_header=True, title="COVERAGE", header_style="bold magenta")
        for name in ["engine", "edge-cov", "unique", "first", "total"]:
            table.add_column(name)
        for it in stats.coverage_stats:
            fname = self.format_fuzzer_name(campaign, it.engine, False)
            table.add_row(fname, str(it.number), str(it.unique), str(it.first), str(it.total))
        console.print(table)

        # ExecEntry
        table = Table(show_header=True, title="EXECUTION", header_style="bold magenta")
        for name in ["engine", "DSE", "SMT", "replay", "total", "wait"]:
            table.add_column(name)
        for it in stats.exec_stats:
            fname = self.format_fuzzer_name(campaign, it.engine, False)
            tot = it.total
            table.add_row(fname, sfmt(it.dse, tot), sfmt(it.smt, tot), sfmt(it.replay, tot), sfmt(tot, tot, False), sfmt(it.wait, tot, False))
        console.print(table)

        # SeedSharingEntry
        table = Table(show_header=True, title="SEED SHARING", header_style="bold magenta")
        for name in ["engine", "accepted", "rejected", "total"]:
            table.add_column(name)
        for it in stats.seed_sharing_stats:
            fname = self.format_fuzzer_name(campaign, it.engine, False)
            acc = f"{it.accepted} ({it.accepted / it.total:.2%})"
            rejs = f"{it.rejected} ({it.rejected / it.total:.2%})"
            table.add_row(fname, acc, rejs, str(it.total))
        console.print(table)

        # SmtEntry
        table = Table(show_header=True, title="SMT SOLVING", header_style="bold magenta")
        for name in ["engine", "SAT", "UNSAT", "TO", "Total", "mean query", "cov/input", "branches solved", "branches not solved"]:
            table.add_column(name)
        for it in stats.smt_stats:
            fname = self.format_fuzzer_name(campaign, it.engine, False)
            table.add_row(fname, str(it.sat), str(it.unsat), str(it.timeout), str(it.total), f"{it.avg_query:.2f}", f"{it.cov_sat_ratio:.2f}", str(it.branch_solved), str(it.branch_not_solved))
        console.print(table)


        # for stat in (getattr(stats, x) for x in stats.schema()['properties']):
        #     if not stat:
        #         print(f"Stat {stat} is empty")
        #         continue
        #     table = Table(show_header=True, title=str(type(stat[0])), header_style="bold magenta")
        #     item = stat[0]
        #
        #     for name, column in {x: getattr(item, x) for x in item.schema()['properties']}.items():
        #         table.add_column(name)
        #     for item in stat:
        #         table.add_row(*[str(getattr(item, x)) for x in item.schema()['properties']])
        #     console.print(table)



    def show_delta_history(self, campaign: CampaignResult) -> None:
        console = Console()
        def tt(secs):
            return str(timedelta(seconds=int(secs)))
        def pp_edge(e):
            return f"({e[0]:#08x}-{e[1]:#08x})"

        mapping = self._calcul_triton_input_to_broker(campaign)

        def caract_input(name) -> str:
            types = ["_CC_", "_SR_", "_SW_", "_DYN_"]
            for t in types:
                if t in name:
                    return t[1:-1]
            return "N/C"

        table = Table(show_header=True, title="Delta History", header_style="bold magenta")
        for col in ["Elapsed", "Fuzzer", "Type", "New", "Tot Cov", "Items"]:
            table.add_column(col)
        # FIXME: Ajouter une colonne pour le count

        for delta in campaign.delta_items:

            # Resolve broker input to triton ones (to what it was generated from)
            typ = "-"
            if campaign.is_triton(delta.fuzzer):
                meta = campaign.parse_filename(delta.input_name)
                if meta:
                    hash = meta[3]
                    triton_input_name = mapping.get(hash)
                    if triton_input_name:
                        typ = caract_input(triton_input_name)

            table.add_row(tt(delta.time_elapsed),
                          self.format_fuzzer_name(campaign, delta.fuzzer, short=True),
                          typ,
                          str(len(delta.overall_new_items_covered)),
                          str(delta.overall_coverage_sum),
                          " ".join(pp_edge(e) for e in list(delta.overall_new_items_covered)[:4])
            )

        console.print(table)
