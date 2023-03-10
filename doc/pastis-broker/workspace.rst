.. _broker_workspace:

Workspace
=========

All the corpus, crahes, clients logs and telemetry are stored in the workspace.
It thus aggregate all data related to a campaign. If a klocwork report have been
provided it also provides for each alertes data returned by clients, inputs triggered
the crash of the alert etc. In this mode ``pastis-broker`` also export a final CSV
indicating which alerts have been covered or triggered. The workspace folder also
enables restarting an interrupted campaign. The workspace file structure is the following:


.. highlight:: none

::

    workspace/
        alerts_data/   (alert related data if a report was provided)
        binaries/      (binaries used, copied from --bins argument)
        corpus/        (corpus files)
        crashes/       (crash files)
        hangs/         (hang files)
        logs/          (log files, one file per client)
        broker.log     (log file of the broker)
        sastreport.bin (copy of the SAST report if provided)
        results.csv    (synthetic results of alerts, if a report is provided)
