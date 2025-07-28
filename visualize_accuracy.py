#!/usr/bin/env python3

# TRIX: Inference of Transient Violation Times from Logged Routing Events or Collected BGP Messages
# Copyright (C) 2024-2025 Roland Schmid <roschmi@ethz.ch> and Tibor Schneider <sctibor@ethz.ch>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import glob
import os
import pandas as pd
import plotly.express as px
import sys
import re

plot_list = ["err", "abs_err", "rel_err", "rel_total_err", "violation", "raw", "quantiles"]

parser = argparse.ArgumentParser()
parser.add_argument("eval_path")
parser.add_argument("--filter-sample-id", default="")
parser.add_argument("--num-prefixes", required=False)
parser.add_argument("--show", action='store_true')
parser.add_argument("-i", "--include", action="append", default=[])
parser.add_argument("-v", "--exclude", action="append", default=[])
parser.add_argument("-m", "--include-model", action="append", default=[])
parser.add_argument("-M", "--exclude-model", action="append", default=[])
parser.add_argument("-a", "--include-algorithm", action="append", default=[])
parser.add_argument("-A", "--exclude-algorithm", action="append", default=[])
parser.add_argument("-p", "--include-plot", action="append", default=[], choices=plot_list)
parser.add_argument("-P", "--exclude-plot", action="append", default=[], choices=plot_list)
parser.add_argument("-z", "--only-nonzero", action="store_true")
parser.add_argument("--sample", type=int, help="Randomly pick SAMPLE datapoints.")
parser.add_argument("--perc", help="Display this percentile (between 0 and 1)", action="append", default=[])
parser.add_argument("-t", "--template", choices=["eval-accuracy", "eval-fib-queue", "eval-algorithms", "quantiles-fib-queue", "quantiles-algorithms"], required=False)
args = parser.parse_args()

if args.template:
    args.exclude.append("Announce")
    args.exclude.append("Reflectors")
    args.exclude.append("LinkFailure")
    if args.template == "eval-accuracy":
        args.include_model.append("bgp_messages_nx9k-asymmetric_nh-100us_drop-60us_delay-0ms.csv")
        args.include_model.append("ufdm_nx9k-asymmetric_nh-100us_drop-60us_delay-0ms.csv")
        args.include_model.append("fw_updates")
        args.exclude_algorithm.append("baseline")
    if args.template == "eval-fib-queue":
        args.include.append("Prefix10000_")
        args.include_model.append("bgp_messages_nx9k-asymmetric_nh-100us_drop-60us_delay-0ms.csv")
        args.include_model.append("bgp_messages.csv")
        args.include_model.append("ufdm_nx9k-asymmetric_nh-100us_drop-60us_delay-0ms.csv")
        args.include_model.append("ufdm.csv")
        args.exclude_algorithm.append("baseline")
    if args.template == "eval-algorithms":
        args.include.append("Prefix10_")
        args.include_model.append("fw_updates")
        args.include_algorithm.append("alg")
        args.include_algorithm.append("baseline")
    if args.template == "quantiles-fib-queue":
        args.include_model.append("bgp_messages_nx9k-asymmetric_nh-100us_drop-60us_delay-0ms.csv")
        args.include_model.append("bgp_messages.csv")
        args.include_model.append("ufdm_nx9k-asymmetric_nh-100us_drop-60us_delay-0ms.csv")
        args.include_model.append("ufdm.csv")
        args.include_algorithm.append("alg")
        args.exclude.append("Prefix1_")
        # args.perc.append(0.8)
        # args.perc.append(0.95)
        args.include_plot.append("quantiles")
    if args.template == "quantiles-algorithms":
        args.include_model.append("fw_updates")
        args.exclude.append("Prefix1_")
        # args.perc.append(0.8)
        # args.perc.append(0.95)
        args.include_plot.append("quantiles")

# prepare the plot list
plot_list = args.include_plot if args.include_plot else plot_list
plot_list = {p for p in plot_list if p not in args.exclude_plot}

# collect data into a single dataframe
eval_files = list(glob.glob(args.eval_path + "/**/eval_*.csv"))
dfs = []
for f in eval_files:
    # ensure skip file is not present
    if os.path.exists(f.replace(".csv", ".skip")):
        continue
    # apply the filter
    if args.include and not all(x in f for x in args.include):
        continue
    if args.exclude and any(x in f for x in args.exclude):
        continue
    if "_Prefix" not in f:
        continue
    # try to read data from csv
    print(f"reading {f}")
    try:
        dfs.append(pd.read_csv(f, delimiter=";"))
    except Exception as e:
        pass

# no data found, abort plotting
if len(dfs) == 0:
    print("No usable data found.")
    sys.exit(0)

df = pd.concat(dfs)

# filter by sample_id
filtered_df = df[df["sample_id"].str.contains(args.filter_sample_id, na=False)]

# rename columns
df.rename(columns={
    'err': 'err_alg',
    'rel_err': 'rel_err_alg',
    'abs_err': 'abs_err_alg',
    'rel_err_total': 'rel_total_err_alg',
    'rel_err_total_baseline': 'rel_total_err_baseline',
    'baseline': 'violation_baseline',
    'computed': 'violation_alg',
    'measured': 'violation_ground_truth',
}, inplace=True)

if not (len(plot_list) == 1 and "quantiles" in plot_list) or args.sample:
    target_samples = args.sample if args.sample else 100000
    n_samples = min(len(df), target_samples)
    print(f"sampling... ({n_samples} of {len(df)})")
    if args.only_nonzero:
        df = df[df["violation_ground_truth"] > 0.0]
    df = df.sample(n_samples)

print("filtering the model...")
if args.include_model:
    df = df[df["model"].isin(args.include_model)]
if args.exclude_model:
    for model in args.exclude_model:
        df = df[df["model"].map(lambda m: model not in m)]

# print statistics
models = set(df["model"])
for model in models:
    dfm = df[df["model"] == model]
    if model == "fw_updates":
        mean_baseline_err = dfm["abs_err_baseline"].mean()
        mean_alg_err = dfm["abs_err_alg"].mean()
        print("Model", model)
        print("  Compare to the baseline algorithm")
        print("    mean baseline error:", mean_baseline_err)
        print("    mean algorithm error:", mean_alg_err)
        print("    algorithm improvement (in mean):", (mean_baseline_err - mean_alg_err) / mean_baseline_err)

    no_model = min((m for m in models if m[:-4] in model), key=lambda x: len(x))
    if no_model != model:
        dfnm = df[df["model"] == no_model]
        print("Model", model)
        print("  Compare to", no_model)
        mean_naive_err = dfnm["abs_err_alg"].mean()
        mean_fib_queue_err = dfm["abs_err_alg"].mean()
        print("    mean naive error:", mean_naive_err)
        print("    mean FIB queue error:", mean_fib_queue_err)
        print("    FIB queue improvement (in mean):", (mean_naive_err - mean_fib_queue_err) / mean_naive_err)


print("transforming...")
# add "source" column, transofrm to long
id_cols = ["sample_id", "model", "scenario", "num_prefixes", "rid", "prefix"]
df_all = pd.wide_to_long(df, stubnames=["err", "rel_err", "abs_err", "rel_total_err", "violation"], i=id_cols, sep="_", j="source", suffix='\\w+').reset_index()

# filter models
print("filtering the algorithm...")
if args.include_algorithm:
    df_all = df_all[df_all["source"].isin(args.include_algorithm)]
if args.exclude_algorithm:
    for algorithm in args.exclude_algorithm:
        df_all = df_all[df_all["source"] != algorithm]

# generate ID column
df_all["id"] = df_all.apply(lambda row: ", ".join((str(row[c]) for c in id_cols if c not in {"scenario", "model"})), axis=1)

if "raw" in plot_list:
    print("sorting...")
    df_all.sort_values("violation", inplace=True)
    df_all.sort_values("source", inplace=True)
    df_all.sort_values("model", inplace=True)

df = df_all[df_all["source"] != "ground_truth"]

hover_data = ["sample_id", "model", "scenario", "num_prefixes", "router", "prefix", "err", "abs_err", "rel_err", "rel_total_err", "violation"]

if "err" in plot_list:
    print("Creating eval.html")
    # create the CDF plots
    # Signed error, ground_truth - computed, to allow deducing which value is typically larger.
    fig = px.ecdf(
        df,
        x="err",
        color="model",
        line_dash="source",
        hover_data=hover_data,
        labels={"err": "(Signed) Error", "cdf": "CDF", "source": "Algorithm"},
        title="CDF of (signed) error, (ground_truth - computed), by input source / algorithm used"
    )
    if args.show:
        fig.show()
    fig.write_html(args.eval_path + "/eval.html")

if "rel_err" in plot_list:
    filename = os.path.join(args.eval_path, "eval_rel.html")
    print(f"Creating {filename}")
    fig_rel = px.ecdf(
        df,
        x="rel_err",
        color="model",
        line_dash="source",
        hover_data=hover_data,
        labels={"rel_err": "Relative Error", "cdf": "CDF", "source": "Algorithm"},
        title="CDF of relative error by input source / algorithm used"
    )
    if args.show:
        fig_rel.show()
    fig_rel.write_html(filename)

    def rel_err_cdf(df):
        df = df.sort_values(["rel_err"]).reset_index()[["model", "source", "rel_err"]]
        df["cdf"] = df.index / len(df)
        # sample equidistant points to make plotting sufficiently fast
        df = df[df.index % (len(df) // 1000) == 0]
        return df

    cdf = df.groupby(["model", "source"]).apply(rel_err_cdf).reset_index(drop=True)
    cdf.sort_values(["model", "source", "cdf"], inplace=True)

    for model in args.include_model:
        cdf[cdf["model"] == model].to_csv(os.path.join(args.eval_path, f"rel_error_{model}.csv"), index=False)

    filename = os.path.join(args.eval_path, "eval_rel_vs_violation.html")
    print(f"Creating {filename}")
    # print the violation in these groups
    def violation_bins(df):
        def violation_mean(x):
            return x.mean()
        def violation_q50(x):
            return x.quantile(0.5)
        def violation_q75(x):
            return x.quantile(0.75)
        def violation_q90(x):
            return x.quantile(0.9)
        df = df.sort_values("rel_err").reset_index()
        del df["index"]
        df["cdf"] = (df.index * 50 / len(df)).astype(int) / 50.0 + 0.01
        df = df.groupby("cdf")["violation"].aggregate([violation_mean, violation_q50, violation_q75, violation_q90]).reset_index()
        return pd.wide_to_long(df, stubnames="violation", i="cdf", j="aggregate", suffix="\\w+", sep="_")
    violation = df.groupby(["model", "source"]).apply(violation_bins).reset_index()
    violation["model, source"] = violation["model"].astype(str) + ", " + violation["source"].astype(str)
    fig_rel = px.line(
        violation,
        x="violation",
        y="cdf",
        color="model, source",
        line_dash="aggregate",
        title="Violation time in CDF bins of the relative error",
    )
    if args.show:
        fig_rel.show()
    fig_rel.write_html(filename)






# Plot the relative error w.r.t. the total convergence time for the prefix.
# Supposed to help mitigate problems with 0-violation entries.
if "rel_total_err" in plot_list:
    filename = os.path.join(args.eval_path, "eval_rel_total.html")
    print(f"Creating {filename}")
    fig_rel_total = px.ecdf(
        df,
        x="rel_total_err",
        color="model",
        line_dash="source",
        hover_data=hover_data,
        labels={"rel_err_total": "Relative Error", "cdf": "CDF", "source": "Algorithm"},
        title="CDF of total relative error (w.r.t. total convergence time) by input source / algorithm used"
    )
    if args.show:
        fig_rel_total.show()
    fig_rel_total.write_html(filename)

    def rel_total_err_cdf(df):
        df = df.sort_values(["rel_total_err"]).reset_index()[["model", "source", "rel_total_err"]]
        df["cdf"] = df.index / len(df)
        # sample equidistant points to make plotting sufficiently fast
        df = df[df.index % (len(df) // 1000) == 0]
        return df

    cdf = df.groupby(["model", "source"]).apply(rel_total_err_cdf).reset_index(drop=True)
    cdf.sort_values(["model", "source", "cdf"], inplace=True)

    for model in args.include_model:
        cdf[cdf["model"] == model].to_csv(os.path.join(args.eval_path, f"rel_total_err_{model}.csv"), index=False)

if "abs_err" in plot_list:
    filename = os.path.join(args.eval_path, "eval_abs.html")
    print(f"Creating {filename}")
    fig_abs = px.ecdf(
        df,
        x="abs_err",
        color="model",
        line_dash="source",
        hover_data=hover_data,
        labels={"abs_err": "Absolute Error", "cdf": "CDF", "source": "Algorithm"},
        title="CDF of absolute error by input source / algorithm used"
    )
    if args.show:
        fig_abs.show()
    fig_abs.write_html(filename)

    def abs_err_cdf(df):
        df = df.sort_values(["abs_err"]).reset_index()[["model", "source", "abs_err"]]
        df["cdf"] = df.index / len(df)
        # sample equidistant points to make plotting sufficiently fast
        df = df[df.index % (len(df) // 1000) == 0]
        return df

    cdf = df.groupby(["model", "source"]).apply(abs_err_cdf).reset_index(drop=True)
    cdf.sort_values(["model", "source", "cdf"], inplace=True)

    for model in args.include_model:
        cdf[cdf["model"] == model].to_csv(os.path.join(args.eval_path, f"abs_error_{model}.csv"), index=False)

# Plot the violation times as CDFs to illustrate whether the distributions are similar.
if "violation" in plot_list:
    filename = os.path.join(args.eval_path, "eval_total.html")
    print(f"Creating {filename}")
    fig_total = px.ecdf(
        df_all,
        x="violation",
        color="model",
        line_dash="source",
        hover_data=hover_data,
        labels={"violation": "Total Violation Time", "cdf": "CDF", "source": "Algorithm"},
        title="CDF of total violation by input source / algorithm used"
    )
    if args.show:
        fig_total.show()
    fig_total.write_html(filename)

# Plot the raw data, each line on the y axis corresponding to one EvaluationRecord.
# Ideally, shapes should be similar / follow the ground truth.
if "raw" in plot_list:
    filename = os.path.join(args.eval_path, "eval_raw.html")
    print(f"Creating {filename}")
    fig_raw = px.scatter(
        df_all,
        x="violation",
        y="id",
        color="model",
        hover_data=hover_data,
        labels={"violation": "Total Violation Time", "id": "Measurement Identifier (sample_id, model, scenario, rid, prefix)"},
        title="Raw violation by input source / algorithm used"
    )
    if args.show:
        fig_raw.show()
    fig_raw.write_html(filename)

if "quantiles" in plot_list:
    filename = os.path.join(args.eval_path, "eval_quantiles.html")
    print(f"Creating {filename}")
    percentiles = args.perc if args.perc else [0.5, 0.75, 0.8, 0.9, 0.95, 0.99]
    percentiles = [float(p) for p in percentiles]
    quantiles = df.groupby(["model", "source", "num_prefixes"]).quantile(percentiles).reset_index().rename(columns = {"level_3": "quantile"})

    quantiles["model_source"] = quantiles["model"].astype(str) + ", " + quantiles["source"].astype(str)

    fig_quantiles = px.line(
        quantiles,
        x="num_prefixes",
        y="abs_err",
        log_x=True,
        log_y=True,
        color="model_source",
        line_dash="quantile",
        title="Absolute error quantiles by number of prefixes",
    )
    if args.show:
        fig_quantiles.show()
    fig_quantiles.write_html(filename)

    # prepare csv
    percentiles = args.perc if args.perc else [0.5, 0.75, 0.8, 0.9, 0.95, 0.99]
    quantiles = df.groupby(["model", "source", "num_prefixes"])[["model", "source", "abs_err"]].quantile(percentiles).reset_index().rename(columns = {"level_3": "quantile"})
    avg = df.groupby(["model", "source", "num_prefixes"])[["model", "source", "abs_err"]].mean()
    avg["quantile"] = "avg"
    avg.reset_index(inplace=True)
    quantiles = pd.concat([quantiles, avg], sort=True)
    quantiles["key"] = quantiles["model"].astype(str) + ":" + quantiles["source"].astype(str) + ":" + quantiles["quantile"].astype(str)
    quantiles = quantiles.pivot(columns="key", index="num_prefixes", values="abs_err")
    quantiles.to_csv(os.path.join(args.eval_path, "quantiles.csv"))
