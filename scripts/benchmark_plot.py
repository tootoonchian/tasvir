#!/usr/bin/python3

from itertools import permutations, product
import math
import numpy as np
import pandas as pd
import glob
import os
from pprint import pprint
import re
import sys
import seaborn as sns
sns.set()


def process_logs(log_dir):
    def convert_type(v):
        if '.' in v:
            return float(v)
        elif v.isdigit():
            return int(v)
        else:
            return v

    def normalize(l):
        return tuple(sorted((k, convert_type(v)) for k, v in l))

    def process_file(fname):
        stats_this = {}
        runs_this = {}
        runid = None
        cmdline = None
        with open(fname) as f:
            try:
                for line in f:
                    # tidy up output
                    line = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/ ]*[@-~]', '', line)
                    line = re.sub(r'[0-9]+\.[0-9]{3}.+tasvir.+', '', line)
                    line = re.sub(r'=\s+', '=', line)
                    line = re.sub(r'\s+', ' ', line).strip()
                    if line.startswith('workload'):
                        runid = [i.split('=') for i in line.split()]
                        stats_this[normalize(runid)] = {}
                    elif line.startswith('round'):
                        a, b = line.split(':')
                        runid_this = runid + [i.split('=') for i in a.split()]
                        res = [i.split('=') for i in b.split()]
                        res = {k: convert_type(v) for k, v in res}
                        runs_this[normalize(runid_this)] = res
                    elif '=' in line:
                        k, v = line.replace(' ', '').split('=')
                        stats_this[normalize(runid)][k] = convert_type(v)

                for k, v in stats_this.items():
                    stats[k] = v
                for k, v in runs_this.items():
                    runs[k] = v
            except Exception as e:
                print('oops', fname, e, line)
                raise e

    for fname in glob.glob("%s/*/t0.*" % (log_dir, )):
        process_file(fname)

    col_l = None
    stats_l = []
    for k, v in stats.items():
        l = sorted(list(k) + [(i, j) for i, j in v.items()])
        if not col_l:
            col_l = [k for k, v in l]
        stats_l.append([v for k, v in l])
    global stats_df
    stats_df = pd.DataFrame(stats_l, columns=col_l)


def tabulate():
    for k, v in runs.items():
        print(k)
        print("\t", v)
    for k, v in stats.items():
        print(k)
        print("\t", v)


def overhead_interval():
    df = stats_df[['overhead_srv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct']]
    df = df[(df.workload == 'WRITE_SEQ')].sort_values('area_len_kb')
    df = df.groupby(['sync_int_us'])
    print(stats_df.groupby(['area_len_kb'], as_index=False).last()) #.unstack('area_len_kb'))
    # for nr_workers, sync_int_us in product([1, 3, 5, 7], [1000, 10000, 100000]):

def overhead():
    col_n = list(stats_df)
    print(col_n)
    return

    # knobs: workload, sync_int_us, nr_workers, area_len, stride
    for workload, nr_workers, sync_int_us in product(['WRITE_SEQ', 'WRITE_RND'], [1, 3, 5, 7], [1000, 10000, 100000]):
        try:
            df = stats_df[(stats_df.workload == workload) & (stats_df.nr_workers == nr_workers) & (stats_df.sync_int_us == sync_int_us)].sort_values('area_len_kb')
            title = 'workload=%s,nr_workers=%d,sync_int_us=%d' % (workload, nr_workers, sync_int_us)
            # p = df.plot.bar(x='area_len_kb', y=['overhead_full_pct'], stacked=True, title=title, ylim=(0, 100))
            with sns.axes_style('white'):
                for t in ['overhead_srv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct']:
                    max_val = df[t].max()
                    max_val = 20 * math.ceil(max_val / 20.)
                    p = df.plot.bar(x='area_len_kb', y=[t], stacked=False, title=title, ylim=(0, max_val), figsize=(8, 6))
                    fig = p.get_figure()
                    fig.tight_layout()
                    fig.savefig("%s/%s_%s_w%dsi%06d.png" % (out_dir, t, workload, nr_workers, sync_int_us))
                    fig.clf()

                max_val = df[['overhead_srv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct']].max(axis=1).max()
                max_val = 20 * math.ceil(max_val / 20.)
                p = df.plot.bar(x='area_len_kb', y=['overhead_srv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct'], stacked=False, title=title, ylim=(0, max_val), figsize=(8, 6))
                fig = p.get_figure()
                fig.tight_layout()
                fig.savefig("%s/stacked_%s_w%dsi%06d.png" % (out_dir, workload, nr_workers, sync_int_us))
                fig.clf()
        except Exception as e:
            print('failed for %s_w%d: %s' % (workload, nr_workers, e))
    """
    df = stats_df[stats_df.overhead_log_pct > 20]
    df = df[['overhead_srv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct']]
    max_val = df.max(axis=1).max()
    with sns.axes_style('white'):
        ax = sns.heatmap(df, vmin=0, vmax=100)
        fig = ax.get_figure()
        fig.tight_layout()
        fig.savefig('%s/zz.heatmap.png' % out_dir)
    """


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s log_directory" % (sys.argv[0], ))
        sys.exit(1)

    runs = {}
    stats = {}
    stats_df = None

    out_dir = '%s/zz.plots' % sys.argv[1]
    process_logs(sys.argv[1])
    try:
        os.mkdir('%s/zz.plots' % sys.argv[1])
    except:
        pass
    overhead()
