#!/usr/bin/python3

from itertools import permutations, product
import math
import numpy as np
import pandas as pd
import glob
import os
import pprint
import re
import sys
import seaborn as sns
sns.set()

rmap_raw = {}
rmap_stats = {}
stats_df = None


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
        rmap_stats_this = {}
        rmap_raw_this = {}
        runid = None
        with open(fname) as f:
            try:
                lastline = None
                for line in f:
                    # tidy up output
                    line = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/ ]*[@-~]', '', line)
                    line = re.sub(r'[0-9]+\.[0-9]{3}.+tasvir.+', '', line)
                    line = re.sub(r'=\s+', '=', line)
                    line = re.sub(r'\s+', ' ', line).strip()
                    if line.startswith('RUNS'):
                        line = line.replace('RUNS ', '')
                        runid = [i.split('=') for i in line.split()]
                    elif line.startswith('RESULTS'):
                        line = line.replace('RESULTS ', '')
                        runid = [i.split('=') for i in line.split()]
                        rmap_stats_this[normalize(runid)] = {}
                    elif not line or not runid or 'cmdline' in line:
                        continue
                    elif lastline or line.startswith('round'):
                        if lastline:
                            a = lastline
                            b = line
                            lastline = None
                        else:
                            a, b = line.split(':')
                            if b == '':
                                lastline = a
                                continue
                        runid_this = runid + [i.split('=') for i in a.split()]
                        res = [i.split('=') for i in b.split()]
                        res = {k: convert_type(v) for k, v in res}
                        rmap_raw_this[normalize(runid_this)] = res
                    else:
                        k, v = line.replace(' ', '').split('=')
                        rmap_stats_this[normalize(runid)][k] = convert_type(v)

                for k, v in rmap_stats_this.items():
                    rmap_stats[k] = v
                for k, v in rmap_raw_this.items():
                    rmap_raw[k] = v
            except Exception as e:
                print(fname, e, line)
                pass

    for fname in glob.glob("%s/*/t0.*" % (log_dir, )):
        process_file(fname)

    col_l = None
    stats_l = []
    for k, v in rmap_stats.items():
        l = sorted(list(k) + [(i, j) for i, j in v.items()])
        if not col_l:
            col_l = [k for k, v in l]
        stats_l.append([v for k, v in l])
    global stats_df
    stats_df = pd.DataFrame(stats_l, columns=col_l)


def tabulate():
    for k, v in rmap_raw.items():
        print(k)
        print("\t", v)
    for k, v in rmap_stats.items():
        print(k)
        print("\t", v)


def overhead():
    # runid: (round, stream, random, log, service)
    # result: (time_ms, sync_success, sync_failure, sync_time_ms, sync_size_kb)
    # 'area_len_kb', 'core', 'cpu', 'nr_workers', 'nr_writers', 'overhead_direct_pct', 'overhead_full_pct', 'overhead_indirect_pct', 'overhead_isync_full_pct', 'overhead_isync_noop_pct', 'overhead_log_pct', 'overhead_serv_pct', 'random', 'runtime_1m_l0s0_us', 'runtime_1m_l0s1_us', 'runtime_1m_l1s0_us', 'runtime_1m_l1s1_us', 'service_us', 'stream', 'stride_b', 'sync_ext_us', 'sync_int_us', 'sync_write_pct', 'sync_xput_mbps', 'sync_xput_per_core_mbps', 'wid', 'write_xput_l0s0_mbps', 'write_xput_l0s1_mbps', 'write_xput_l1s0_mbps', 'write_xput_l1s1_mbps'
    # col_n = list(stats_df)
    # print(col_n)
    #mi = pd.MultiIndex.from_frame(stats_df)
    #dfr = pd.DataFrame(data=dist, index=index, columns=['df'])
    #print(data.head())

    # print(stats_df.groupby(['area_len_kb'], as_index=False).last()) #.unstack('area_len_kb'))
    # return
    for random, stream, nr_workers, sync_int_us in product([0, 1], [0, 1], [1], [1000, 10000, 100000]):
    # for random, stream, nr_workers, sync_int_us in product([0, 1], [0, 1], [1, 3, 5, 7], [1000, 10000, 100000]):
        try:
            df = stats_df[(stats_df.random == random) & (stats_df.stream == stream) & (stats_df.nr_workers == nr_workers) & (stats_df.sync_int_us == sync_int_us)].sort_values('area_len_kb')
            title = 'random=%d,stream=%d,nr_workers=%d,sync_int_us=%d' % (random, stream, nr_workers, sync_int_us)
            # p = df.plot.bar(x='area_len_kb', y=['overhead_full_pct'], stacked=True, title=title, ylim=(0, 100))
            max_val = df[['overhead_serv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct']].max(axis=1).max()
            max_val = 50 * math.ceil(max_val / 50.)
            with sns.axes_style('white'):
                p = df.plot.bar(x='area_len_kb', y=['overhead_serv_pct', 'overhead_log_pct', 'overhead_isync_full_pct', 'overhead_indirect_pct'], stacked=False, title=title, ylim=(0, max_val), figsize=(8, 6))
                p.get_figure().tight_layout()
                p.get_figure().savefig("%s/zz.plots/test_r%ds%dw%dsi%06d.png" % (sys.argv[1], random, stream, nr_workers, sync_int_us))
        except Exception as e:
            print('failed for r%ds%dw%d: %s' % (random, stream, nr_workers, e))

    #for isync in [1000, 10000, 100000]:
    #    for k, v in rmap_stats.items():


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s log_directory" % (sys.argv[0], ))
        sys.exit(1)
    process_logs(sys.argv[1])
    try:
        os.mkdir('%s/zz.plots' % sys.argv[1])
    except:
        pass
    # tabulate()
    overhead()
