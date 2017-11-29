/*
* Copyright 2016 [See AUTHORS file for list of authors]
*
*    Licensed under the Apache License, Version 2.0 (the "License");
*    you may not use this file except in compliance with the License.
*    You may obtain a copy of the License at
*
*        http://www.apache.org/licenses/LICENSE-2.0
*
*    Unless required by applicable law or agreed to in writing, software
*    distributed under the License is distributed on an "AS IS" BASIS,
*    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*    See the License for the specific language governing permissions and
*    limitations under the License.
*/
#ifndef _CYCLADES_PARTITIONER_
#define _CYCLADES_PARTITIONER_

#include <unordered_map>

#include "Partitioner/Partitioner.h"

DEFINE_int32(cyclades_batch_size, 5000, "Batch size for cyclades.");

class CycladesPartitioner : public Partitioner {
private:
    int model_size;

    int UnionFind(int a, std::vector<int> &p) {
        int root = a;
        while (p[a] != a)
            a = p[a];
        while (root != a) {
            int root2 = p[root];
            p[root] = a;
            root = root2;
        }
        return a;
    }

    void ComputeCC(const std::vector<Datapoint *> &datapoints, int start_index, int end_index,
                   std::unordered_map<int, std::vector<Datapoint *>> &components) {
        auto n = end_index - start_index;
        std::vector<int> tree(FLAGS_cyclades_batch_size + model_size);
        // Initialize tree for union find.
        for (int i = 0; i < tree.size(); i++)
            tree[i] = i;

        // CC Computation.
        for (int i = 0; i < n; i++) {
            int target = UnionFind(i, tree);
            for (auto const &c : datapoints[start_index + i]->GetCoordinates())
                tree[UnionFind(n + c, tree)] = target;
        }

        for (int i = 0; i < n; i++) {
            components[UnionFind(i, tree)].push_back(datapoints[start_index + i]);
        }
    }

public:
    CycladesPartitioner(Model *model) : Partitioner() { model_size = model->NumParameters(); }

    ~CycladesPartitioner() {}

    // Basic partitioner return partition with 1 batch, each thread gets an equal
    // split of a shuffled portion of the datapoints.
    DatapointPartitions Partition(const std::vector<Datapoint *> &datapoints, int n_threads) {
        DatapointPartitions partitions(n_threads);

        // Shuffle the datapoints.
        std::vector<Datapoint *> datapoints_copy(datapoints);

        // Calculate overall number of batches.
        int num_total_batches = ceil((double)datapoints_copy.size() / (double)FLAGS_cyclades_batch_size);

        // Process FLAGS_cyclades_batch_size pointer per iteration, computing CCS on them.
        std::vector<std::unordered_map<int, std::vector<Datapoint *>>> components(num_total_batches);
        //#pragma omp parallel for
        for (int batch = 0; batch < num_total_batches; batch++) {
            // Current batch index.
            int start = batch * FLAGS_cyclades_batch_size;
            int end = std::min(start + FLAGS_cyclades_batch_size, (int)datapoints_copy.size());

            // Compute components.
            ComputeCC(datapoints_copy, start, end, components[batch]);
        }

        for (int batch = 0; batch < num_total_batches; batch++) {
            // Load balance the connected components within the batch (not across it).
            for (auto it = components[batch].begin(); it != components[batch].end(); it++)
                partitions.AddDatapointsToLeastLoadedThread(it->second);
            partitions.StartNewBatch();
        }

        return partitions;
    }
};

#endif
