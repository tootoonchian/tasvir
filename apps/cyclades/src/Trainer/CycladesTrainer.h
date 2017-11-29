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
#ifndef _CYCLADES_TRAINER_
#define _CYCLADES_TRAINER_

#include "Trainer/Trainer.h"

class CycladesTrainer : public Trainer {
private:
    void DebugPrintPartitions(DatapointPartitions &p) {
        int n_batches = p.NumBatches();
        for (int i = 0; i < n_batches; i++) {
            std::cout << "Batch " << i << std::endl;
            for (int j = 0; j < FLAGS_n_threads; j++) {
                std::cout << "Thread " << j << ": ";
                for (int k = 0; k < p.NumDatapointsInBatch(j, i); k++) {
                    if (k != 0)
                        std::cout << " ";
                    std::cout << p.GetDatapoint(j, i, k).GetOrder();
                }
                std::cout << std::endl;
            }
        }
    }

public:
    CycladesTrainer() {}

    ~CycladesTrainer() {}

    TrainStatistics Train(Model *model, const std::vector<Datapoint *> &datapoints, Updater *updater) override {
        // Partitions.
        CycladesPartitioner partitioner(model);
        Timer partition_timer;
        DatapointPartitions partitions = partitioner.Partition(datapoints, FLAGS_n_threads);
        // DebugPrintPartitions(partitions);
        if (FLAGS_print_partition_time) {
            printf("Number of partitions: %d\n", partitions.NumBatches());
            PrintPartitionTime(partition_timer);
        }

        model->SetUpWithPartitions(partitions);
        updater->SetUpWithPartitions(partitions);
        printf("Model size: %d\n", model->NumParameters() * model->NumCoordinates());
        // Keep track of statistics of training.
        TrainStatistics stats;

        // Train.
        Timer gradient_timer;
        for (int epoch = 0; epoch < FLAGS_n_epochs; epoch++) {
            int num_batches = partitions.NumBatches();
            double et1 = 0, et2 = 0, et3 = 0, etb = 0, ete = 0;
            auto t1 = std::chrono::high_resolution_clock::now();
            EpochBegin(epoch, gradient_timer, model, datapoints, &stats);
            updater->EpochBegin();
            auto t2 = std::chrono::high_resolution_clock::now();
            for (int batch_index = 0; batch_index < num_batches; batch_index++) {
                int batch = FLAGS_random_batch_processing ? rand() % partitions.NumBatches() : batch_index;
                int num_datapoints = partitions.NumDatapointsInBatch(FLAGS_wid, batch);
                auto t1 = std::chrono::high_resolution_clock::now();
                model->BatchBegin(batch);
                auto t2 = std::chrono::high_resolution_clock::now();
                for (int dp_index = 0; dp_index < num_datapoints; dp_index++) {
                    int datapoint = FLAGS_random_per_batch_datapoint_processing ? rand() % num_datapoints : dp_index;
                    updater->Update(partitions.GetDatapoint(FLAGS_wid, batch, datapoint));
                }
                auto t3 = std::chrono::high_resolution_clock::now();
                model->BatchFinish(batch);
                auto t4 = std::chrono::high_resolution_clock::now();
                et1 += std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
                et2 += std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();
                et3 += std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
            }
            auto t3 = std::chrono::high_resolution_clock::now();
            updater->EpochFinish();
            auto t4 = std::chrono::high_resolution_clock::now();
            etb = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
            ete = std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
            auto tot = etb + ete + et1 + et2 + et3;
            printf("tot=%9.3f -- eb=%9.3fms bb=%9.3fms cp=%9.3fms be=%9.3fms ee=%9.3fms\n", tot / 1000., etb / 1000.,
                   et1 / 1000., et2 / 1000., et3 / 1000., ete / 1000.);
            // printf("per_b: %9.3fus %9.3fus %9.3fus\n", et1 / num_batches, et2 / num_batches, et3 / num_batches);
        }
        return stats;
    }
};

#endif
