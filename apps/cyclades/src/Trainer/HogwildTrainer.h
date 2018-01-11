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
#ifndef _HOGWILD_TRAINER_
#define _HOGWILD_TRAINER_

#include "Trainer/Trainer.h"

class HogwildTrainer : public Trainer {
public:
    HogwildTrainer() {}
    ~HogwildTrainer() {}

    TrainStatistics Train(Model *model, const std::vector<Datapoint *> &datapoints, Updater *updater) override {
        // Partition.
        BasicPartitioner partitioner;
        Timer partition_timer;
        DatapointPartitions partitions = partitioner.Partition(datapoints, FLAGS_n_threads);
        if (FLAGS_print_partition_time) {
            this->PrintPartitionTime(partition_timer);
        }

        model->SetUpWithPartitions(partitions);
        updater->SetUpWithPartitions(partitions);

        // Keep track of statistics of training.
        TrainStatistics stats;

        // Train.
        Timer gradient_timer;
        for (int epoch = 0; epoch < FLAGS_n_epochs; epoch++) {
            int batch = 0;
            int num_datapoints = partitions.NumDatapointsInBatch(FLAGS_wid, batch);

            auto t1 = std::chrono::high_resolution_clock::now();
            EpochBegin(epoch, gradient_timer, model, datapoints, &stats);
            updater->EpochBegin();
            model->EpochBegin();
            auto t2 = std::chrono::high_resolution_clock::now();
            model->BatchBegin(batch);
            auto t3 = std::chrono::high_resolution_clock::now();
            for (int dp_index = 0; dp_index < num_datapoints; dp_index++) {
                int datapoint = FLAGS_random_per_batch_datapoint_processing ? rand() % num_datapoints : dp_index;
                updater->Update(partitions.GetDatapoint(FLAGS_wid, batch, datapoint));
            }
            auto t4 = std::chrono::high_resolution_clock::now();
            model->BatchFinish(batch);
            auto t5 = std::chrono::high_resolution_clock::now();
            updater->EpochFinish();
            model->EpochFinish();
            auto t6 = std::chrono::high_resolution_clock::now();

            auto etb = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            auto et1 = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();
            auto et2 = std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count();
            auto et3 = std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count();
            auto ete = std::chrono::duration_cast<std::chrono::milliseconds>(t6 - t5).count();
            auto tot = etb + ete + et1 + et2 + et3;
            printf("tot=%9.3f -- eb=%9.3fms bb=%9.3fms cp=%9.3fms be=%9.3fms ee=%9.3fms\n", tot, etb, et1, et2, et3,
                   ete);
        }
        return stats;
    }
};

#endif
