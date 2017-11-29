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
#ifndef _TRAINER_
#define _TRAINER_

#include <float.h>
#include <limits.h>
#include <stdio.h>
#include <vector>

#include "defines.h"

// Contains times / losses / etc
struct TrainStatistics {
    std::vector<double> times;
    std::vector<double> losses;
};

typedef struct TrainStatistics TrainStatistics;

class Trainer {
protected:
    void TrackTimeLoss(double cur_time, double cur_loss, TrainStatistics *stats) {
        stats->times.push_back(cur_time);
        stats->losses.push_back(cur_loss);
    }

    void PrintPartitionTime(Timer &timer) { printf("Partition Time(s): %f\n", timer.Elapsed()); }

    void PrintTimeLoss(double cur_time, double cur_loss, int epoch) {
        printf("Epoch: %d\tTime(s): %f\tLoss: %lf\t\n", epoch, cur_time, cur_loss);
    }

    void EpochBegin(int epoch, Timer &gradient_timer, Model *model, const std::vector<Datapoint *> &datapoints,
                    TrainStatistics *stats) {
        double cur_time = gradient_timer.Elapsed();
        double cur_loss = model->ComputeLoss(datapoints);
        TrackTimeLoss(cur_time, cur_loss, stats);
        if (FLAGS_print_loss_per_epoch && epoch % FLAGS_interval_print == 0) {
            PrintTimeLoss(cur_time, cur_loss, epoch);
        }
    }

public:
    Trainer() {
        /*
        // Some error checking.
        if (FLAGS_n_threads > std::thread::hardware_concurrency()) {
            std::cerr << "Trainer: Number of threads is greater than the number of physical cores." << std::endl;
            // exit(0);
        }

        // Basic set up, like pinning to core, setting number of threads.
        omp_set_num_threads(FLAGS_n_threads);
#pragma omp parallel
        { pin_to_core(omp_get_thread_num()); }
        */
    }
    virtual ~Trainer() {}

    // Main training method.
    virtual TrainStatistics Train(Model *model, const std::vector<Datapoint *> &datapoints, Updater *updater) = 0;
};

#endif
