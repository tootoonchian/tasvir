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

#ifndef _UPDATER_
#define _UPDATER_

#include "DatapointPartitions/DatapointPartitions.h"
#include "Gradient/Gradient.h"

class Updater {
protected:
    // Keep a reference of the model and datapoints, and partition ordering.
    Model *model;
    std::vector<Datapoint *> datapoints;
    DatapointPartitions *datapoint_partitions;

    // Gradient object stores extra info for Model processing
    Gradient gradient;

    std::vector<int> bookkeeping;
    // A reference to all_coordinates, which indexes all the coordinates of the model.
    std::vector<int> all_coordinates;

    // H, Nu and Mu for updates.
    virtual double H(int coordinate, int index_into_coordinate_vector) { return 0; }
    virtual double Nu(int coordinate, int index_into_coordinate_vector) { return 0; }
    virtual double Mu(int coordinate) { return 0; }

    // After calling PrepareNu/Mu/H, for the given coordinates, we expect that
    // calls to Nu/Mu/H are ready.
    virtual void PrepareNu(const std::vector<int> &coordinates) {}
    virtual void PrepareMu(const std::vector<int> &coordinates) {}
    virtual void PrepareH(const Datapoint &datapoint) {}

    // By default need catch up.
    virtual bool NeedCatchUp() { return true; }

    virtual void ApplyGradient(const Datapoint &datapoint) {
        static int cnt = 0;
        int n_coords = model->NumCoordinates();
        for (const auto &c : datapoint.GetCoordinates()) {
            const auto &mu = Mu(c);
            tasvir_log_write(&model->Data(c, 0, false), sizeof(double) * n_coords);
            for (int j = 0; j < n_coords; j++)
                model->Data(c, j, false) = (1 - mu) * model->Data(c, j, false) - Nu(c, j) + H(c, j);
        }
    }

    virtual void CatchUp(int index, int diff) {
        if (!NeedCatchUp())
            return;
        if (diff < 0)
            diff = 0;
        int n_coords = model->NumCoordinates();
        double geom_sum = 0;
        double mu = Mu(index);
        if (mu != 0)
            geom_sum = ((1 - pow(1 - mu, diff + 1)) / (1 - (1 - mu))) - 1;
        tasvir_log_write(&model->Data(index, 0, false), sizeof(double) * n_coords);
        for (int j = 0; j < n_coords; j++)
            model->Data(index, j, false) =
                pow(1 - mu, diff) * model->Data(index, j, false) - Nu(index, j) * geom_sum;
    }

    virtual void CatchUpDatapoint(const Datapoint &datapoint) {
        int n_coords = model->NumCoordinates();
        for (const auto &c : datapoint.GetCoordinates()) {
            int diff = datapoint.GetOrder() - bookkeeping[c] - 1;
            CatchUp(c, diff);
        }
    }

    virtual void FinalCatchUp() {
        const auto &n_coords = model->NumCoordinates();
        const auto &parameter_size = model->NumParameters();

        // #pragma omp parallel num_threads(FLAGS_n_threads)
        PrepareNu(all_coordinates);
        PrepareMu(all_coordinates);
        // #pragma omp for
        for (int i = 0; i < model->NumParameters(); i++) {
            int diff = parameter_size - bookkeeping[i];
            CatchUp(i, diff);
        }
    }

public:
    Updater(Model *model, std::vector<Datapoint *> &datapoints) {
        this->model = model;
        this->datapoints = datapoints;

        for (int i = 0; i < model->NumParameters(); i++) {
            // Set up bookkeping.
            bookkeeping.push_back(0);
            // Keep an array that has integers 1...n_coords.
            all_coordinates.push_back(i);
        }
    }

    Updater() {}
    virtual ~Updater() {}

    // Could be useful to get partitioning info.
    virtual void SetUpWithPartitions(DatapointPartitions &partitions) { datapoint_partitions = &partitions; }

    // Main update method, which is run by multiple threads.
    virtual void Update(const Datapoint &datapoint) {
        gradient.Clear();
        gradient.datapoint = &datapoint;

        // First prepare Nu and Mu for catchup since they are independent of the the model.
        PrepareNu(datapoint.GetCoordinates());
        PrepareMu(datapoint.GetCoordinates());
        CatchUpDatapoint(datapoint);

        // After catching up, prepare H and apply the gradient.
        PrepareH(datapoint);
        ApplyGradient(datapoint);

        // Update bookkeeping.
        for (const auto &coordinate : datapoint.GetCoordinates())
            bookkeeping[coordinate] = datapoint.GetOrder();
    }

    // Called before epoch begins.
    virtual void EpochBegin() {}

    // Called when the epoch ends.
    virtual void EpochFinish() {
        FinalCatchUp();
        std::fill(bookkeeping.begin(), bookkeeping.end(), 0);
    }
};

#endif
