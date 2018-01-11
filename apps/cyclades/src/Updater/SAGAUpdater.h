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

#ifndef _SAGA_UPDATER_
#define _SAGA_UPDATER_

#include "Updater/Updater.h"

class SAGAUpdater : public Updater {
protected:
    // Data structures for capturing the gradient.
    std::vector<std::vector<double>> h;
    int datapoint_order;

    // SAGA data structures.
    std::vector<std::vector<std::vector<double>>> prev_gradients;
    std::vector<std::vector<double>> sum_gradients;  // global

    void CatchUp(int index, int diff) override {
        if (diff < 0)
            diff = 0;

        const auto &n_coords = model->NumCoordinates();
        tasvir_log_write(&model->Data(index, 0, false), sizeof(double) * n_coords);
        for (int j = 0; j < n_coords; j++) {
            model->Data(index, j, false) -= FLAGS_learning_rate * diff * sum_gradients[index][j] / datapoints.size();
        }
    }

    void PrepareH(const Datapoint &datapoint) override {
        model->PrecomputeCoefficients(datapoint, gradient, *model);
        for (const auto &c : datapoint.GetCoordinates())
            model->H_bar(c, h[c], gradient, *model);
        datapoint_order = datapoint.GetOrder() - 1;
    }

    double H(int coordinate, int index_into_coordinate_vector) override {
        return FLAGS_learning_rate * (-h[coordinate][index_into_coordinate_vector] +
                                      prev_gradients[datapoint_order][coordinate][index_into_coordinate_vector] -
                                      sum_gradients[coordinate][index_into_coordinate_vector] / datapoints.size());
    }

    void Update(Datapoint &datapoint) {
        Updater::Update(datapoint);

        // Update prev and sum gradients.
        int dp_order = datapoint.GetOrder() - 1;
        for (const auto &c : datapoint.GetCoordinates()) {
            for (int i = 0; i < model->NumCoordinates(); i++) {
                sum_gradients[c][i] += h[c][i] - prev_gradients[dp_order][c][i];
                prev_gradients[dp_order][c][i] = h[c][i];
            }
        }
    }

public:
    SAGAUpdater(Model *model, std::vector<Datapoint *> &datapoints) : Updater(model, datapoints) {
        h.resize(model->NumParameters());
        sum_gradients.resize(model->NumParameters());
        for (int i = 0; i < model->NumParameters(); i++) {
            h[i].resize(model->NumCoordinates());
            sum_gradients[i].resize(model->NumCoordinates());
        }
        datapoint_order = 0;

        // I hope this problem is sparse enough!
        prev_gradients.resize(datapoints.size());
        for (const auto &datapoint : datapoints)
            for (const auto &c : datapoint->GetCoordinates())
                prev_gradients[datapoint->GetOrder() - 1][c].resize(model->NumCoordinates());
    }

    ~SAGAUpdater() {}
};

#endif
