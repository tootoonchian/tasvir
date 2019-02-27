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

#ifndef _FASTMCUPDATER_
#define _FASTMCUPDATER_

#include "Updater/SparseSGDUpdater.h"

// Fast matrix completion SGD updater.
class FastMCSGDUpdater : public SparseSGDUpdater {
protected:
    void PrepareMCGradient(const Datapoint &datapoint) {
        if (gradient.coeffs.size() != 1)
            gradient.coeffs.resize(1);
        const auto &labels = datapoint.GetWeights();
        const auto &c = datapoint.GetCoordinates();
        const auto &user_coordinate = c[0];
        const auto &movie_coordinate = c[1];
        double coeff = 0;
        for (int i = 0; i < model->NumCoordinates(); i++) {
            coeff += model->Data(user_coordinate, i, false) * model->Data(movie_coordinate, i, false);
        }
        coeff -= labels[0];
        gradient.coeffs[0] = coeff;
    }

    void ApplyMCGradient(const Datapoint &datapoint) {
        // Custom SGD. This is fast because it avoids intermediate writes to memory,
        // and simply updates the model directly and simultaneously.
        const auto &g_coeff = gradient.coeffs[0];
        const auto &c = datapoint.GetCoordinates();
        const auto &user_coordinate = c[0];
        const auto &movie_coordinate = c[1];
        const auto &n_coords = model->NumCoordinates();

        tasvir_log(&model->Data(user_coordinate, 0, false), sizeof(double) * n_coords);
        tasvir_log(&model->Data(movie_coordinate, 0, false), sizeof(double) * n_coords);
        for (int i = 0; i < n_coords; i++) {
            double new_user_value = model->Data(user_coordinate, i, false) -
                                    FLAGS_learning_rate * g_coeff * model->Data(movie_coordinate, i, false);
            double new_movie_value = model->Data(movie_coordinate, i, false) -
                                     FLAGS_learning_rate * g_coeff * model->Data(user_coordinate, i, false);
            model->Data(user_coordinate, i, false) = new_user_value;
            model->Data(movie_coordinate, i, false) = new_movie_value;
        }
    }

    // Note that the Update method is called by many threads.
    // So we have thread local gradients to avoid conflicts.
    void Update(const Datapoint &datapoint) override {
        gradient.Clear();
        gradient.datapoint = &datapoint;

        // Prepare and apply gradient.
        PrepareMCGradient(datapoint);
        ApplyMCGradient(datapoint);

        // Update bookkeeping.
        for (const auto &c : datapoint.GetCoordinates()) {
            bookkeeping[c] = datapoint.GetOrder();
        }
    }

public:
    FastMCSGDUpdater(Model *model, std::vector<Datapoint *> &datapoints) : SparseSGDUpdater(model, datapoints) {}

    ~FastMCSGDUpdater() {}
};

#endif
