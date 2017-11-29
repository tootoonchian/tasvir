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

#ifndef _WORDEMBEDDINGSUPDATER_
#define _WORDEMBEDDINGSUPDATER_

#include "Updater/SparseSGDUpdater.h"

// Fast matrix completion SGD updater.
class WordEmbeddingsSGDUpdater : public SparseSGDUpdater {
protected:
    double c_sum_mult1, c_sum_mult2;

    void PrepareWordEmbeddingsGradient(const Datapoint &datapoint) {
        if (gradient.coeffs.size() != 1)
            gradient.coeffs.resize(1);
        const auto &labels = datapoint.GetWeights();
        const auto &c = datapoint.GetCoordinates();
        double weight = labels[0];
        double norm = 0;
        for (int i = 0; i < model->NumCoordinates(); i++) {
            norm += (model->Data2D(c[0], i, false) + model->Data2D(c[1], i, false)) *
                    (model->Data2D(c[0], i, false) + model->Data2D(c[1], i, false));
        }
        gradient.coeffs[0] = 2 * weight * (log(weight) - norm - model->Data1D(0, true, 1));

        // Do some extra computation for optimization of C.
        c_sum_mult1 += weight * (log(weight) - norm);
        c_sum_mult2 += weight;
    }

    void ApplyWordEmbeddingsGradient(const Datapoint &datapoint) {
        const auto &c = datapoint.GetCoordinates();
        const auto &n_coords = model->NumCoordinates();
        tasvir_log_write(&model->Data2D(c[0], 0, false), sizeof(double) * n_coords);
        tasvir_log_write(&model->Data2D(c[1], 0, false), sizeof(double) * n_coords);
        for (int i = 0; i < model->NumCoordinates(); i++) {
            double final_grad =
                -(2 * gradient.coeffs[0] * (model->Data2D(c[0], i, false) + model->Data2D(c[1], i, false)));
            model->Data2D(c[0], i, false) -= FLAGS_learning_rate * final_grad;
            model->Data2D(c[1], i, false) -= FLAGS_learning_rate * final_grad;
        }
    }

    // Note that the Update method is called by many threads.
    // So we have thread local gradients to avoid conflicts.
    void Update(const Datapoint &datapoint) override {
        gradient.Clear();
        gradient.datapoint = &datapoint;

        // Prepare and apply gradient.
        PrepareWordEmbeddingsGradient(datapoint);
        ApplyWordEmbeddingsGradient(datapoint);

        // Update bookkeeping.
        for (const auto &c : datapoint.GetCoordinates()) {
            bookkeeping[c] = datapoint.GetOrder();
        }
    }

public:
    WordEmbeddingsSGDUpdater(Model *model, std::vector<Datapoint *> &datapoints) : SparseSGDUpdater(model, datapoints) {
        c_sum_mult1 = c_sum_mult2 = 0;
    }

    ~WordEmbeddingsSGDUpdater() {}

    // Called when the epoch ends.
    virtual void EpochFinish() override {
        SparseSGDUpdater::EpochFinish();

        // Update C based on closed form solution.
        double C_A = 0, C_B = 0;
        /*
        for (int thread = 0; thread < FLAGS_n_threads; thread++) {
            C_A += c_sum_mult1;
            C_B += c_sum_mult2[thread];
            c_sum_mult1[thread] = 0;
            c_sum_mult2[thread] = 0;
        }
        model->ExtraData()[0] = C_A / C_B;
        */
    }
};

#endif
