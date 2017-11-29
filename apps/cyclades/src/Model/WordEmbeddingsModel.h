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

#ifndef _WORDEMBEDDINGSMODEL_
#define _WORDEMBEDDINGSMODEL_

#include "Model/Model.h"

DEFINE_int32(vec_length, 30, "Length of word embeddings vector in w2v.");

class WordEmbeddingsModel : public Model {
private:
    double C[1];  // FIXME
    int n_words;
    int w2v_length;

    void InitializePrivateModel() {
        for (int i = 0; i < n_words; i++) {
            for (int j = 0; j < w2v_length; j++) {
                Data2D(i, j, true) = ((double)rand() / (double)RAND_MAX);
            }
        }
    }

    void Initialize(const std::string &input_line) {
        // Expected input_line format: n_words.
        std::stringstream input(input_line);
        input >> n_words;
        w2v_length = FLAGS_vec_length;

        _n_data = 1;
        _n_coords = w2v_length;
        _n_params = n_words;

        // Allocate memory.
        _data[0] = tasvir::TasvirArray<double>::Allocate("model0", FLAGS_wid, FLAGS_n_threads, n_words * w2v_length);

        // Initialize C = 0.
        _data[1] = tasvir::TasvirArray<double>::Allocate("model1", FLAGS_wid, FLAGS_n_threads, 1);
        Data1D(0, true) = 0;

        // Initialize private model.
        if (FLAGS_wid == 0)
            InitializePrivateModel();
    }

public:
    WordEmbeddingsModel(const std::string &input_line) { Initialize(input_line); }

    ~WordEmbeddingsModel() {}

    double ComputeLoss(const std::vector<Datapoint *> &datapoints) override {
        double loss = 0;
        //#pragma omp parallel for num_threads(FLAGS_n_threads) reduction(+ : loss)
        for (const auto &datapoint : datapoints) {
            const auto &labels = datapoint->GetWeights();
            const auto &c = datapoint->GetCoordinates();
            const auto &weight = labels[0];
            double cross_product = 0;
            for (int j = 0; j < w2v_length; j++) {
                cross_product += (Data2D(c[0], j, true) + Data2D(c[1], j, true)) * (2 * Data2D(c[1], j, true));
            }
            loss += weight * (log(weight) - cross_product - C[0]) * (log(weight) - cross_product - C[0]);
        }
        return loss / datapoints.size();
    }

    void PrecomputeCoefficients(const Datapoint &datapoint, Gradient &g, Model &local_model) override {
        if (g.coeffs.size() != 1)
            g.coeffs.resize(1);
        const auto &labels = datapoint.GetWeights();
        const auto &c = datapoint.GetCoordinates();
        const auto &weight = labels[0];
        double norm = 0;
        for (int i = 0; i < w2v_length; i++) {
            norm += (local_model.Data2D(c[0], i, false) + local_model.Data2D(c[1], i, false)) *
                    (local_model.Data2D(c[0], i, false) + local_model.Data2D(c[1], i, false));
        }
        g.coeffs[0] = 2 * weight * (log(weight) - norm - C[0]);
    }

    virtual void H_bar(int coordinate, std::vector<double> &out, Gradient &g, Model &local_model) override {
        const auto &c = g.datapoint->GetCoordinates();
        for (int i = 0; i < w2v_length; i++) {
            out[i] = -(2 * g.coeffs[0] * (local_model.Data2D(c[0], i, false) + local_model.Data2D(c[1], i, false)));
        }
    }
};

#endif
