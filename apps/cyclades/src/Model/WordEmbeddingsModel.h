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
    double _C;
    int n_words;
    int w2v_length;
    tasvir::Array<double> *_c_sum_mult;

    void InitializePrivateModel() {
        for (int i = 0; i < n_words; i++) {
            for (int j = 0; j < w2v_length; j++) {
                Data(i, j, true) = ((double)rand() / (double)RAND_MAX);
            }
        }
    }

    void Initialize(const std::string &input_line) {
        // Expected input_line format: n_words.
        std::stringstream input(input_line);
        input >> n_words;
        w2v_length = FLAGS_vec_length;

        _n_coords = w2v_length;
        _n_params = n_words;

        // Allocate memory.
        _data = tasvir::Array<double>::Allocate("model", FLAGS_wid, FLAGS_n_threads, n_words * w2v_length);
        _loss = tasvir::Array<double>::Allocate("loss", FLAGS_wid, FLAGS_n_threads, 1);
        _c_sum_mult = tasvir::Array<double>::Allocate("csum", FLAGS_wid, FLAGS_n_threads, 2);

        // Initialize _C = 0.
        _C = 0;

        // Initialize private model.
        if (FLAGS_wid == 0)
            InitializePrivateModel();
    }

public:
    WordEmbeddingsModel(const std::string &input_line) { Initialize(input_line); }

    ~WordEmbeddingsModel() {}

    double ComputeLoss(const std::vector<Datapoint *> &datapoints) override {
        _loss->Barrier();
        size_t nr_datapoints = datapoints.size();
        size_t batch_size = nr_datapoints / FLAGS_n_threads + (nr_datapoints % FLAGS_n_threads > 0);
        size_t index_lo = FLAGS_wid * batch_size;
        size_t index_hi = std::min(nr_datapoints, index_lo + batch_size);

        tasvir_log(&_loss->DataWorker()[0], sizeof(double));
        _loss->DataWorker()[0] = 0;
        for (size_t i = index_lo; i < index_hi; i++) {
            const auto &labels = datapoints[i]->GetWeights();
            const auto &c = datapoints[i]->GetCoordinates();
            const auto &weight = labels[0];
            double cross_product = 0;
            for (size_t j = 0; j < NumCoordinates(); j++)
                cross_product += (Data(c[0], j, true) + Data(c[1], j, true)) * (2 * Data(c[1], j, true));
            _loss->DataWorker()[0] += weight * (log(weight) - cross_product - _C) * (log(weight) - cross_product - _C);
        }

        _loss->Barrier();
        _loss->ReduceAdd();
        _loss->Barrier();

        return _loss->DataParent()[0] / nr_datapoints;
    }

    void PrecomputeCoefficients(const Datapoint &datapoint, Gradient &g, Model &local_model) override {
        if (g.coeffs.size() != 1)
            g.coeffs.resize(1);
        const auto &labels = datapoint.GetWeights();
        const auto &c = datapoint.GetCoordinates();
        const auto &weight = labels[0];
        double norm = 0;
        for (int i = 0; i < NumCoordinates(); i++) {
            norm += (local_model.Data(c[0], i, false) + local_model.Data(c[1], i, false)) *
                    (local_model.Data(c[0], i, false) + local_model.Data(c[1], i, false));
        }
        g.coeffs[0] = 2 * weight * (log(weight) - norm - _C);
    }

    virtual void H_bar(int coordinate, std::vector<double> &out, Gradient &g, Model &local_model) override {
        const auto &c = g.datapoint->GetCoordinates();
        for (int i = 0; i < NumCoordinates(); i++) {
            out[i] = -(2 * g.coeffs[0] * (local_model.Data(c[0], i, false) + local_model.Data(c[1], i, false)));
        }
    }

    const double &C() { return _C; }

    inline double &CSumMulti(int offset, bool global) {
        return global ? _c_sum_mult->DataParent()[offset] : _c_sum_mult->DataWorker()[offset];
    }

    virtual void EpochFinish() override {
        Model::EpochFinish();
        _c_sum_mult->Barrier();
        _c_sum_mult->ReduceAdd();
        _c_sum_mult->Barrier();
        _C = CSumMulti(0, true) / CSumMulti(1, true);

        CSumMulti(0, false) = 0;
        CSumMulti(1, false) = 0;
    }
};

#endif
