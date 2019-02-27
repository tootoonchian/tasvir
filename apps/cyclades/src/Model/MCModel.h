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

#ifndef _MCMODEL_
#define _MCMODEL_

#include <algorithm>
#include "Model/Model.h"

DEFINE_int32(rlength, 100, "Length of vector in matrix completion.");

class MCModel : public Model {
private:
    int n_users;
    int n_movies;
    int rlength;

    void InitializePrivateModel() {
        tasvir_log(&Data(0, true), sizeof(double) * NumParameters() * NumCoordinates());
        for (int i = 0; i < NumParameters(); i++) {
            for (int j = 0; j < NumCoordinates(); j++) {
                Data(i, j, true) = (double)rand() / (double)RAND_MAX;
            }
        }
    }

    void Initialize(const std::string &input_line) {
        // Expected input_line format: N_USERS N_MOVIES.
        std::stringstream input(input_line);
        input >> n_users >> n_movies;
        rlength = FLAGS_rlength;

        _n_coords = rlength;
        _n_params = n_users + n_movies;

        // Allocate memory.
        _data =
            tasvir::Array<double>::Allocate("model", FLAGS_wid, FLAGS_n_threads, NumParameters() * NumCoordinates());
        _loss = tasvir::Array<double>::Allocate("loss", FLAGS_wid, FLAGS_n_threads, 1);

        // Initialize private model.
        if (FLAGS_wid == 0)
            InitializePrivateModel();
    }

public:
    MCModel(const std::string &input_line) { Initialize(input_line); }

    ~MCModel() {}

    void SetUp(const std::vector<Datapoint *> &datapoints) override {
        // Update the movies coordinates to reference the second
        // chunk of the model. Do this by offsetting the coordinates
        // by n_users.
        for (const auto &datapoint : datapoints) {
            ((MCDatapoint *)datapoint)->OffsetMovieCoord(n_users);
        }
    }

    double ComputeLoss(const std::vector<Datapoint *> &datapoints) override {
        _loss->Barrier();
        size_t nr_datapoints = datapoints.size();
        size_t batch_size = nr_datapoints / FLAGS_n_threads + (nr_datapoints % FLAGS_n_threads > 0);
        size_t index_lo = FLAGS_wid * batch_size;
        size_t index_hi = std::min(nr_datapoints, index_lo + batch_size);

        tasvir_log(&_loss->DataWorker()[0], sizeof(double));
        _loss->DataWorker()[0] = 0;
        for (size_t i = index_lo; i < index_hi; i++) {
            const auto &c = datapoints[i]->GetCoordinates();
            double cross_product = -datapoints[i]->GetWeights()[0];
            for (size_t j = 0; j < NumCoordinates(); j++)
                cross_product += Data(c[0], j, true) * Data(c[1], j, true);
            _loss->DataWorker()[0] += cross_product * cross_product;
        }

        _loss->Barrier();
        _loss->ReduceAdd();
        _loss->Barrier();

        return _loss->DataMaster()[0] / nr_datapoints;
    }

    void PrecomputeCoefficients(const Datapoint &datapoint, Gradient &g, Model &local_model) override {
        if (g.coeffs.size() != 1)
            g.coeffs.resize(1);
        const auto &c = datapoint.GetCoordinates();
        g.coeffs[0] = -datapoint.GetWeights()[0];
        for (int i = 0; i < NumCoordinates(); i++)
            g.coeffs[0] += local_model.Data(c[0], i, false) * local_model.Data(c[1], i, false);
    }

    void H_bar(int coordinate, std::vector<double> &out, Gradient &g, Model &local_model) override {
        const auto &c = g.datapoint->GetCoordinates();
        const auto &other_coordinate = c[0] == coordinate ? c[1] : c[0];
        for (int i = 0; i < NumCoordinates(); i++)
            out[i] = g.coeffs[0] * local_model.Data(other_coordinate, i, false);
    }
};

#endif
