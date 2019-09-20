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

#ifndef _LSMODEL_
#define _LSMODEL_

#include "Model/Model.h"

class LSModel : public Model {
private:
    int n_coords;
    std::vector<double> B;

    void MatrixVectorMultiply(const std::vector<Datapoint *> &datapoints, std::vector<double> &input_vector,
                              std::vector<double> &output_vector) {
        // Write to temporary vector to allow for input_vector
        // and output_vector referencing the same vector.
        std::vector<double> temp_vector;

        for (const auto &datapoint : datapoints) {
            double cross_product = 0;

            // Each datapoint is like a sparse row in the sparse matrix.
            for (int i = 0; i < datapoint->GetWeights().size(); i++) {
                int index = datapoint->GetCoordinates()[i];
                double weight = datapoint->GetWeights()[i];
                cross_product += input_vector[index] * weight;
            }
            temp_vector.push_back(cross_product);
        }

        // Copy over.
        std::copy(temp_vector.begin(), temp_vector.end(), output_vector.begin());
    }

    void Initialize(const std::string &input_line) {
        // Expect a single number with n_coords.
        std::stringstream input(input_line);
        input >> n_coords;

        _n_coords = 1;
        _n_params = n_coords;

        // Allocate memory.
        _loss = tasvir::Array<double>::Allocate("loss", FLAGS_wid, FLAGS_n_threads, 1);
        _data =
            tasvir::Array<double>::Allocate("model", FLAGS_wid, FLAGS_n_threads, NumParameters() * NumCoordinates());
    }

public:
    LSModel(const std::string &input_line) { Initialize(input_line); }

    void SetUp(const std::vector<Datapoint *> &datapoints) override {
        B.resize(datapoints.size());

        // Initialize B by multiplying the input matrix with a random vector.
        std::vector<double> rand_vect(n_coords);
        for (int i = 0; i < n_coords; i++) {
            rand_vect[i] = (rand() % FLAGS_random_range);
        }

        MatrixVectorMultiply(datapoints, rand_vect, B);

        // Add some noise to B.
        /*
        for (int i = 0; i < datapoints.size(); i++)
            B[i] += rand() % FLAGS_random_range;
        */
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
            const auto &w = datapoints[i]->GetWeights();
            double cross_product = 0;
            int row = ((LSDatapoint *)datapoints[i])->row;
            for (int j = 0; j < c.size(); j++)
                cross_product += w[j] * Data(c[j], true);
            _loss->DataWorker()[0] += pow((cross_product - B[row]), 2);
        }

        _loss->Barrier();
        _loss->ReduceAdd();
        _loss->Barrier();

        return _loss->DataParent()[0] / nr_datapoints;
    }

    void PrecomputeCoefficients(const Datapoint &datapoint, Gradient &g, Model &local_model) override {
        if (g.coeffs.size() != n_coords)
            g.coeffs.resize(n_coords);
        int row = ((const LSDatapoint &)datapoint).row;
        double cp = 0;
        for (int i = 0; i < datapoint.GetCoordinates().size(); i++) {
            int index = datapoint.GetCoordinates()[i];
            double weight = datapoint.GetWeights()[i];
            cp += weight * local_model.Data(index, false);
        }
        double partial_grad = 2 * (cp - B[row]);
        for (int i = 0; i < datapoint.GetCoordinates().size(); i++) {
            int index = datapoint.GetCoordinates()[i];
            double weight = datapoint.GetWeights()[i];
            g.coeffs[index] = partial_grad * weight;
        }
    }

    void Lambda(int coordinate, double &out, Model &local_model) override { out = 0; }

    void Kappa(int coordinate, std::vector<double> &out, Model &local_model) override { out[0] = 0; }

    void H_bar(int coordinate, std::vector<double> &out, Gradient &g, Model &local_model) override {
        out[0] = g.coeffs[coordinate];
    }

    ~LSModel() {}
};

#endif
