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

#ifndef _SVRG_UPDATER_
#define _SVRG_UPDATER_

#include "Updater/Updater.h"

class SVRGUpdater : public Updater {
protected:
    double n_updates_so_far;

    // Vectors for computing SVRG related data.
    std::vector<double> lambda;
    std::vector<std::vector<double>> h_x, h_y;
    std::vector<double> g;  // global

    // Vectors for computing the sum of gradients (g).
    std::vector<std::vector<double>> g_kappa, g_h_bar;
    std::vector<double> g_lambda;
    std::vector<double> n_zeroes;

    void PrepareMu(const std::vector<int> &coordinates) override {
        for (int i = 0; i < coordinates.size(); i++) {
            int index = coordinates[i];
            model->Lambda(index, lambda[index], *model);
        }
    }

    void PrepareH(const Datapoint &datapoint) override {
        model->PrecomputeCoefficients(datapoint, gradient, *model);
        int n_coords = model->NumCoordinates();
        for (const auto &c : datapoint.GetCoordinates())
            model->H_bar(c, h_x[c], gradient, *model);
        model->PrecomputeCoefficients(datapoint, gradient, *model);
        for (const auto &c : datapoint.GetCoordinates())
            model->H_bar(c, h_y[c], gradient, *model);
    }

    double H(int coordinate, int index_into_coordinate_vector) override {
        return -FLAGS_learning_rate *
               (h_x[coordinate][index_into_coordinate_vector] - h_y[coordinate][index_into_coordinate_vector]);
    }

    double Nu(int coordinate, int index_into_coordinate_vector) override {
        return FLAGS_learning_rate *
               (g[coordinate * model->NumCoordinates() + index_into_coordinate_vector] -
                lambda[coordinate] * model->Data2D(coordinate, index_into_coordinate_vector, false));
    }

    double Mu(int coordinate) override { return lambda[coordinate] * FLAGS_learning_rate; }

public:
    SVRGUpdater(Model *model, std::vector<Datapoint *> &datapoints) : Updater(model, datapoints) {
        g.resize(model->NumParameters() * model->NumCoordinates());
        lambda.resize(model->NumParameters());
        h_x.resize(model->NumParameters());
        h_y.resize(model->NumParameters());
        g_lambda.resize(model->NumParameters());
        g_kappa.resize(model->NumParameters());
        g_h_bar.resize(model->NumParameters());
        n_zeroes.resize(model->NumParameters());
        for (int i = 0; i < model->NumParameters(); i++) {
            h_x[i].resize(model->NumCoordinates());
            h_y[i].resize(model->NumCoordinates());
            g_kappa[i].resize(model->NumCoordinates());
            g_h_bar[i].resize(model->NumCoordinates());
            n_zeroes[i] = datapoints.size();
        }

        // Compute number of zeroes for each column (parameters) of the model.
        int sum = 0;
        for (int dp = 0; dp < datapoints.size(); dp++) {
            for (auto &coordinate : datapoints[dp]->GetCoordinates()) {
                n_zeroes[coordinate]--;
                sum++;
            }
        }
    }

    void EpochBegin() override {
        Updater::EpochBegin();
        // TODO: Make a copy of the model every epoch.

        // Clear the sum of gradients.
        std::fill(g.begin(), g.end(), 0);

        // Compute average sum of gradients on the model copy.
        int n_coords = model->NumCoordinates();

        // zero gradients.
        //#pragma omp parallel for num_threads(FLAGS_n_threads)
        for (int coordinate = 0; coordinate < model->NumParameters(); coordinate++) {
            model->Kappa(coordinate, g_kappa[coordinate], *model);
            model->Lambda(coordinate, g_lambda[coordinate], *model);
            for (int j = 0; j < n_coords; j++) {
                g[coordinate * n_coords + j] =
                    (g_lambda[coordinate] * model->Data2D(coordinate, j, false) - g_kappa[coordinate][j]) *
                    n_zeroes[coordinate];
            }
        }

        // non zero gradients. Essentially do SGD here, on the same partitioning pattern.
        //#pragma omp parallel num_threads(FLAGS_n_threads)
        {
            for (int batch = 0; batch < datapoint_partitions->NumBatches(); batch++) {
                //#pragma omp barrier
                for (int index = 0; index < datapoint_partitions->NumDatapointsInBatch(FLAGS_wid, batch); index++) {
                    const auto &datapoint = datapoint_partitions->GetDatapoint(FLAGS_wid, batch, index);
                    gradient.datapoint = &datapoint;
                    model->PrecomputeCoefficients(datapoint, gradient, *model);
                    for (const auto &coord : datapoint.GetCoordinates()) {
                        model->H_bar(coord, g_h_bar[coord], gradient, *model);
                        model->Lambda(coord, g_lambda[coord], *model);
                        model->Kappa(coord, g_kappa[coord], *model);
                    }
                    for (const auto &coord : datapoint.GetCoordinates()) {
                        for (int j = 0; j < n_coords; j++) {
                            g[coord * n_coords + j] += g_lambda[coord] * model->Data2D(coord, j, false) -
                                                       g_kappa[coord][j] + g_h_bar[coord][j];
                        }
                    }
                }
            }
        }

        //#pragma omp parallel for num_threads(FLAGS_n_threads)
        for (int i = 0; i < model->NumParameters(); i++) {
            for (int j = 0; j < n_coords; j++) {
                g[i * n_coords + j] /= datapoints.size();
            }
        }
    }

    ~SVRGUpdater() {}
};

#endif
