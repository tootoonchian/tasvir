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
#ifndef _MODEL_
#define _MODEL_

#include <sys/mman.h>
#include <set>
#include <sstream>
#include <vector>

#include <tasvir/array.hpp>

#include "DatapointPartitions/DatapointPartitions.h"
#include "Gradient/Gradient.h"
#include "defines.h"

class Model {
   protected:
    tasvir::Array<double> *_loss;
    tasvir::Array<double> *_data;
    std::vector<std::vector<std::vector<std::vector<int>>>> _cmap;  // [batch][worker]
    int _n_params;
    int _n_coords;

   public:
    Model() : _n_params(0), _n_coords(0) {}

    Model(const std::string &input_line) : Model() {}
    virtual ~Model() {}

    // Computes loss on the model
    virtual double ComputeLoss(const std::vector<Datapoint *> &datapoints) = 0;

    // Do some set up with the model and datapoints before running gradient descent.
    virtual void SetUp(const std::vector<Datapoint *> &datapoints) {}

    // Do some set up with the model given partitioning scheme before running the trainer.
    virtual void SetUpWithPartitions(const DatapointPartitions &partitions) {
        int n_threads = partitions.NumThreads();
        int n_batches = partitions.NumBatches();
        int n_coords = NumCoordinates();
        _cmap.resize(n_batches);
        for (int b = 0; b < n_batches; b++) {
            _cmap[b].resize(n_threads);
            for (int t = 0; t < n_threads; t++) {
                std::set<int> s;
                for (const auto &datapoint : partitions.GetDatapoints(t, b))
                    s.insert(datapoint->GetCoordinates().begin(), datapoint->GetCoordinates().end());
                for (const auto &c : s) {
                    if (_cmap[b][t].size() > 0 && _cmap[b][t].back()[1] == c * n_coords)
                        _cmap[b][t].back()[1] = (c + 1) * n_coords;
                    else
                        _cmap[b][t].push_back({c * n_coords, (c + 1) * n_coords});
                }
            }
        }
    }

    // Return the number of parameters of the model.
    inline int NumParameters() { return _n_params; }

    // Return the size (the # of doubles) of a single coordinate.
    inline int NumCoordinates() { return _n_coords; };

    // The following are for updates of the form:
    // [∇f(x)] = λx − κ + h(x)
    // See https://arxiv.org/pdf/1605.09721v1.pdf page 20 for more details.
    virtual void PrecomputeCoefficients(const Datapoint &datapoint, Gradient &g, Model &local_model) {}
    virtual void Lambda(int coordinate, double &out, Model &local_model) {}
    virtual void Kappa(int coordinate, std::vector<double> &out, Model &local_model) {}
    virtual void H_bar(int coordinate, std::vector<double> &out, Gradient &g, Model &local_model) {}

    virtual void EpochBegin() {}

    virtual void EpochFinish() {}

    void BatchBegin(int batch) {
        _data->Barrier();
        _data->CopySelect(_cmap[batch][FLAGS_wid]);
    }

    void BatchFinish(int batch) { _data->ReduceSelect(_cmap[batch][FLAGS_wid]); }

    inline double &Data(int offset, bool global) {
        return global ? _data->DataParent()[offset] : _data->DataWorker()[offset];
    }

    inline double &Data(int parameter, int coordinate, bool global) {
        return Data(parameter * NumCoordinates() + coordinate, global);
    }
};

#endif
