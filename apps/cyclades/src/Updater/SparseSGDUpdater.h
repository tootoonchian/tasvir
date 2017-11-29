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

#ifndef _SPARSE_SGD_UPDATER_
#define _SPARSE_SGD_UPDATER_

#include "Updater/Updater.h"

class SparseSGDUpdater : public Updater {
protected:
    std::vector<std::vector<double>> h_bar;

    // Catch up is not required as mu and nu are 0.
    virtual bool NeedCatchUp() override { return false; }

    void PrepareH(const Datapoint &datapoint) override {
        model->PrecomputeCoefficients(datapoint, gradient, *model);
        for (const auto &c : datapoint.GetCoordinates()) {
            model->H_bar(c, h_bar[c], gradient, *model);
        }
    }

    double H(int coordinate, int index_into_coordinate_vector) override {
        return -h_bar[coordinate][index_into_coordinate_vector] * FLAGS_learning_rate;
    }

public:
    SparseSGDUpdater(Model *model, std::vector<Datapoint *> &datapoints) : Updater(model, datapoints) {
        h_bar.resize(model->NumParameters());
        for (int i = 0; i < model->NumParameters(); i++)
            h_bar[i].resize(model->NumCoordinates());
    }

    ~SparseSGDUpdater() {}
};

#endif
