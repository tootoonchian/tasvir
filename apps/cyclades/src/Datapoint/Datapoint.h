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

#ifndef _DATAPOINT_
#define _DATAPOINT_

#include <string>
#include <vector>

class Datapoint {
private:
    int order;

public:
    Datapoint() {}
    Datapoint(const std::string &input_line, int order) { this->order = order; }
    virtual ~Datapoint() {}

    // Get labels corresponding to the corresponding coordinates of GetCoordinates().
    virtual const std::vector<double> &GetWeights() const = 0;

    // Get coordinates corresponding to labels of GetWeights().
    virtual const std::vector<int> &GetCoordinates() const = 0;

    // Get number of coordinates accessed by the datapoint.
    virtual int GetNumCoordinateTouches() const = 0;

    // Set order of the datapoint.
    virtual void SetOrder(int order) { this->order = order; }

    // Get the order of a datapoint (equivalent to id).
    virtual int GetOrder() const { return order; }
};

#endif
