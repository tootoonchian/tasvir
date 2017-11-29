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

#ifndef _GRADIENT_
#define _GRADIENT_

#include <algorithm>
#include <iostream>
#include <tuple>
#include <vector>

class Model;
class Datapoint;

class Gradient {
public:
    std::vector<double> coeffs;
    const Datapoint *datapoint;

    Gradient() {}
    virtual ~Gradient() {}

    virtual void Clear() { datapoint = NULL; }
};

#endif
