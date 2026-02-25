/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// From https://svn.boost.org/trac10/ticket/12818
// This fuzz target can likely be enhanced to exercise more code.
// The ideal place for this fuzz target is the boost repository.
#ifdef DEBUG
#include <iostream>
#endif

#include <fuzzer/FuzzedDataProvider.h>

#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/system/errc.hpp>
#include <cstdint>
#include <string>
#include <sstream>
#include <utility> // std::swap

using namespace boost::system;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    // Seed ints from input
    int val1 = static_cast<int>(data[0]);
    int val2 = static_cast<int>(data[1]);
    int val3 = static_cast<int>(data[2]);
    int val4 = static_cast<int>(data[3]);

    // --- error_code constructions ---
    error_code ec1(val1, generic_category());
    error_code ec2(val2, system_category());
    error_code ec3(val3, generic_category());
    error_code ec4(val4, system_category());
    error_code ec_default; // default ctor

    // --- error_condition constructions ---
    error_condition cond1(val1, generic_category());
    error_condition cond2(val2, system_category());

    // --- make_error_code / make_error_condition ---
    auto e1 = static_cast<errc::errc_t>(val3 % 133);
    auto e2 = static_cast<errc::errc_t>(val4 % 133);
    error_code mec1 = make_error_code(e1);
    error_code mec2 = make_error_code(e2);
    error_condition mcond1 = make_error_condition(e1);
    error_condition mcond2 = make_error_condition(e2);

    // --- equality / inequality ---
    (void)(ec1 == ec2);
    (void)(ec1 != ec2);
    (void)(ec1 == cond1);
    (void)(cond1 == ec1);  // reverse overload
    (void)(cond2 != ec2);

    (void)(mec1 == mec2);
    (void)(mec1 != mec2);
    (void)(mec1 == mcond1);
    (void)(mcond2 != mec2);

    // --- swap / copy / assign / clear ---
    error_code tmp = ec1;
    ec1 = ec2;
    ec2 = tmp;
    std::swap(ec1, ec3);

    ec1.assign(val1, generic_category());
    ec1.assign(val2, system_category());
    ec1.clear();

    // --- default_error_condition ---
    error_condition defc1 = ec1.default_error_condition();
    (void)(defc1 == ec1);
    std::string def_msg = defc1.message();

    // --- categories ---
    (void)generic_category().name();
    (void)system_category().name();

    // --- value() / category() on everything ---
    (void)ec1.value();
    (void)ec1.category().name();
    (void)cond1.value();
    (void)cond1.category().name();
    (void)mec1.value();
    (void)mec1.category().name();

    // --- message() calls ---
    std::string s1 = ec1.message();
    std::string s2 = ec2.message();
    std::string s3 = cond1.message();
    std::string s4 = cond2.message();
    std::string s5 = mec1.message();
    std::string s6 = mcond1.message();

    // --- operator bool ---
    if (ec1) { (void)ec1.message(); }

    // --- stream output ---
    std::ostringstream oss;
    oss << ec1 << " " << cond1 << " " << mec1 << " " << mcond1;
    std::string out_str = oss.str();

    // --- system_error exceptions ---
    try { throw system_error(mec1); }
    catch (const system_error& ex) { (void)ex.code(); (void)ex.what(); }

    try { throw system_error(ec2, std::string("context")); }
    catch (const system_error& ex) { (void)ex.code(); (void)ex.what(); }

    try { throw system_error(ec3, "c-string context"); }
    catch (const system_error& ex) { (void)ex.code(); (void)ex.what(); }

    try { throw system_error(mec2, "extra context"); }
    catch (const system_error& ex) { (void)ex.code(); (void)ex.what(); }

    return 0;
}

