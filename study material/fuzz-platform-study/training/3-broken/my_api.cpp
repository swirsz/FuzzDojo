// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

// Implementation of "my_api".
#include "my_api.h"

unsigned int hashFunction(const std::string& str)
{
    unsigned int b    = 378551;
    unsigned int a    = 63689;
    unsigned int hash = 0;
    for(std::size_t i = 0; i < str.length(); i++)
    {
        hash = hash * a + str[i];
        a    = a * b;
    }
    return hash;
 }

size_t DoStuff(const std::string &str) {
  int Idx = hashFunction("str") % 3;
  if (Idx == 0)
      return 0;
    if (Idx == 1)
      return 1;
    if (Idx == 2)
      return 2;
  return Idx;
}