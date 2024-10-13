/*
Copyright (c) NCC Group, 2018
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int g = 6;

struct Test2;

class Test {
 public:
  Test(int const& _i) : i(_i) { }
  void pi() { printf("[test::pi] %d\n", i); }

  int const& i = g;
  int a;
  long b;
  char c;
  Test2* t2 = nullptr;
  double d;
  Test* t = nullptr;
};

struct Test2 {
  int x;
  uint64_t z;
};







void bar2(Test& tt) {
  tt.pi();
  tt.b = 0x4141;
}

void bar() {
  int i = 5;
  Test t{i};
  t.t2 = new Test2();
  t.t2->x = 0x41424344;
  t.t2->z = 0xff00ff00ff00ff00;
  i++;
  t.pi();
  i = 0x4242;
  bar2(t);
  delete t.t2;
}

union u {
  int a;
  long b;
  char c;
  double d;
  void* v;
};


void foo(int i) {
  u a;
  a.a = 0;

  a.a += i;
  printf("[test::foo] i: %d\n", a.a);
}

int main(int argc, char** argv) {
  //printf("%zu\n", sizeof(long));
  if (argc != 2) {
    puts("[test::main] nope");
    return 1;
  }
  foo(atoi(argv[1]));
  bar();
  puts("[test::main] TERMINATE");
  return 0;
}
