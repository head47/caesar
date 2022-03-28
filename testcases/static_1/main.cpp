#include <iostream>
using namespace std;

void print_wow() {
  cout << "wow ";
}

void print_so() {
  print_wow();
  cout << "so ";
}

void print_cool() {
  print_so();
  cout << "cool";
}

int main() {
  print_wow();
  print_so();
  print_cool();
}
