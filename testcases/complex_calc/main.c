#include <stdio.h>
#include <lib1.h>

int main() {
  double r1, i1, r2, i2;
  char op;
  struct Complex c1, c2, c3;
  printf("calculator\n");
  printf("enter first number in format R I: ");
  scanf("%lf %lf",&r1,&i1);
  set_r(&c1, r1);
  set_i(&c1, i1);
  printf("enter second number in format R I: ");
  scanf("%lf %lf",&r2,&i2);
  set_r(&c2, r2);
  set_i(&c2, i2);
  printf("enter operation (+-): ");
  scanf(" %c",&op);
  if (op == '+') {
    add_c(&c1, &c2, &c3);
  }
  else if (op == '-') {
    sub_c(&c1, &c2, &c3);
  }
  printf("result: %lf %lf",get_r(&c3),get_i(&c3));
}
