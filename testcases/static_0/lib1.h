#ifndef LIB1_H
#define LIB1_H

struct Complex {
  double r;
  double i;
};

double get_r(struct Complex*);
double get_i(struct Complex*);
void set_r(struct Complex*, double);
void set_i(struct Complex*, double);
void add_c(struct Complex*, struct Complex*, struct Complex*);
void sub_c(struct Complex*, struct Complex*, struct Complex*);

#endif
