struct Complex {
  double r;
  double i;
};

double get_r(struct Complex* n) {
  return n->r;
}

double get_i(struct Complex* n) {
  return n->i;
}

void set_r(struct Complex* n, double r) {
  n->r = r;
}

void set_i(struct Complex* n, double i) {
  n->i = i;
}

void add_c(struct Complex* a, struct Complex* b, struct Complex* res) {
  double a_r = get_r(a);
  double b_r = get_r(b);
  double a_i = get_i(a);
  double b_i = get_i(b);
  set_r(res,a_r+b_r);
  set_i(res,a_i+b_i);
}

void sub_c(struct Complex* a, struct Complex* b, struct Complex* res) {
  double a_r = get_r(a);
  double b_r = get_r(b);
  double a_i = get_i(a);
  double b_i = get_i(b);
  set_r(res,a_r-b_r);
  set_i(res,a_i-b_i);
}
