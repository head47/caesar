gcc -c lib1.c
ar rvs lib1.a lib1.o
gcc -o test.exe main.c lib1.a
