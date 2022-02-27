#include <stdio.h>

int func1(int a, int b)
{
  int c;
  if (a > b) c = a + b;
  else       c = a - b;
  return c;
}

void onlyprint(int a, int b)
{
  printf("%d %d\n", a, b);
}

void infloop(int a, int b)
{
  int c = 0;
  for(int i=0; i<10; i++) {
    c += a * 3 / b;
  }
  while(1) {
  }
};

int main()
{
  int a = 3;
  int b = 5;
  int c = func1(a, b);
  printf("c = %d\n", c);
  return 0;
}

