#include <stdio.h>

extern char*glblvar;
extern char*glblfnc(void);
void tester(char *s)
{
	printf("lib:%s:%s:%s\n", s, glblfnc(), glblvar);
}
