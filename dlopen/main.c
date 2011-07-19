#include <stdio.h>


#include <stdlib.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <dlfcn.h>

char *glblvar = "glblvar(main)";
char *glblfnc(void) { return "glbfcf(main)"; }

int
main(int argc, char **argv)
{
   void *handle;
   void (*fnc)(char*);
   char *error;

   handle = dlopen("libtest.so.1.0", RTLD_NOW);
   if (!handle) {
       fprintf(stderr, "%s\n", dlerror());
       exit(EXIT_FAILURE);
   }

   dlerror();    /* Clear any existing error */

   *(void **) (&fnc) = dlsym(handle, "tester");

   if ((error = dlerror()) != NULL)  {
       fprintf(stderr, "%s\n", error);
       exit(EXIT_FAILURE);
   }

   (*fnc)("param");
   dlclose(handle);
   exit(EXIT_SUCCESS);
}

