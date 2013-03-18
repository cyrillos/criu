define PRLIMIT_TEST
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
int main(void)
{
	return prlimit(0, 0, NULL, NULL);
}
endef
