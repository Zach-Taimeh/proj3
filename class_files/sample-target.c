#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
#include "foo.h"


/*
 * sleepfunc()
 *
 * The only purpose of this function is to output the message "sleeping..."
 * once a second to provide a more concrete idea of when the sample library
 * gets injected.
 *
 */

void sleepfunc()
{
	struct timespec* sleeptime = malloc(sizeof(struct timespec));
	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0;
	int i;
	for(i=0;i<25;i++)
	{
		printf("address of nanosleep is: %p", &nanosleep);
		printf("sleeping...\n");
		nanosleep(sleeptime, NULL);
	}

	free(sleeptime);
}

int main()
{
	int a=foo(0);
    printf("Main function foo: %d\n",a);
	sleepfunc();
	//puts("breakpoint here");
	printf("Main function foo: \n");
	return 0;
}
