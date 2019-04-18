#include "daemon.h"

int		main(int argc, char **argv)
{
	if (argc >= 1 && argc <= 2)
	{
		strcpy(config, find_device(argv[1])); 
		fork_process();
	}
	else
		printf("Error arguments\n");
}
