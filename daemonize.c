#include "daemon.h"

static void	close_allfd(void)
{
	int 			i;
	int 			fd0, fd1, fd2;
	struct rlimit	limit;

	if (getrlimit(RLIMIT_NOFILE, &limit) < 0)
		exit(EXIT_FAILURE);
	i = -1;
	if (limit.rlim_max == RLIM_INFINITY)
		limit.rlim_max = 1024;
	while (++i < limit.rlim_max)
		close(i);
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);
	if (fd0 != 0 || fd1 != 1 || fd2 != 2)
	{
		syslog(LOG_ERR, "Error file descriptor %d %d %d", fd0, fd1, fd2);
		exit(EXIT_FAILURE);
	}
}

static void	handler_sig(void)
{
	struct sigaction	sig;

	sig.sa_handler = SIG_IGN;
	sigemptyset(&sig.sa_mask);
	if (sigaction(SIGHUP, &sig, NULL) < 0)
		exit(EXIT_FAILURE);
	if (sigaction(SIGPIPE, &sig, NULL) < 0)
		exit(EXIT_FAILURE);
	if (sigaction(SIGALRM, &sig, NULL) < 0)
		exit(EXIT_FAILURE);
	if (sigaction(SIGTSTP, &sig, NULL) < 0)
		exit(EXIT_FAILURE);
	if (sigaction(SIGPROF, &sig, NULL) < 0)
		exit(EXIT_FAILURE);
	if (sigaction(SIGCHLD, &sig, NULL) < 0)
		exit(EXIT_FAILURE);
}

int		lockfile(int fd)
{
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	return(fcntl(fd, F_SETLK, &fl));
}

int		ft_already_running(void)
{
	int fd;

	fd = open(LOCKFILE, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0)
	{
		syslog(LOG_ERR, "Error opening %s: %s", LOCKFILE, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (lockfile(fd) < 0)
	{
		if (errno == EACCES || errno == EAGAIN)
		{
			close(fd);
			return (1);
		}
		syslog(LOG_ERR, "Error lockfile %s: %s", LOCKFILE, strerror(errno));
		exit(EXIT_FAILURE);
	}
	ftruncate(fd, 0);
	ft_putnbr_fd((int)getpid(), fd);
	return(0);
}

void		daemonize(void)
{
	pid_t				pid;

	/* clear the file creation mode mask */
	umask(0);
	/* lose control terminal */
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);
	else if (pid != 0)
		exit(EXIT_SUCCESS);
	/* impossibility to get control terminal */
	setsid();
	/* setting ignoring of signals */
	handler_sig();
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);
	else if (pid != 0)
		exit(EXIT_SUCCESS);
	/* assign the root directory to the current working directory */
	if (chdir("/") < 0)
		exit(EXIT_FAILURE);
	/* initialize the log file */
	openlog(LOG_PREFIX, LOG_PID | LOG_CONS | LOG_NDELAY | LOG_NOWAIT, LOG_LOCAL0);
	(void)setlogmask(LOG_UPTO(LOG_DEBUG));
	/* close all file descriptors */
	close_allfd();
}
