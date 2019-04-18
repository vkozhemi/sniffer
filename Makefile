NAME_SNIF = sniffer
NAME_CLI = cli

G = gcc
FLAG_SNIF = -pthread
FLAGS_CLI = -lpcap

SRC_SNIF =	main_sniffer.c connect_cli.c daemonize.c sniffer.c tree.c

OBJ_SNIF = $(SRC_SNIF:.c=.o)

SRC_CLI =	main_cli.c sniffer.c tree.c connect_cli.c daemonize.c

OBJ_CLI= $(SRC_CLI:.c=.o)

LIBFTPRINTF = libftprintf/libftprintf.a

all: $(NAME_SNIF) $(NAME_CLI)

$(NAME_SNIF): $(OBJ_SNIF)
	@make -C libftprintf/
	$(G)  -o $@ $(OBJ_SNIF) $(LIBFTPRINTF) $(FLAGS_CLI) $(FLAG_SNIF)

$(NAME_CLI): $(OBJ_CLI)
	$(G)  -o $@ $(OBJ_CLI) $(LIBFTPRINTF) $(FLAGS_CLI) $(FLAG_SNIF)

%.o: %.c
	$(G) -c $< -o $@

clean:
	@make -C libftprintf/ clean
	@rm -f $(OBJ_SNIF)
	@rm -f $(OBJ_CLI)

fclean: clean
	@make -C libftprintf/ fclean
	@rm -f $(NAME_SNIF)
	@rm -f $(NAME_SNIF) $(NAME_CLI)

re: fclean all
	@make -C libftprintf/ re
