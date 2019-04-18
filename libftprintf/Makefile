#******************************************************************************#
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/03/22 17:46:38 by vkozhemi          #+#    #+#              #
#    Updated: 2018/04/04 18:46:21 by vkozhemi         ###   ########.fr        #
#                                                                              #
#******************************************************************************#

NAME = libftprintf.a

SRC_DIR := ./sources/
OBJ_DIR := ./objects/
INC_DIR := ./includes/

FLAGS = -Wall -Wextra -Werror
CC := gcc

SRCS =   ft_atoi.c \
        ft_bzero.c \
        ft_isalnum.c \
        ft_isalpha.c \
        ft_isascii.c \
        ft_isdigit.c \
        ft_isprint.c \
        ft_itoa.c \
        ft_lstadd.c \
        ft_lstdel.c \
        ft_lstdelone.c \
        ft_lstiter.c \
        ft_lstmap.c \
        ft_lstnew.c \
        ft_memalloc.c \
        ft_memccpy.c \
        ft_memchr.c \
        ft_memcmp.c \
        ft_memcpy.c \
        ft_memdel.c \
        ft_memmove.c \
        ft_memset.c \
        ft_putchar.c \
        ft_putchar_fd.c \
        ft_putendl.c \
        ft_putendl_fd.c \
        ft_putnbr.c \
        ft_putnbr_fd.c \
        ft_putstr.c \
        ft_putstr_fd.c \
        ft_range.c \
        ft_sqrt.c \
        ft_strcat.c \
        ft_strchr.c \
        ft_strclr.c \
        ft_strcmp.c \
        ft_strcpy.c \
        ft_strdel.c \
        ft_strdup.c \
        ft_strequ.c \
        ft_striter.c \
        ft_striteri.c \
        ft_strjoin.c \
        ft_strlcat.c \
        ft_strlen.c \
        ft_strmap.c \
        ft_strmapi.c \
        ft_strncat.c \
        ft_strncmp.c \
        ft_strncpy.c \
        ft_strnequ.c \
        ft_strnew.c \
        ft_strnstr.c \
        ft_strrchr.c \
        ft_strsplit.c \
        ft_strstr.c \
        ft_strsub.c \
        ft_strtrim.c \
        ft_swap.c \
        ft_tolower.c \
        ft_toupper.c \
		ft_count_if.c \
		ft_foreach.c \
		get_next_line.c \
		ft_itoa_base.c \
		ft_itoa_base_uns.c \
		ft_itoa_base_plus.c \
		ft_my_atoi.c \
		printf.c conversions.c parsing.c ft_wchar_c.c int.c uns_int.c \
		int_flag_no_minus.c int_flag_minus.c uns_int_flag_minus.c \
		uns_int_flag_no_minus.c ft_char.c ft_str.c ft_pointer.c \
		ft_percent.c ft_wchar_str.c ft_wchar_str2.c ft_wchar_width.c \
		ft_countwords.c \
		ft_splitdel.c \
		ft_strjoin_free.c

OBJ = $(addprefix $(OBJ_DIR), $(SRCS:.c=.o))

HDR_FLAGS := -I $(INC_DIR)

.PHONY: all
all: $(NAME)

$(NAME): $(OBJ)
	@ ar rc $(NAME) $(OBJ)
	@echo made

$(OBJ): | $(OBJ_DIR)

$(OBJ_DIR):
	@ mkdir $(OBJ_DIR)

$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	@ $(CC) -c $< -o $@ $(FLAGS) $(HDR_FLAGS)

.PHONY: clean
clean:
	@ rm -f $(OBJ)
	@echo cleaned

.PHONY: fclean
fclean: clean
	@ rm -f $(NAME) 
	@ rm -rf $(OBJ_DIR)
	@echo fcleaned

.PHONY: re
re: fclean all
