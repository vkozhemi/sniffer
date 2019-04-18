/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   printf.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 18:14:44 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/24 18:14:54 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PRINTF_H
# define PRINTF_H

# include <stdio.h>
# include "libft.h"
# include <unistd.h>
# include <stdlib.h>
# include <stdarg.h>
# include <locale.h>
# include <wchar.h>

typedef struct	s_s
{
	int			minus;
	int			plus;
	int			noll;
	int			hash;
	int			space;
	int			width;
	int			calc_width;
	int			precision;
	int			calc_precision;
	int			calc_prec;
	int			flag_precision;
	int			flag_int;
	int			flag_uns_int;
	char		modifier;
	char		conversions;
	char		*str;
	int			i;
	int			len_wchar;
	int			len_wchar1;
	int			len_wchar2;
	int			wchar_s_res;
	int			len_wchar3;
	int			destruct;
	int			current_count;
	int			flag_wchar;
	int			len_p;
	int			len;
	int			j;
	size_t		count;
}				t_s;

int				ft_printf(char *fmt, ...);
void			ft_call_pars(char *fmt, va_list ap, t_s *s);
void			ft_conversions(char *p, int *i, va_list ap, t_s *s);
void			ft_get_conversions(char *p, int *i, t_s *s);
void			ft_get_conversions_str(char *p, int *i, t_s *s);
void			ft_flags(char *p, int *i, t_s *s);
void			ft_field_width(char *p, int *i, t_s *s);
void			ft_precision(char *p, int *i, t_s *s);
void			ft_size_modifier(char *p, int *i, t_s *s);
void			ft_int(intmax_t d, t_s *s);
void			ft_uns_int(uintmax_t d, t_s *s, char *p, int *i);
void			ft_long_int(va_list ap, t_s *s);
void			ft_uns_long_int(va_list ap, t_s *s);
void			ft_uns_long_oct(va_list ap, t_s *s);
void			ft_uns_oct(uintmax_t d, t_s *s);
void			ft_uns_hex(uintmax_t d, t_s *s);
void			ft_uns_hexb(va_list ap, t_s *s);
void			ft_pointer(va_list ap, t_s *s);
void			ft_char(char c, t_s *s);
void			ft_str(va_list ap, t_s *s);
int				ft_size_bin(wchar_t value);
void			ft_wchar_c(wchar_t value, t_s *s);
void			ft_wchar_c11(unsigned int v, unsigned char octet, t_s *s);
void			ft_wchar_c16(unsigned int v, unsigned char octet, t_s *s);
void			ft_wchar_c32(unsigned int v, unsigned char octet, t_s *s);
void			ft_wchar_s(va_list ap, t_s *s);
void			ft_plus_minus_int(intmax_t d, char **str);
void			ft_find_precision_int(t_s *s, char *str);
void			ft_width_int(t_s *s, char *str, intmax_t d);
void			ft_flag_minus_int(t_s *s, char *str, intmax_t d);
void			ft_flag_no_minus_int(t_s *s, char *str, intmax_t d);
void			ft_count_int(t_s *s, char *str, intmax_t d);
void			ft_flag_minus_uns_int(t_s *s, uintmax_t d,
				char *p, int *i);
void			ft_flag_no_minus_uns_int(t_s *s, uintmax_t d,
				char *p, int *i);
void			ft_percent(t_s *s);
void			ft_wchar_s_width(t_s *s, wchar_t *str);
void			ft_wchar_s_str(t_s *s, int j);
void			ft_wchar_s_str_p_w(t_s *s, char *n);
void			ft_len_wchar1(wchar_t value, t_s *s);
void			ft_len_wchar(wchar_t value, t_s *s);
int				ft_size_bin(wchar_t value);
void			ft_len_wchar2(wchar_t value, t_s *s);
void			ft_char_c_minus(t_s *s);
void			ft_char_c_no_minus(t_s *s);

#endif
