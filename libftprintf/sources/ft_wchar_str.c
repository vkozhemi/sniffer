/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_wchar_str.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/04 20:22:39 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/04 20:22:40 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_wchar_s_print(t_s *s, wchar_t *str)
{
	int i;

	i = 0;
	while (str[i] && s->wchar_s_res > 0)
	{
		ft_wchar_c(str[i++], s);
		s->wchar_s_res -= s->len_wchar1;
	}
}

void	ft_wchar_s_precision(t_s *s, wchar_t *str)
{
	int j;

	j = 0;
	if (s->precision || s->flag_precision)
	{
		s->calc_precision = s->precision;
		while (str[j] && (s->calc_precision > 0))
		{
			ft_len_wchar1(str[j], s);
			s->calc_precision -= s->len_wchar1;
			if (s->calc_precision >= 0)
				s->wchar_s_res += s->len_wchar1;
			j++;
		}
		if (s->precision > s->len_wchar)
			s->precision = s->len_wchar;
		else
			s->precision = s->wchar_s_res;
	}
	else
		s->wchar_s_res = s->len_wchar;
}

void	ft_wchar_s_width_print(t_s *s, wchar_t *str)
{
	if (s->minus)
	{
		ft_wchar_s_print(s, str);
		while (s->calc_width-- && ++s->count)
			write(1, " ", 1);
	}
	else if (s->minus == 0)
	{
		while (s->calc_width-- && ++s->count)
		{
			if (s->noll)
				write(1, "0", 1);
			else
				write(1, " ", 1);
		}
		if (s->precision == 0 && s->flag_precision)
			write(1, "", 0);
		else
			ft_wchar_s_print(s, str);
	}
}

void	ft_wchar_s_width_print2(t_s *s, wchar_t *str)
{
	int i;
	int res;

	i = 0;
	res = s->wchar_s_res;
	while (str[i] && res > 0)
	{
		ft_wchar_c(str[i], s);
		ft_len_wchar1(str[i++], s);
		res -= s->len_wchar1;
	}
}

void	ft_wchar_s(va_list ap, t_s *s)
{
	int		i;
	wchar_t	*str;

	i = 0;
	s->j = 0;
	s->wchar_s_res = 0;
	str = va_arg(ap, wchar_t*);
	if (!str)
	{
		ft_wchar_s_str(s, s->j);
		return ;
	}
	while (str[s->j])
		ft_len_wchar(str[s->j++], s);
	ft_wchar_s_precision(s, str);
	ft_wchar_s_width(s, str);
	if (s->width)
		ft_wchar_s_width_print(s, str);
	else
		ft_wchar_s_width_print2(s, str);
	ft_bzero(s, sizeof(int) * 24 + sizeof(char) * 3);
}
