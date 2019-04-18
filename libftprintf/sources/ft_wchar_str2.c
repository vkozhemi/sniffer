/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_wchar_str2.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/04 20:22:48 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/04 20:22:51 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_len_wchar(wchar_t value, t_s *s)
{
	unsigned int	v;
	unsigned char	octet;
	int				size;
	int				i;

	if (MB_CUR_MAX == 1)
		s->len_wchar++;
	else
	{
		v = value;
		size = ft_size_bin(value);
		i = 0;
		octet = 0;
		if (size <= 7)
			s->len_wchar++;
		else if (size <= 11)
			s->len_wchar += 2;
		else if (size <= 16)
			s->len_wchar += 3;
		else
			s->len_wchar += 4;
	}
}

void	ft_len_wchar1(wchar_t value, t_s *s)
{
	unsigned int	v;
	unsigned char	octet;
	int				size;
	int				i;

	if (MB_CUR_MAX == 1)
		s->len_wchar1 = 1;
	else
	{
		v = value;
		size = ft_size_bin(value);
		i = 0;
		octet = 0;
		if (size <= 7)
			s->len_wchar1 = 1;
		else if (size <= 11)
			s->len_wchar1 = 2;
		else if (size <= 16)
			s->len_wchar1 = 3;
		else
			s->len_wchar1 = 4;
	}
}

void	ft_wchar_s_str_p_w(t_s *s, char *n)
{
	if (s->flag_precision)
		s->calc_precision = s->precision;
	if (s->calc_precision > 6)
		s->calc_precision = 6;
	if (s->precision == 0)
		s->calc_precision = ft_strlen(n);
	if (s->width)
		s->calc_width = s->width - s->calc_precision;
	else
		s->calc_width = 0;
	if (s->calc_width < 0)
		s->calc_width = 0;
}

void	ft_wchar_s_str(t_s *s, int j)
{
	char	*n;

	n = "(null)";
	ft_wchar_s_str_p_w(s, n);
	if (s->minus)
	{
		while (j < s->calc_precision)
			write(1, &n[j++], 1);
		while (s->calc_width-- > 0 && ++s->count)
			write(1, " ", 1);
		s->count += s->calc_precision;
	}
	else if (s->minus == 0)
	{
		while (s->calc_width-- > 0 && ++s->count)
		{
			if (s->noll)
				write(1, "0", 1);
			else
				write(1, " ", 1);
		}
		while (j < s->calc_precision)
			write(1, &n[j++], 1);
		s->count += s->calc_precision;
	}
}

void	ft_wchar_s_width(t_s *s, wchar_t *str)
{
	if (s->width || s->width == 0)
	{
		if (!*str)
			s->calc_width = s->width;
		else
			s->calc_width = s->width - s->wchar_s_res;
		if (s->calc_width < 0)
			s->calc_width = 0;
	}
}
