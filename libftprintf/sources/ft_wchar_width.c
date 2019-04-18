/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_wchar_width.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/07 14:56:31 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/08/07 14:56:34 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

int		ft_size_bin(wchar_t value)
{
	int i;

	i = 0;
	while (value)
	{
		value = value / 2;
		i++;
	}
	return (i);
}

void	ft_len_wchar2(wchar_t value, t_s *s)
{
	unsigned int	v;
	unsigned char	octet;
	int				size;
	int				i;

	if (MB_CUR_MAX == 1)
		s->len_wchar2 = 1;
	else
	{
		v = value;
		size = ft_size_bin(value);
		i = 0;
		octet = 0;
		if (size <= 7)
			s->len_wchar2 = 1;
		else if (size <= 11)
			s->len_wchar2 = 2;
		else if (size <= 16)
			s->len_wchar2 = 3;
		else
			s->len_wchar2 = 4;
	}
}

void	ft_char_c_minus(t_s *s)
{
	s->calc_width = s->width - s->len_wchar2;
	if (s->calc_width < 0)
		s->calc_width = 0;
	while (s->calc_width && ++s->count)
	{
		write(1, " ", 1);
		s->calc_width--;
	}
}

void	ft_char_c_no_minus(t_s *s)
{
	s->calc_width = s->width - s->len_wchar2;
	if (s->calc_width < 0)
		s->calc_width = 0;
	while (s->calc_width && ++s->count)
	{
		if (s->noll)
			write(1, "0", 1);
		else
			write(1, " ", 1);
		s->calc_width--;
	}
}
