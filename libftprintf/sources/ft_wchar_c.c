/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_wchar_c.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkozhemi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 17:54:16 by vkozhemi          #+#    #+#             */
/*   Updated: 2018/07/24 17:54:18 by vkozhemi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/printf.h"

void	ft_wchar_c7(wchar_t value, unsigned char octet)
{
	octet = value;
	write(1, &octet, 1);
}

void	ft_wchar_c11(unsigned int v, unsigned char octet, t_s *s)
{
	unsigned int	mask1;
	unsigned char	o2;
	unsigned char	o1;

	mask1 = 49280;
	o2 = (v << 26) >> 26;
	o1 = ((v >> 6) << 27) >> 27;
	octet = (mask1 >> 8) | o1;
	write(1, &octet, 1);
	octet = ((mask1 << 24) >> 24) | o2;
	write(1, &octet, 1);
	s->count += 2;
}

void	ft_wchar_c16(unsigned int v, unsigned char octet, t_s *s)
{
	unsigned int	mask2;
	unsigned char	o3;
	unsigned char	o2;
	unsigned char	o1;

	mask2 = 14712960;
	o3 = (v << 26) >> 26;
	o2 = ((v >> 6) << 26) >> 26;
	o1 = ((v >> 12) << 28) >> 28;
	octet = (mask2 >> 16) | o1;
	write(1, &octet, 1);
	octet = ((mask2 << 16) >> 24) | o2;
	write(1, &octet, 1);
	octet = ((mask2 << 24) >> 24) | o3;
	write(1, &octet, 1);
	s->count += 3;
}

void	ft_wchar_c32(unsigned int v, unsigned char octet, t_s *s)
{
	unsigned int	mask3;
	unsigned char	o4;
	unsigned char	o3;
	unsigned char	o2;
	unsigned char	o1;

	mask3 = 4034953344;
	o4 = (v << 26) >> 26;
	o3 = ((v >> 6) << 26) >> 26;
	o2 = ((v >> 12) << 26) >> 26;
	o1 = ((v >> 18) << 29) >> 29;
	octet = (mask3 >> 24) | o1;
	write(1, &octet, 1);
	octet = ((mask3 << 8) >> 24) | o2;
	write(1, &octet, 1);
	octet = ((mask3 << 16) >> 24) | o3;
	write(1, &octet, 1);
	octet = ((mask3 << 24) >> 24) | o4;
	write(1, &octet, 1);
	s->count += 4;
}

void	ft_wchar_c(wchar_t value, t_s *s)
{
	unsigned int	v;
	int				size;
	unsigned char	octet;

	if (MB_CUR_MAX == 1)
		ft_char(value, s);
	else
	{
		v = value;
		size = ft_size_bin(value);
		octet = 0;
		ft_len_wchar2(value, s);
		if (s->minus == 0)
			ft_char_c_no_minus(s);
		if (size <= 7 && ++s->count)
			ft_wchar_c7(value, octet);
		else if (size <= 11)
			ft_wchar_c11(v, octet, s);
		else if (size <= 16)
			ft_wchar_c16(v, octet, s);
		else
			ft_wchar_c32(v, octet, s);
		if (s->minus)
			ft_char_c_minus(s);
	}
}
