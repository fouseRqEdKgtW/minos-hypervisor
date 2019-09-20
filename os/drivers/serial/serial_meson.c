/*
 * copyright (c) 2018 min le (lemin9538@gmail.com)
 *
 * this program is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license version 2 as
 * published by the free software foundation.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program.  if not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>
#include <asm/io.h>
#include <minos/mmu.h>

#define AO_UART1_WFIFO		(0xff803000 + (0x000 << 2))
#define AO_UART1_RFIFO		(0xff803000 + (0x001 << 2))
#define AO_UART1_CONTROL	(0xff803000 + (0x002 << 2))
#define AO_UART1_STATUS		(0xff803000 + (0x003 << 2))
#define AO_UART1_MISC		(0xff803000 + (0x004 << 2))
#define AO_UART1_REG5		(0xff803000 + (0x005 << 2))

#define AO_UART2_WFIFO		(0xff804000 + (0x000 << 2))
#define AO_UART2_RFIFO		(0xff804000 + (0x001 << 2))
#define AO_UART2_CONTROL	(0xff804000 + (0x002 << 2))
#define AO_UART2_STATUS		(0xff804000 + (0x003 << 2))
#define AO_UART2_MISC		(0xff804000 + (0x004 << 2))
#define AO_UART2_REG5		(0xff804000 + (0x005 << 2))

#define UART_PORT	0

#if UART_PORT == 0
#define UART_WFIFO	AO_UART1_WFIFO
#define UART_RFIFO	AO_UART1_RFIFO
#define UART_CONTROL	AO_UART1_CONTROL
#define UART_STATUS	AO_UART1_STATUS
#define UART_MISC	AO_UART1_MISC
#define UART_REG5	AO_UART1_REG5
#else
#define UART_WFIFO	AO_UART2_WFIFO
#define UART_RFIFO	AO_UART2_RFIFO
#define UART_CONTROL	AO_UART2_CONTROL
#define UART_STATUS	AO_UART2_STATUS
#define UART_MISC	AO_UART2_MISC
#define UART_REG5	AO_UART2_REG5
#endif

static void serial_serbrg(int baud)
{
	int clk81 = 0;
	unsigned long baud_para;
	uint32_t cval;

	baud_para = clk81 / (baud * 4) - 1;
	baud_para &= UART_CNTL_MASK_BAUD_RATE;
	cval = ioread32(UART_CONTROL) & ~UART_CNTL_MASK_BAUD_RATE;
	cval |= baud_para;

	iowrite32(cval, UART_CONTROL);
}

static void serial_set_stop(int stop_bits)
{
	unsigned long uart_config;

	uart_config = ioread32(UART_CONTROL) & ~UART_CNTL_MASK_STP_BITS;
	
	switch (stop_bits) {
	case 2:
		uart_config |= UART_CNTL_MASK_STP_2BIT;
		break;
	case 1:
		uart_config |= UART_CNTL_MASK_STP_1BIT;
		break;
	default:
		break;
	}

	iowrite32(uart_config, UART_CONTROL);
}

static void serial_set_parity(int type)
{
	unsigned long uart_config;

    uart_config = ioread32(UART_CONTROL) & ~(UART_CNTL_MASK_PRTY_TYPE |
		    UART_CNTL_MASK_PRTY_EN);
    iowrite32(uart_config, UART_CONTROL);
}

static void serial_set_dlen(int data_len)
{
	unsigned long uart_config;

	uart_config = ioread32(UART_CONTROL) & ~UART_CNTL_MASK_CHAR_LEN;
	switch (data_len) {
	case 5:
		uart_config |= UART_CNTL_MASK_CHAR_5BIT;
		break;
	case 6:
		uart_config |= UART_CNTL_MASK_CHAR_6BIT;
		break;
	case 7:
		uart_config |= UART_CNTL_MASK_CHAR_7BIT;
		break;
	case 8:
		uart_config |= UART_CNTL_MASK_CHAR_8BIT;
		break;
	default:
		uart_config |= UART_CNTL_MASK_CHAR_8BIT;
		break;
	}

	iowrite32(uart_config, UART_CONTROL);
}

static void serial_reset(void)
{
	uint32_t value;

	value = ioread32(UART_CONTROL);
	value |= (UART_CNTL_MASK_RST_TX | UART_CNTL_MASK_RST_RX |
			UART_CNTL_MASK_CLR_ERR);
	iowrite32(value, UART_CONTROL);

	value = ioread32(UART_CONTROL);
	value &= ~(UART_CNTL_MASK_RST_TX | UART_CNTL_MASK_RST_RX |
			UART_CNTL_MASK_CLR_ERR);
	iowrite32(value, UART_CONTROL);
}

static void inline __meson_uart_putc(char c)
{
	while ((ioread32(UART_STATUS) & UART_STAT_MASK_TFIFO_FULL));

	iowrite32(c, UART_WFIFO);
}

void meson_uart_putc(char c)
{
	if (c == '\n')
		__meson_uart_putc('\r');
	__meson_uart_putc(c);
}

char meson_uart_getc(void)
{
	uint32_t value;
	char ch;

	while ((ioread32(UART_STATUS) & UART_STAT_MASK_RFIFO_CNT) == 0);
	
	ch = ioread32(UART_RFIFO) & 0x00ff;

	if (ioread32(UART_STATUS) & (UART_STAT_MASK_PRTY_ERR |
				UART_STAT_MASK_FRAM_ERR)) {
		value = ioread32(UART_CONTROL);
		value |= UART_CNTL_MASK_CLR_ERR;
		iowrite32(value, UART_CONTROL);

		value = ioread32(UART_CONTROL);
		value &= ~UART_CNTL_MASK_CLR_ERR;
		iowrite32(value, UART_CONTROL);
	}

	return ch;
}

int meson_uart_init(void *addr, int clock, int baudrate)
{
	uint32_t value;

	iowrite32(0, UART_CONTROL);
	serial_set_brg(115200);
	serial_set_stop(1);
	serial_set_parity(0);
	serial_set_dlen(8);

	value = ioread32(UART_CONTROL);
	value |= (UART_CNTL_MASK_TX_EN | UART_CNTL_MASK_RX_EN);
	iowrite32(value, UART_CONTROL);

	while (!(ioread32(UART_CONTROL) & UART_STAT_MASK_TFIFO_EMPTY));

	serial_reset();
}
