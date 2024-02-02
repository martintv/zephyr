/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>

#include <nrfx_timer.h>
#include <hal/nrf_power.h>
#include <nrfx_ppi.h>
#include <helpers/nrfx_gppi.h>

static const nrfx_timer_t sleep_timer = NRFX_TIMER_INSTANCE(1);
static const nrfx_timer_t elapsed_time_timer = NRFX_TIMER_INSTANCE(2);
static const nrfx_timer_t irq_timer = NRFX_TIMER_INSTANCE(3);

static void dummy_timer_event_handler(nrf_timer_event_t event_type, void *p_context)
{
}

void setup_timer1(void)
{
	/* Setup grant timer for application */
	nrfx_timer_config_t counter_cfg = {
		.frequency = NRFX_MHZ_TO_HZ(1),
		.bit_width = NRF_TIMER_BIT_WIDTH_32,
		.mode = NRF_TIMER_MODE_TIMER,
		.p_context = NULL,
	};
	if (nrfx_timer_init(&sleep_timer, &counter_cfg, dummy_timer_event_handler) !=
	    NRFX_SUCCESS) {
		while(1);
	}
	nrf_ppi_channel_t channel_start, channel_stop;

	if (nrfx_ppi_channel_alloc(&channel_start) != NRFX_SUCCESS) {
		while(1);
	}

	if (nrfx_ppi_channel_alloc(&channel_stop) != NRFX_SUCCESS) {
		while(1);
	}

	nrfx_gppi_channel_endpoints_setup(
		channel_start, nrf_power_event_address_get(NRF_POWER, NRF_POWER_EVENT_SLEEPENTER),
		nrfx_timer_task_address_get(&sleep_timer, NRF_TIMER_TASK_START));
	nrfx_gppi_channel_endpoints_setup(
		channel_stop, nrf_power_event_address_get(NRF_POWER, NRF_POWER_EVENT_SLEEPEXIT),
		nrfx_timer_task_address_get(&sleep_timer, NRF_TIMER_TASK_STOP));
	nrfx_gppi_channels_enable(BIT(channel_start));
	nrfx_gppi_channels_enable(BIT(channel_stop));
}

void setup_timer2(void)
{
	/* Setup grant timer for application */
	nrfx_timer_config_t counter_cfg = {
		.frequency = NRFX_MHZ_TO_HZ(1),
		.bit_width = NRF_TIMER_BIT_WIDTH_32,
		.mode = NRF_TIMER_MODE_TIMER,
		.p_context = NULL,
	};
	if (nrfx_timer_init(&elapsed_time_timer, &counter_cfg, dummy_timer_event_handler) !=
	    NRFX_SUCCESS) {
		while(1);
	}

	nrf_timer_task_trigger(NRF_TIMER2, NRF_TIMER_TASK_START);
}

volatile uint32_t interrupt_count;
K_SEM_DEFINE(my_sem, 0, 1);
void timer3_isr_wrapper(void)
{
	interrupt_count++;
	nrf_timer_event_clear(NRF_TIMER3, NRF_TIMER_EVENT_COMPARE0);
	k_sem_give(&my_sem);
	if (interrupt_count ==33000)
	{
		nrf_timer_task_trigger(NRF_TIMER3, NRF_TIMER_TASK_STOP);
	}
}

void setup_timer3(void)
{
	/* Setup grant timer for application */
	nrfx_timer_config_t counter_cfg = {
		.frequency = NRFX_MHZ_TO_HZ(1),
		.bit_width = NRF_TIMER_BIT_WIDTH_32,
		.mode = NRF_TIMER_MODE_TIMER,
		.p_context = NULL,
	};
	if (nrfx_timer_init(&irq_timer, &counter_cfg, dummy_timer_event_handler) !=
	    NRFX_SUCCESS) {
		while(1);
	}
	nrf_timer_cc_set(NRF_TIMER3, NRF_TIMER_CC_CHANNEL0, 30);
	nrf_timer_int_enable(NRF_TIMER3, NRF_TIMER_INT_COMPARE0_MASK);
	IRQ_CONNECT(TIMER3_IRQn, 3, timer3_isr_wrapper, 0, 0);
	irq_enable(TIMER3_IRQn);
	nrf_timer_shorts_set(NRF_TIMER3, NRF_TIMER_SHORT_COMPARE0_CLEAR_MASK);
	nrf_timer_task_trigger(NRF_TIMER3, NRF_TIMER_TASK_START);
}


uint32_t timer1_read_sleep_time_us(void)
{
	nrf_timer_task_trigger(NRF_TIMER1, NRF_TIMER_TASK_CAPTURE0);
	return nrf_timer_cc_get(NRF_TIMER1, NRF_TIMER_CC_CHANNEL0);
}

uint32_t timer1_read_sleep_elapsed_time_us(void)
{
	nrf_timer_task_trigger(NRF_TIMER2, NRF_TIMER_TASK_CAPTURE0);
	return nrf_timer_cc_get(NRF_TIMER2, NRF_TIMER_CC_CHANNEL0);
}


#define MY_STACK_SIZE 5000
#define MY_PRIORITY 5

void my_entry_point(int unused1, int unused2, int unused3)
{
    while (1) {
		if (k_sem_take(&my_sem, K_FOREVER) == 0) {
    	    //printk("SU\n");
    	} else {
    	    printk("Failed\n");
    	}
    }
}


K_THREAD_DEFINE(my_tid, MY_STACK_SIZE,
                my_entry_point, NULL, NULL, NULL,
                MY_PRIORITY, 0, 0);

int main(void)
{
	printf("Hello World! %s\n", CONFIG_BOARD);
	/*timer 1 is used to count how many us1 cpu sleeps
	  timer2 is used for measureing elapsed time
	  timer3 is used to generate interrupts that gives a semaphore that wakes up my_entry_point thread.
	*/
	setup_timer1();
	setup_timer2();
	setup_timer3();
	nrf_timer_task_trigger(NRF_TIMER1, NRF_TIMER_TASK_CLEAR);
	nrf_timer_task_trigger(NRF_TIMER2, NRF_TIMER_TASK_CLEAR);

	k_sleep(K_SECONDS(1));


	nrf_timer_task_trigger(NRF_TIMER3, NRF_TIMER_TASK_STOP);

	uint32_t sleep_time_us = timer1_read_sleep_time_us();
	uint32_t elapsed_time_us = timer1_read_sleep_elapsed_time_us();
	double sleep_percent = (((double)sleep_time_us)/(elapsed_time_us))*100.0;
	#if defined(CONFIG_ARM_MPU)
	printf("CONFIG_ARM_MPU=y\n");
	#else
	printf("CONFIG_ARM_MPU=n\n");
	#endif
	printf("Timer3 interrut count %i\n", interrupt_count);
	printf("Cpu sleept %ums\n", sleep_time_us/1000);
	printf("Elapsed time %u ms\n", elapsed_time_us/1000);
	printf("Cpu slept %.2f%% of the time\n", sleep_percent);
	return 0;
}
