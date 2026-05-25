/**
 * @file uart_tp_user.c
 * @author wwyyy (1046685883@qq.com)
 * @link https://gitee.com/oldking-ecu
 * @brief
 * @version 1.0
 * @date 2026-05-22
 *
 * @copyright Copyright (c) 2015-2026 oldking-ecu, All rights reserved
 *
 * @fileid data
 * @filehash 3.2.5075D1B34BCAA98554578B5A5FAC3AF14E75B145AA714D08E1FE0047595D425E
 * @timestamp 2026-05-22T20:57:33
 */
#include "../user_demo/uart_tp_user.h"
#include "public.h"
#include "task.h"
#include "mcu_hal_user.h"
#include "timer.h"
#include "string.h"
#include "../user_demo/iap_cmd_user.h"

static uint8 RxIsr[128];
static uint8 RxFrame[2048];
static uint8 TxFrame[2048];

static void UserRxIndication_FuncPtr(uint8 *rxData, uint16 size)
{
	uint8 *buff;
	if ((buff = UartTp_GetTransBuf(UartTp_INS_ONE, size)) != NULL) {
		memcpy(buff, rxData, size);
		UartTp_TransmitSync(UartTp_INS_ONE);
	}
}
/**
 * @brief 定义实例配置
 *
 */
static const MODULE_INS_CFG_TYPE(UartTp) MODULE_INS_CFG(UartTp)[MODULE_ENUM_NAME(UartTp, TOTAL_NUM)] = {
	{.Type = UARTTP_TYPE_INVT,
	 .UartId = MCU_UART_ONE,
	 .RxBuf = RxIsr,
	 .RxBufSz = sizeof(RxIsr),
	 .RxFmBuf = RxFrame,
	 .RxFmBufSz = sizeof(RxFrame),
	 .RxFmOverTimeMs = 3,
	 .RxIndication_FuncPtr = IapCmd_UserRecvPacketUart,
	 .TxFmBuf = TxFrame,
	 .TxFmBufSz = sizeof(TxFrame),
	 .TxFmInvtTimeMs = 3},
};

/**
 * @brief 顶益实例状态(开辟RAM)
 *
 */
static MODULE_INS_INF_TYPE(UartTp) MODULE_INS_INF(UartTp)[MODULE_ENUM_NAME(UartTp, TOTAL_NUM)];

/**
 * @brief 定义总配置(可以是ram或者flash,不可释放)
 *
 */
MODULE_CFG_TYPE(UartTp)
MODULE_CFG(UartTp) = {0};

/**
 * @brief
 *
 */
void MODULE_USERINIT_FUN(UartTp)(void)
{
	MODULE_CFG(UartTp).InsCfgPtr = MODULE_INS_CFG(UartTp);
	MODULE_CFG(UartTp).InsInfPtr = MODULE_INS_INF(UartTp);
	MODULE_CFG(UartTp).InsNum = ARRAY_SIZE(MODULE_INS_CFG(UartTp));
	MODULE_CFG(UartTp).TxIndication_FuncPtr = NULL;
	MODULE_CFG(UartTp).GetSysTick_FuncPtr = Tim_GetTick;
	MODULE_CFG(UartTp).UartInit_FuncPtr = McuUart_UserInit;
	MODULE_CFG(UartTp).UartTx_FuncPtr = McuUart_TxSync;
	MODULE_CFG(UartTp).UartGetTxBusy_FuncPtr = NULL;
	MODULE_INIT_FUN(UartTp)
	(&MODULE_CFG(UartTp));
	Task_Creat(TASK_NOR, MODULE_MAIN_FUN(UartTp), 0);
}

void UartTp_UserRxData(uint8 rdata)
{
	UartTp_RxData(UartTp_INS_ONE, rdata);
}
