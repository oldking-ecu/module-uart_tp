/**
 * @file uart_tp_user.h
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
 * @timestamp 2026-05-22T20:57:25
 */
#ifndef UART_TP_USER_H__
#define UART_TP_USER_H__
#include "uart_tp.h"

/**
 * @brief 实例枚举定义
 *
 */
typedef enum {
	MODULE_ENUM_NAME(UartTp, ONE) = 0,
	MODULE_ENUM_NAME(UartTp, TOTAL_NUM)
} MODULE_ENUM_TYPE(UartTp);

/**
 * @brief 对外星人提供接口
 *
 */
void MODULE_USERINIT_FUN(UartTp)(void);
void UartTp_UserRxData(uint8 rdata);

#endif    // UART_TP_USER_H__
