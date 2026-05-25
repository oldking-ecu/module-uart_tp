/**
 * @file uart_tp.h
 * @author wwyyy (1046685883@qq.com)
 * @link https://gitee.com/oldking-ecu
 * @brief
 * @version 1.0
 * @date 2026-05-22
 *
 * @copyright Copyright (c) 2015-2026 oldking-ecu, All rights reserved
 *
 * @fileid method
 * @filehash 2.2.5075D1B34BCAA98554578B5A5FAC3AF14E75B145AA714D08E1FE0047595D425E
 * @timestamp 2026-05-22T20:57:06
 */
#ifndef UART_TP_H__
#define UART_TP_H__
#include "circular_buff.h"
#include "code_file_std.h"

/**
 * @brief 最小RAM配置
 *
 */
// #define MINIMUM_RAM__

typedef enum {
	UARTTP_TYPE_INVT = 0,
	UARTTP_TYPE_1A,    // HeadMark(AA55) len [data ... ] crc TailMark(BBCC)
	UARTTP_TYPE_1B,    // HeadMark(AA55) len [data ... ] crc
	UARTTP_TYPE_2A,    //(转义)HeadMark(7E) [data ... crc] TailMark(7E)
	UARTTP_TYPE_2B,    //(转义)[data ... crc] TailMark(7E)
	UARTTP_TYPE_3A,
	UARTTP_TYPE_3B,    //["qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)]
	UARTTP_TYPE_4A,    //[HeadMark(:) "00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(\r\n)]
	UARTTP_TYPE_4B,    //["00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(\r\n)]
} UARTTP_ENUM_TYPE;

/**
 * @brief 实例配置参数
 *
 */
typedef struct {
	UARTTP_ENUM_TYPE Type;
	uint8 UartId;     // 物理串口id
	uint8 *RxBuf;     // 必须是2的n次方
	uint8 RxBufSz;    // 必须是2的n次方
	uint8 *RxFmBuf;
	uint16 RxFmBufSz;
	uint16 RxFmOverTimeMs;                                       // 用于判断解析长度期间超时RxFmInvtTimeMs
	void (*RxIndication_FuncPtr)(uint8 *rxData, uint16 size);    // 接收一包数据回调函数

	uint8 *TxFmBuf;
	uint16 TxFmBufSz;
	uint16 TxFmInvtTimeMs;    // 发送完成后间隔,用于驱动发送完成回调
	// uint16			FmMaxSz;//用于非法帧，否则就用RxFmBufSz代替
} MODULE_INS_CFG_TYPE(UartTp);

/**
 * @brief 实例状态变量
 *
 */
typedef struct {
	CircularBufType CBuf;
	uint8 RxStatus;
	uint16 RxFmIdx;        // 解析buff中尾指针,不包括
	uint16 RxParseSize;    // 协议中长度字段或head和tail之间包裹的长度
	uint16 RxErrCntCrc;
	uint16 RxErrCntShor;
	uint16 RxErrCntLong;
	uint16 RxErrCntOdd;
	uint16 RxErrCntContext;
	uint32 RxTimstamp;
	uint8 TxBusy;
	uint16 TxBlkSize;
	uint32 TxTimstamp;
} MODULE_INS_INF_TYPE(UartTp);

/**
 * @brief 总配置参数
 *
 */
typedef struct {
	const MODULE_INS_CFG_TYPE(UartTp) * InsCfgPtr;
	MODULE_INS_INF_TYPE(UartTp) * InsInfPtr;
	uint8 InsNum;
	uint8 *Pbuff;    // 用于临时存储发送原始数据和接收临时解包缓存
	uint16 PbufSz;
	// void (*RxIndication_FuncPtr)(uint8 ins, uint8 *rxData, uint16 size);    // 接收一包数据回调函数
	void (*TxIndication_FuncPtr)(uint8 ins, uint8 txing);    // 发送开始和结束分别回调Txing为1和0，一般用于485 SET DIR为接收
	uint32 (*GetSysTick_FuncPtr)(void);
	void (*UartInit_FuncPtr)(void);
	uint8 (*UartTx_FuncPtr)(uint8 uartIns, const void *sendData, uint16 size);    // 同步或者异步
	uint8 (*UartGetTxBusy_FuncPtr)(uint8 uartIns);                                // 查询tx是否完成，可选
} MODULE_CFG_TYPE(UartTp);

/**
 * @brief 全部状态
 *
 */
typedef struct {
#ifdef MINIMUM_RAM__
	const MODULE_CFG_TYPE(UartTp) * CfgPtr;
#else
	const MODULE_CFG_TYPE(UartTp) Config;
#endif
	uint8 Init;
} MODULE_INF_TYPE(UartTp);

/**
 * @brief 变量声明
 *
 */
extern MODULE_INF_TYPE(UartTp) MODULE_INF(UartTp);

/**
 * @brief 对外提供接口
 *
 */
void MODULE_INIT_FUN(UartTp)(const MODULE_CFG_TYPE(UartTp) * cfgPtr);
MODULE_INS_INF_TYPE(UartTp) * MODULE_GET_INSINF_PTR_FUN(UartTp)(uint8 ins);
const MODULE_INS_CFG_TYPE(UartTp) * MODULE_GET_INSCFG_PTR_FUN(UartTp)(uint8 ins);
void MODULE_MAIN_FUN(UartTp)(void);
uint8 *UartTp_GetTransBuf(uint8 ins, uint16 size);
void UartTp_TransmitSync(uint8 ins);
void UartTp_TransmitAsync(uint8 ins);
// uint8 UartTp_TxDataEB(uint8 ins, uint8 *Data, uint16 size);
void UartTp_RxData(uint8 ins, uint8 rxData);

#endif    // UART_TP_H__
