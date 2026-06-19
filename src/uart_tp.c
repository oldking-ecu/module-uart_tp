/**
 * @file uart_tp.c
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
 * @timestamp 2026-05-22T20:57:14
 */
#include "uart_tp.h"
#include "string.h"
#include "public.h"

// 0 head(0xAA55)                           [RawHex ...] Crc16H(RawHex) Crc16L(RawHex) tail(0xAA55) 漏洞:提前截断数据;校验不通过继续往后看，直到触发buff满自动清空;
// 1A head(0xAA55) LenH(RawHex) LenL(RawHex) [RawHex ...] Crc16H(RawHex) Crc16L(RawHex) tail(0xAA55) 当len错误提前截断且crc凑上，tail可以冗余检查，len错误变短或len错误边长触发超时：跳过当前head重新找head;
// 2                                        [RawHex ...] Crc16H(RawHex) Crc16L(RawHex) tail(0xAA55) 漏洞:提前截断数据;校验不通过继续往后看，直到触发buff满自动清空;
// 1B head(0xAA55) LenH(RawHex) LenL(RawHex) [RawHex ...] Crc16H(RawHex) Crc16L(RawHex)              最优方案
// 2A:转义方案1 HeadMark(0x7E) data[n] CRC16 TailMark(0x7E)
// 5:转义方案2 HeadMark(0x7E) data[n] CRC16 TailMark(0x7E)
// 2B:基于4,无头 data[n] CRC16 TailMark(0x7E)
// 3A:[HeadMark(0x00) "qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)]
// 3B:["qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)] 用于ascii传输
// 4A:[HeadMark(:) "00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(\r\n)]
// 4B:["00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(\r\n)]

/**
 * @brief 头定义
 *
 */
static const uint8 HeadMark1A[] = {0xAA,0x55};
static const uint8 TailMark1A[] = {0x55};
static const uint8 HeadMark1B[] = {0x55,0xAA};
static const uint8 HeadMark3A[] = {0x02};
static const uint8 TailMark3A[] = {0x03};
static const uint8 TailMark3B[] = {0x03};
static const uint8 HeadMark4A[] = {'<'};
static const uint8 TailMark4A[] = {'>'};
static const uint8 TailMark4B[] = {'>', '<'};
#define CHECK_CRC_LEN 2

/**
 * @brief 状态定义(分配RW_MEM
 *
 */
MODULE_INF_TYPE(UartTp)
MODULE_INF(UartTp);

/**
 * @brief
 *
 */
#ifdef MINIMUM_RAM__
	#define GCFG(Member) (MODULE_INF(UartTp).CfgPtr->Member)
#else
	#define GCFG(Member) (MODULE_INF(UartTp).Config.Member)
#endif
#define GINF           (MODULE_INF(UartTp))
#define INSCFG(Member) ((GCFG(InsCfgPtr) + ins)->Member)
#define INSINF(Member) ((GCFG(InsInfPtr) + ins)->Member)
#define CbInf          (&INSINF(CBuf))


// 基于数据流时间间隔[data ... ] crc <--时间间隔--> [data ... ] crc <--时间间隔-->
static void UartTp_MainINVT(uint8 ins)
{
	uint16 idx;
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	} else {
		if ((INSINF(RxFmIdx) && CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs))) ||
			INSINF(RxFmIdx) >= INSCFG(RxFmBufSz)) {
			if (INSINF(RxFmIdx) >= INSCFG(RxFmBufSz)) {
				INSINF(RxErrCntLong)++;
			}
			if (INSINF(RxFmIdx) > CHECK_CRC_LEN) {
				if (Combine2BytesLittle(INSCFG(RxFmBuf) + INSINF(RxFmIdx) - CHECK_CRC_LEN) == Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxFmIdx) - CHECK_CRC_LEN)) {
					if (INSCFG(RxIndication_FuncPtr)) {
						INSCFG(RxIndication_FuncPtr)
						(INSCFG(RxFmBuf), INSINF(RxFmIdx) - CHECK_CRC_LEN);
					}
				} else {
					INSINF(RxErrCntCrc)++;
				}
			} else {
				INSINF(RxErrCntShor)++;
			}
			INSINF(RxFmIdx) = 0;
		}
	}
}

// HeadMark1A len [data ... ] crc TailMark1A
static void UartTp_Main1A(uint8 ins)
{
	uint16 idx;
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		if (0 == INSINF(RxStatus)) {    // 解析头&len
			idx = 0;
			while (idx + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) <= INSINF(RxFmIdx)) {
				if (!memcmp(INSCFG(RxFmBuf) + idx, HeadMark1A, sizeof(HeadMark1A))) {
					INSINF(RxParseSize) = Combine2BytesLittle(INSCFG(RxFmBuf) + idx + sizeof(HeadMark1A));
					if (INSINF(RxParseSize) &&
						sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN + sizeof(TailMark1A) <= INSCFG(RxFmBufSz)) {    // 错误长度
						INSINF(RxStatus) = 1;                                                                                           // 解析长度
						break;
					}
				}
				idx++;
			}
			if (idx) {    // 移动
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
				INSINF(RxFmIdx) -= idx;
			}
		} else if (1 == INSINF(RxStatus)) {//等待长度收齐
			if (INSINF(RxFmIdx) >=
				sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN + sizeof(TailMark1A)) {    // 收齐
				if (!memcmp(INSCFG(RxFmBuf) + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN, TailMark1A, sizeof(TailMark1A)) &&
					Combine2BytesLittle(INSCFG(RxFmBuf) + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize)) ==
						Crc16ModbusBlockCalc(INSCFG(RxFmBuf) + sizeof(HeadMark1A), sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize))) {
					if (INSCFG(RxIndication_FuncPtr)) {
						INSCFG(RxIndication_FuncPtr)
						(INSCFG(RxFmBuf) + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)), INSINF(RxParseSize));
					}
					idx = sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN + sizeof(TailMark1A);
				} else {
					idx = 1;    // 错误的帧
				}
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
				INSINF(RxFmIdx) -= idx;
				INSINF(RxStatus) = 0;
			} else {    // 判断超时后，自动移除
				if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs))) {
					if (INSINF(RxFmIdx)) {
						idx = 1;    // 超时收不齐
						memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
						INSINF(RxFmIdx) -= idx;
					}
					INSINF(RxStatus) = 0;
				}
			}
		}
	}
}

// HeadMark1B len [data ... ] crc
static void UartTp_Main1B(uint8 ins)
{
	uint16 idx;
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		if (0 == INSINF(RxStatus)) {    // 解析头 & len
			idx = 0;
			while (idx + sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) <= INSINF(RxFmIdx)) {
				if (!memcmp(INSCFG(RxFmBuf) + idx, HeadMark1B, sizeof(HeadMark1B))) {
					INSINF(RxParseSize) = Combine2BytesLittle(INSCFG(RxFmBuf) + idx + sizeof(HeadMark1B));
					if (INSINF(RxParseSize) &&
						sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN <= INSCFG(RxFmBufSz)) {
						INSINF(RxStatus) = 1;    // 解析长度
						break;
					}
				}
				idx++;
			}
			if (idx) {    // 移动
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
				INSINF(RxFmIdx) -= idx;
			}
		} else if (1 == INSINF(RxStatus)) {
			if (INSINF(RxFmIdx) >=
				sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN) {    // 收齐
				if (Combine2BytesLittle(INSCFG(RxFmBuf) + sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize)) ==
					Crc16ModbusBlockCalc(INSCFG(RxFmBuf) + sizeof(HeadMark1B), sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize))) {
					if (INSCFG(RxIndication_FuncPtr)) {
						INSCFG(RxIndication_FuncPtr)
						(INSCFG(RxFmBuf) + sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)), INSINF(RxParseSize));
					}
					idx = sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + INSINF(RxParseSize) + CHECK_CRC_LEN;
				} else {
					idx = 1;    // 错误帧，错开重新找
				}
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
				INSINF(RxFmIdx) -= idx;
				INSINF(RxStatus) = 0;
			} else {    // 判断超时后，自动移除
				if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs))) {
					idx = 1;    // 超时收不齐
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
					INSINF(RxStatus) = 0;
				}
			}
		}
	}
}

//(转义)head(0x7E) [data ... crc] tail(0x7E)
static void UartTp_Main2A(uint8 ins)
{
	uint16 idx;

	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		while (INSINF(RxParseSize) < INSINF(RxFmIdx)) {
			if (0 == INSINF(RxStatus)) {    // 解析头
				if (0x7E == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
					INSINF(RxParseSize) = 0;
					INSINF(RxStatus) = 1;
					continue;
				}
			} else if (1 == INSINF(RxStatus)) {
				if (0x7E == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {
					if (INSINF(RxParseSize) > CHECK_CRC_LEN) {
						if (Combine2BytesLittle(INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN) ==
							Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN)) {    // 校验成功
							if (INSCFG(RxIndication_FuncPtr)) {
								INSCFG(RxIndication_FuncPtr)
								(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN);
							}
						}                        /* else {//校验失败
												}*/
						INSINF(RxStatus) = 3;    // 处理head XXX tail xxx tail情况，把前一帧的tail即当尾又当下一帧的头
					}                            /* else {//数据包长度太短 把当前7E当作头
												}*/
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
					INSINF(RxParseSize) = 0;
					continue;
				} else if (0x7D == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 是转义
					INSINF(RxStatus) = 2;
				}
			} else if (2 == INSINF(RxStatus)) {
				if (0x01 == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 0x7D
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf) + INSINF(RxParseSize), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= 1;
					// INSINF(RxParseSize) = idx;
					INSINF(RxStatus) = 1;
					continue;
				} else if (0x02 == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 0x7E
					INSCFG(RxFmBuf)
					[INSINF(RxParseSize) - 1] = 0x7E;
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf) + INSINF(RxParseSize), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= 1;
					// INSINF(RxParseSize) = idx;
					INSINF(RxStatus) = 1;
					continue;
				} else {    // 转义错误
					INSINF(RxStatus) = 0;
				}
			} else if (3 == INSINF(RxStatus)) {
				if (0x7E == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 把7E移动掉
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
				} /* else {//丢失前一个tail或后一个head，无需再移动
				 }*/
				INSINF(RxParseSize) = 0;
				INSINF(RxStatus) = 1;
				continue;
			}
			INSINF(RxParseSize)
			++;
		}
		if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||
			(INSINF(RxFmIdx) >= INSCFG(RxFmBufSz))) {    // TODO移出来 超时收不齐或解析后buff满，清除buff
			INSINF(RxFmIdx) = 0;
			INSINF(RxParseSize) = 0;
			INSINF(RxStatus) = 0;
		}
	}
}

//(转义)[data ... crc] tail(0x7E)
static void UartTp_Main2B(uint8 ins)
{
	uint16 idx;
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		while (INSINF(RxParseSize) < INSINF(RxFmIdx)) {
			if (0 == INSINF(RxStatus)) {
				if (0x7E == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {
					if (INSINF(RxParseSize) > CHECK_CRC_LEN) {
						if (Combine2BytesLittle(INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN) ==
							Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN)) {    // 校验成功
							if (INSCFG(RxIndication_FuncPtr)) {
								INSCFG(RxIndication_FuncPtr)
								(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN);
							}
						} else {    // 校验失败
						}
					} else {    // 数据包长度太短
					}
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
					INSINF(RxParseSize) = 0;
					INSINF(RxStatus) = 0;    // 处理head XXX tail head(丢失) xxx tail情况，把前一帧的tail即当尾又当下一帧的头
					continue;
				} else if (0x7D == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 是转义
					INSINF(RxStatus) = 2;
				}
			} else if (2 == INSINF(RxStatus)) {
				if (0x01 == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 0x7D
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf) + INSINF(RxParseSize), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= 1;
					INSINF(RxStatus) = 0;
					continue;
				} else if (0x02 == INSCFG(RxFmBuf)[INSINF(RxParseSize)]) {    // 0x7E
					INSCFG(RxFmBuf)
					[INSINF(RxParseSize) - 1] = 0x7E;
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf) + INSINF(RxParseSize), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= 1;
					INSINF(RxStatus) = 0;
					continue;
				} else {    // 转义错误，数据全部丢弃
					idx = INSINF(RxParseSize) + 1;
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
					INSINF(RxParseSize) = 0;
					INSINF(RxStatus) = 0;
					continue;
				}
			}
			INSINF(RxParseSize)
			++;
		}
		if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||
			(INSINF(RxFmIdx) >= INSCFG(RxFmBufSz))) {    // TODO移出来 超时收不齐或解析后buff满，清除buff
			INSINF(RxFmIdx) = 0;
			INSINF(RxParseSize) = 0;
			INSINF(RxStatus) = 0;
		}
	}
}

//HeadMark3A ["qaz123aabbcdsadsadf"] CRC16(ASCII) TailMark3A
static void UartTp_Main3A(uint8 ins)
{
	uint16 idx;
	uint16 crc16;
	uint8 crc16Ascii[4];
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		if (0 == INSINF(RxStatus)) {    // 解析头
			idx = 0;
			while (idx + sizeof(HeadMark3A) <= INSINF(RxFmIdx)) {
				if (!memcmp(INSCFG(RxFmBuf) + idx, HeadMark3A, sizeof(HeadMark3A))) {
					INSINF(RxStatus) = 1;    // 解析尾巴
					INSINF(RxParseSize) = sizeof(HeadMark3A);
					break;
				}
				idx++;
			}
			if (idx) {    // 移动
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
				INSINF(RxFmIdx) -= idx;
			}
		} else if (1 == INSINF(RxStatus)) {
			while (INSINF(RxParseSize) + sizeof(TailMark3A) <= INSINF(RxFmIdx)) {
				if (!memcmp(INSCFG(RxFmBuf) + INSINF(RxParseSize), TailMark3A, sizeof(TailMark3A))) {    // 找到尾
					if (INSINF(RxParseSize) > sizeof(HeadMark3A) + CHECK_CRC_LEN * 2) {//head和tail之间去掉check长度必须大于0
						idx = INSINF(RxParseSize) - (sizeof(HeadMark3A) + CHECK_CRC_LEN * 2);
						crc16 = Crc16ModbusBlockCalc(INSCFG(RxFmBuf) + sizeof(HeadMark3A), idx);
						HexToAscii(crc16, crc16Ascii);
						HexToAscii(crc16 >> 8, crc16Ascii + 2);
						if (!memcmp(crc16Ascii, INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN * 2 /*CRC16*/, sizeof(crc16Ascii))) {
							if (INSCFG(RxIndication_FuncPtr)) {
								INSCFG(RxIndication_FuncPtr)
								(INSCFG(RxFmBuf) + sizeof(HeadMark3A), idx);
							}
							idx = INSINF(RxParseSize) + sizeof(TailMark3A);
						} else {
							idx = sizeof(HeadMark3A);    // 错误帧，错开重新找
						}
					} else {
						idx = sizeof(HeadMark3A);    // 错误帧，错开重新找
					}
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
					INSINF(RxStatus) = 0;
					break;
				}
				INSINF(RxParseSize)
				++;
			}
			if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||
				(INSINF(RxFmIdx) >= INSCFG(RxFmBufSz))) {    // 超时收不齐或解析后buff满，跳过1个字节，重新开支找头
				if (INSINF(RxFmIdx)) {
					idx = 1;
					memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
					INSINF(RxFmIdx) -= idx;
				}
				INSINF(RxStatus) = 0;
				INSINF(RxParseSize) = 0;
			}
		}
	}
}

//["qaz123aabbcdsadsadf"] CRC16(ASCII) TailMark3B
static void UartTp_Main3B(uint8 ins)
{
	uint16 idx;
	uint16 crc16;
	uint8 crc16Ascii[4];
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		while (INSINF(RxParseSize) + sizeof(TailMark3B) <= INSINF(RxFmIdx)) {
			if (!memcmp(INSCFG(RxFmBuf) + INSINF(RxParseSize), TailMark3B, sizeof(TailMark3B))) {
				if (INSINF(RxParseSize) > CHECK_CRC_LEN * 2) {
					crc16 = Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN * 2);
					HexToAscii(crc16, crc16Ascii);
					HexToAscii(crc16 >> 8, crc16Ascii + 2);
					if (!memcmp(crc16Ascii, INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN * 2, sizeof(crc16Ascii))) {
						if (INSCFG(RxIndication_FuncPtr)) {
							INSCFG(RxIndication_FuncPtr)
							(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN * 2);
						}
					}
				}
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + (INSINF(RxParseSize) + sizeof(TailMark3B)), INSINF(RxFmIdx) - (INSINF(RxParseSize) + sizeof(TailMark3B)));
				INSINF(RxFmIdx) -= (INSINF(RxParseSize) + sizeof(TailMark3B));
				INSINF(RxParseSize) = 0;
			} else {
				INSINF(RxParseSize)
				++;
			}
		}
		if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||
			(INSINF(RxFmIdx) >= INSCFG(RxFmBufSz))) {    // 超时收不齐或解析后buff满，清除buff
			INSINF(RxFmIdx) = 0;
			INSINF(RxParseSize) = 0;
		}
	}
}

//HeadMark4A ["00112233445566778899AABBCCDDEEFF"] CRC16(ASCII) TailMark4A
static void UartTp_Main4A(uint8 ins)
{
	uint16 idx;
	uint16 crc16;
	uint8 crc16Ascii[4];
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		while (INSINF(RxParseSize) < INSINF(RxFmIdx)) {
			if (0 == INSINF(RxStatus)) {    // 解析头
				if (INSINF(RxParseSize) + sizeof(HeadMark4A) <= INSINF(RxFmIdx)) {
					if (!memcmp(INSCFG(RxFmBuf) + INSINF(RxParseSize), HeadMark4A, sizeof(HeadMark4A))) {
						INSINF(RxParseSize) += sizeof(HeadMark4A);
						memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + INSINF(RxParseSize), INSINF(RxFmIdx) - INSINF(RxParseSize));
						INSINF(RxFmIdx) -= INSINF(RxParseSize);
						INSINF(RxStatus) = 1;
						INSINF(RxParseSize) = 0;
						continue;
					}
				} else {    // 数据长度不够,终止解析
					break;
				}
			} else if (1 == INSINF(RxStatus)) {
				if (INSINF(RxParseSize) + sizeof(TailMark4A) <= INSINF(RxFmIdx)) {
					if (!memcmp(INSCFG(RxFmBuf) + INSINF(RxParseSize), TailMark4A, sizeof(TailMark4A))) {    // 找到尾
						if (INSINF(RxParseSize) > CHECK_CRC_LEN * 2) {
							crc16 = Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN * 2 /*CRC16*/);
							HexToAscii(crc16, crc16Ascii);
							HexToAscii(crc16 >> 8, crc16Ascii + 2);
							if (!memcmp(crc16Ascii, INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN * 2 /*CRC16*/, sizeof(crc16Ascii))) {
								if (!(INSINF(RxParseSize) % 2)) {
									if (!AsciisToHexs(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN * 2, INSCFG(RxFmBuf))) {
										if (INSCFG(RxIndication_FuncPtr)) {
											INSCFG(RxIndication_FuncPtr)
											(INSCFG(RxFmBuf), (INSINF(RxParseSize) - CHECK_CRC_LEN * 2) / 2);
										}
									} else {
										INSINF(RxErrCntContext)
										++;
									}
								} else {
									INSINF(RxErrCntOdd)
									++;
								}
							} else {    // 校验失败
								INSINF(RxErrCntCrc)
								++;
							}
							if (sizeof(HeadMark4A) == sizeof(TailMark4A) && !memcmp(HeadMark4A, TailMark4A, sizeof(HeadMark4A))) {
								INSINF(RxStatus) = 3;    // Case A:需要处理mark XXX mark xxx mark情况，前一帧的尾mark，即当尾又当下一帧的头
							} else {
								INSINF(RxStatus) = 0;
							}
						} else {    // Case B(Head和tail相同):数据包长度太短 把当前Tail当作Head,如果不纠正过来，将会永远错下去
							if (sizeof(HeadMark4A) == sizeof(TailMark4A) && !memcmp(HeadMark4A, TailMark4A, sizeof(HeadMark4A))) {
								// INSINF(RxStatus) = 1;//保持不动
							} else {
								INSINF(RxStatus) = 0;
							}
							INSINF(RxErrCntShor)
							++;
						}
						idx = INSINF(RxParseSize) + sizeof(TailMark4A);
						memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + idx, INSINF(RxFmIdx) - idx);
						INSINF(RxFmIdx) -= idx;
						INSINF(RxParseSize) = 0;
						continue;
					}
				} else {    // 数据长度不够,终止解析
					break;
				}
			} else if (3 == INSINF(RxStatus)) {
				if (INSINF(RxParseSize) + sizeof(HeadMark4A) <= INSINF(RxFmIdx)) {
					if (!memcmp(INSCFG(RxFmBuf) + INSINF(RxParseSize), HeadMark4A, sizeof(HeadMark4A))) {
						INSINF(RxParseSize) += sizeof(HeadMark4A);
						memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + INSINF(RxParseSize), INSINF(RxFmIdx) - INSINF(RxParseSize));
						INSINF(RxFmIdx) -= INSINF(RxParseSize);
						INSINF(RxParseSize) = 0;
					} /* else {//丢失前一个tail或后一个head，无需再移动
					 }*/
					INSINF(RxStatus) = 1;
					continue;
				} else {    // 数据长度不够,终止解析
					break;
				}
			}
			INSINF(RxParseSize)
			++;
		}
		if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||
			(INSINF(RxFmIdx) >= INSCFG(RxFmBufSz))) {    // 超时收不齐或解析后buff满，清除buff
			INSINF(RxFmIdx) = 0;
			INSINF(RxParseSize) = 0;
			INSINF(RxStatus) = 0;
		}
	}
}

//["00112233445566778899AABBCCDDEEFF"] CRC16(ASCII) TailMark4B
static void UartTp_Main4B(uint8 ins)
{
	uint16 idx;
	uint16 crc16;
	uint8 crc16Ascii[4];
	idx = CBuff_Size(CbInf);    // 处理接收
	if (idx) {
		if (idx + INSINF(RxFmIdx) > INSCFG(RxFmBufSz)) {
			idx = INSCFG(RxFmBufSz) - INSINF(RxFmIdx);
		}
		CBuff_Pop(CbInf, INSCFG(RxFmBuf) + INSINF(RxFmIdx), idx);
		INSINF(RxFmIdx) += idx;
		INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
	}
	if (INSINF(RxFmIdx)) {
		while (INSINF(RxParseSize) + sizeof(TailMark4B) <= INSINF(RxFmIdx)) {
			if (!memcmp(INSCFG(RxFmBuf) + INSINF(RxParseSize), TailMark4B, sizeof(TailMark4B))) {    // 找到尾
				if (INSINF(RxParseSize) > CHECK_CRC_LEN * 2) {
					crc16 = Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN * 2 /*CRC16*/);
					HexToAscii(crc16, crc16Ascii);
					HexToAscii(crc16 >> 8, crc16Ascii + 2);
					if (!memcmp(crc16Ascii, INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN * 2 /*CRC16*/, sizeof(crc16Ascii))) {
						if (!(INSINF(RxParseSize) % 2)) {
							if (!AsciisToHexs(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN * 2, INSCFG(RxFmBuf))) {
								if (INSCFG(RxIndication_FuncPtr)) {
									INSCFG(RxIndication_FuncPtr)
									(INSCFG(RxFmBuf), (INSINF(RxParseSize) - CHECK_CRC_LEN * 2) / 2);
								}
							} else {
								INSINF(RxErrCntContext)
								++;
							}
						} else {
							INSINF(RxErrCntOdd)
							++;
						}
					} else {    // 校验失败
						INSINF(RxErrCntCrc)
						++;
					}
				} else {
					INSINF(RxErrCntShor)++;
				}
				memcpy(INSCFG(RxFmBuf), INSCFG(RxFmBuf) + (INSINF(RxParseSize) + sizeof(TailMark4B)), INSINF(RxFmIdx) - (INSINF(RxParseSize) + sizeof(TailMark4B)));
				INSINF(RxFmIdx) -= (INSINF(RxParseSize) + sizeof(TailMark4B));
				INSINF(RxParseSize) = 0;
			} else {
				INSINF(RxParseSize)
				++;
			}
		}
		if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||
			(INSINF(RxFmIdx) >= INSCFG(RxFmBufSz))) {    // 超时收不齐或解析后buff满，清除buff
			INSINF(RxFmIdx) = 0;
			INSINF(RxParseSize) = 0;
		}
	}
}

/**
 * @brief 初始化
 *
 * @param cfgPtr:
 */
void MODULE_INIT_FUN(UartTp)(const MODULE_CFG_TYPE(UartTp) * cfgPtr)
{
	uint8 ins;

	memset(&MODULE_INF(UartTp), 0, sizeof(MODULE_INF(UartTp)));
	if (NULL == cfgPtr)
		return;
#ifdef MINIMUM_RAM__
	MODULE_INF(UartTp).CfgPtr = cfgPtr;
#else
	memcpy((void *)&MODULE_INF(UartTp).Config, cfgPtr, sizeof(MODULE_CFG_TYPE(UartTp)));
#endif
	memset((void *)GCFG(InsInfPtr), 0, sizeof(MODULE_INS_INF_TYPE(UartTp)) * GCFG(InsNum));
	for (ins = 0; ins < GCFG(InsNum); ins++) {
		CBuff_Init(CbInf, INSCFG(RxBuf), 1, INSCFG(RxBufSz));
	}
	GINF.Init = 1;
	if (NULL != GCFG(UartInit_FuncPtr))
		GCFG(UartInit_FuncPtr)
	();
}

/**
 * @brief 返回实例的状态指针
 *
 * @param ins:
 * @return UartTp_InsInfType*:
 */
MODULE_INS_INF_TYPE(UartTp) * MODULE_GET_INSINF_PTR_FUN(UartTp)(uint8 ins)
{
	if (NULL == GCFG(InsInfPtr) || ins > GCFG(InsNum))
		return NULL;
	return GCFG(InsInfPtr) + ins;
}

/**
 * @brief 返回模块实例配置指针
 *
 * @param ins:
 * @return const UartTp_InsCfgType*:
 */
const MODULE_INS_CFG_TYPE(UartTp) * MODULE_GET_INSCFG_PTR_FUN(UartTp)(uint8 ins)
{
	if (NULL == GCFG(InsCfgPtr) || ins > GCFG(InsNum))
		return NULL;
	return GCFG(InsCfgPtr) + ins;
}

/**
 * @brief 周期Main函数
 *
 */
void MODULE_MAIN_FUN(UartTp)(void)
{
	uint8 ins;
	for (ins = 0; ins < GCFG(InsNum); ins++) {
		switch (INSCFG(Type)) {
			case UARTTP_TYPE_INVT:
				UartTp_MainINVT(ins);
				break;
//			case UARTTP_TYPE_1A:
//				UartTp_Main1A(ins);
//				break;
//			case UARTTP_TYPE_1B:
//				UartTp_Main1B(ins);
//				break;
//			case UARTTP_TYPE_2A:
//				UartTp_Main2A(ins);
//				break;
//			case UARTTP_TYPE_2B:
//				UartTp_Main2B(ins);
//				break;
//			case UARTTP_TYPE_3A:
//				UartTp_Main3A(ins);
//				break;
//			case UARTTP_TYPE_3B:
//				UartTp_Main3B(ins);
//				break;
//			case UARTTP_TYPE_4A:
//				UartTp_Main4A(ins);
//				break;
//			case UARTTP_TYPE_4B:
//				UartTp_Main4B(ins);
//				break;
			default:
				break;
		}
		if (1 == INSINF(TxBusy)) {    // 处理发送
			if (GCFG(UartGetTxBusy_FuncPtr)) {
				if (!GCFG(UartGetTxBusy_FuncPtr)(INSCFG(UartId))) {
					INSINF(TxTimstamp) = GCFG(GetSysTick_FuncPtr)();
					INSINF(TxBusy) = 2;
				}
			} else {
				INSINF(TxTimstamp) = GCFG(GetSysTick_FuncPtr)();
				INSINF(TxBusy) = 2;
			}
		} else if (2 == INSINF(TxBusy)) {
			if (CheckTimeout(INSINF(TxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(TxFmInvtTimeMs))) {
				if (GCFG(TxIndication_FuncPtr)) {
					GCFG(TxIndication_FuncPtr)
					(ins, FALS);
				}
				INSINF(TxBusy) = 0;
			}
		}
	}
}
#if 0
//(转义)head [data ... crc]tail
void UartTp_Main(void)
{
	uint8 ins;
	uint16 idx = 0, i;
	uint16 crc16;
	uint8 crc16Ascii[4];

	for (ins = 0; ins < GCFG(InsNum); ins++) {
		idx = CBuff_Size(CbInf);    // 处理接收
		if (idx) {
			if (idx > GCFG(PbufSz)) {
				idx = GCFG(PbufSz);
			}
			CBuff_Pop(CbInf, GCFG(Pbuff), idx);
			INSINF(RxTimstamp) = GCFG(GetSysTick_FuncPtr)();
		}
		if (idx) { 
			for(i = 0; i < idx; i++) {
				if (0 == INSINF(RxStatus)) {    // 解析头
					if (0x7E == GCFG(Pbuff)[i]) {
						INSINF(RxParseSize) = 0;
						INSINF(RxStatus) = 1;
					}
				} else if (1 == INSINF(RxStatus)) {
					if (0x7E == GCFG(Pbuff)[i]) {
						if (INSINF(RxParseSize) > CHECK_CRC_LEN) {
							if (Combine2BytesLittle(INSCFG(RxFmBuf) + INSINF(RxParseSize) - CHECK_CRC_LEN) ==\
								Crc16ModbusBlockCalc(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN)) {//校验成功
								if (INSCFG(RxIndication_FuncPtr)) {
									INSCFG(RxIndication_FuncPtr)(INSCFG(RxFmBuf), INSINF(RxParseSize) - CHECK_CRC_LEN);
								}
							}/* else {//校验失败
							}*/
							INSINF(RxStatus) = 3;//处理head XXX tail xxx tail情况，把前一帧的tail即当尾又当下一帧的头
						}/* else {//数据包长度太短 把当前7E当作头
						}*/
						INSINF(RxParseSize) = 0;
					} else if (0x7D == GCFG(Pbuff)[i]) {//是转义
						INSINF(RxStatus) = 2;
					} else {
						INSCFG(RxFmBuf)[INSINF(RxParseSize)++] = GCFG(Pbuff)[i];
					}
				} else if(2 == INSINF(RxStatus)) {
					if (0x01 == GCFG(Pbuff)[i]) {//0x7D
						INSCFG(RxFmBuf)[INSINF(RxParseSize)++] = 0x7D;
						INSINF(RxStatus) = 1;
					} else if(0x02 == GCFG(Pbuff)[i]) {//0x7E
						INSCFG(RxFmBuf)[INSINF(RxParseSize)++] = 0x7E;
						INSINF(RxStatus) = 1;
					} else {//转义错误
						INSINF(RxStatus) = 0;
					}
				} else if (3 == INSINF(RxStatus)) {
					if(0x7E != GCFG(Pbuff)[i]) {
						INSCFG(RxFmBuf)[INSINF(RxParseSize)++] = GCFG(Pbuff)[i];
					} else {//丢失前一个tail或后一个head
						INSINF(RxParseSize) = 0;
					}
					INSINF(RxStatus) = 1;
				}
				if (INSINF(RxParseSize) >= INSCFG(RxFmBufSz)) {
					INSINF(RxStatus) = 0;
				}
			}
			if (CheckTimeout(INSINF(RxTimstamp), GCFG(GetSysTick_FuncPtr)(), INSCFG(RxFmOverTimeMs)) ||\
				(INSINF(RxParseSize) >= INSCFG(RxFmBufSz))) {// TODO移出来 超时收不齐或解析后buff满，清除buff
				INSINF(RxParseSize) = 0;
				INSINF(RxStatus) = 0;
			}
		}
	}
}
#endif

/**
 * @brief
 *
 * @param ins:
 * @param size:
 * @return uint8*:
 */
uint8 *UartTp_GetTransBuf(uint8 ins, uint16 size)
{
	if (NULL == GCFG(InsCfgPtr) || NULL == GCFG(InsInfPtr)) {
		return NULL;
	}
	if (ins >= GCFG(InsNum)) {
		return NULL;
	}
	if (INSINF(TxBusy)) {
		return NULL;
	}
	if (UARTTP_TYPE_INVT == INSCFG(Type)) {    //[data ... ] crc <--时间间隔--> [data ... ] crc
		if (size + CHECK_CRC_LEN /*CRC16*/ > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf);
	} else if (UARTTP_TYPE_1A == INSCFG(Type)) {    // head len [data ... ] crc tail
		if (sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + size + CHECK_CRC_LEN + sizeof(TailMark1A) > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf) + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize));
	} else if (UARTTP_TYPE_1B == INSCFG(Type)) {    // head len [data ... ] crc
		if (sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + size + CHECK_CRC_LEN > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf) + sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize));
	} else if (UARTTP_TYPE_2A == INSCFG(Type) || UARTTP_TYPE_2B == INSCFG(Type)) {    // 转义head [data ... crc] tail
		if (size + CHECK_CRC_LEN > GCFG(PbufSz)) {
			return NULL;
		}
		INSINF(TxBlkSize) = size;
		return GCFG(Pbuff);
	} else if (UARTTP_TYPE_3A == INSCFG(Type)) {    //[HeadMark(0x00) "qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)]
		if (sizeof(HeadMark3A) + size + CHECK_CRC_LEN * 2 + sizeof(TailMark3A) > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf) + sizeof(HeadMark3A);
	} else if (UARTTP_TYPE_3B == INSCFG(Type)) {    //["qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)]
		if (size + CHECK_CRC_LEN * 2 + sizeof(TailMark3B) > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf);
	} else if (UARTTP_TYPE_4A == INSCFG(Type)) {    //[HeadMark(<) "00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(>)]
		if (sizeof(HeadMark4A) + size * 2 + CHECK_CRC_LEN * 2 + sizeof(TailMark4A) > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		if (NULL == GCFG(Pbuff) || size * 2 > GCFG(PbufSz))
			return NULL;
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf) + sizeof(HeadMark4A);
	} else if (UARTTP_TYPE_4B == INSCFG(Type)) {    //[HeadMark(<) "00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(>)]
		if (size * 2 + CHECK_CRC_LEN * 2 + sizeof(TailMark4B) > INSCFG(TxFmBufSz)) {
			return NULL;
		}
		if (NULL == GCFG(Pbuff) || size * 2 > GCFG(PbufSz))
			return NULL;
		INSINF(TxBlkSize) = size;
		return INSCFG(TxFmBuf);
	} else {
		return NULL;
	}
}

static uint8 UartTp_Transmitc(uint8 ins)
{
	uint16 i, j;
	uint16 crc16;
	if (INSINF(TxBusy)) {
		return 1;
	}
	if (GCFG(TxIndication_FuncPtr)) {
		GCFG(TxIndication_FuncPtr)
		(ins, TRUE);
	}
	if (UARTTP_TYPE_INVT == INSCFG(Type)) {    //[data ... ] crc <--时间间隔--> [data ... ] crc
		Split2BytesLittle(Crc16ModbusBlockCalc(INSCFG(TxFmBuf), INSINF(TxBlkSize)),
						  INSCFG(TxFmBuf) + INSINF(TxBlkSize));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), INSINF(TxBlkSize) + CHECK_CRC_LEN)) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_1A == INSCFG(Type)) {    // head len [data ... ] crc tail
		memcpy(INSCFG(TxFmBuf), HeadMark1A, sizeof(HeadMark1A));
		Split2BytesLittle(INSINF(TxBlkSize), INSCFG(TxFmBuf) + sizeof(HeadMark1A));
		Split2BytesLittle(Crc16ModbusBlockCalc(INSCFG(TxFmBuf) + sizeof(HeadMark1A), sizeof(INSINF(RxParseSize)) + INSINF(TxBlkSize)),
						  INSCFG(TxFmBuf) + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(TxBlkSize));
		memcpy(INSCFG(TxFmBuf) + sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(TxBlkSize) + CHECK_CRC_LEN, TailMark1A, sizeof(TailMark1A));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), sizeof(HeadMark1A) + sizeof(INSINF(RxParseSize)) + INSINF(TxBlkSize) + CHECK_CRC_LEN + sizeof(TailMark1A))) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_1B == INSCFG(Type)) {    // head len [data ... ] crc
		memcpy(INSCFG(TxFmBuf), HeadMark1B, sizeof(HeadMark1B));
		Split2BytesLittle(INSINF(TxBlkSize), INSCFG(TxFmBuf) + sizeof(HeadMark1B));
		Split2BytesLittle(Crc16ModbusBlockCalc(INSCFG(TxFmBuf) + sizeof(HeadMark1B), INSINF(TxBlkSize) + sizeof(INSINF(RxParseSize))),
						  INSCFG(TxFmBuf) + sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + INSINF(TxBlkSize));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), sizeof(HeadMark1B) + sizeof(INSINF(RxParseSize)) + INSINF(TxBlkSize) + CHECK_CRC_LEN)) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_2A == INSCFG(Type)) {    // 转义head [data ... crc] tail
		Split2BytesLittle(Crc16ModbusBlockCalc(GCFG(Pbuff), INSINF(TxBlkSize)),
						  GCFG(Pbuff) + INSINF(TxBlkSize));
		j = 0;
		INSCFG(TxFmBuf)
		[j++] = 0x7E;    // head
		for (i = 0; i < INSINF(TxBlkSize) + CHECK_CRC_LEN; i++) {
			if (j >= INSCFG(TxFmBufSz))
				return 1;    // buff满了
			if (GCFG(Pbuff)[i] == 0x7E) {
				INSCFG(TxFmBuf)
				[j++] = 0x7D;
				INSCFG(TxFmBuf)
				[j++] = 0x02;
			} else if (GCFG(Pbuff)[i] == 0x7D) {
				INSCFG(TxFmBuf)
				[j++] = 0x7D;
				INSCFG(TxFmBuf)
				[j++] = 0x01;
			} else {
				INSCFG(TxFmBuf)
				[j++] = GCFG(Pbuff)[i];
			}
		}
		INSCFG(TxFmBuf)
		[j++] = 0x7E;    // tail
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), j)) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_2B == INSCFG(Type)) {    // 转义[data ... crc] tail
		Split2BytesLittle(Crc16ModbusBlockCalc(GCFG(Pbuff), INSINF(TxBlkSize)),
						  GCFG(Pbuff) + INSINF(TxBlkSize));
		j = 0;
		// INSCFG(TxFmBuf)[j++] = 0x7E;//head
		for (i = 0; i < INSINF(TxBlkSize) + CHECK_CRC_LEN; i++) {
			if (j >= INSCFG(TxFmBufSz))
				return 1;    // buff满了
			if (GCFG(Pbuff)[i] == 0x7E) {
				INSCFG(TxFmBuf)
				[j++] = 0x7D;
				INSCFG(TxFmBuf)
				[j++] = 0x02;
			} else if (GCFG(Pbuff)[i] == 0x7D) {
				INSCFG(TxFmBuf)
				[j++] = 0x7D;
				INSCFG(TxFmBuf)
				[j++] = 0x01;
			} else {
				INSCFG(TxFmBuf)
				[j++] = GCFG(Pbuff)[i];
			}
		}
		INSCFG(TxFmBuf)
		[j++] = 0x7E;    // tail
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), j)) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_3A == INSCFG(Type)) {    //[HeadMark(0x00) "qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)]
		memcpy(INSCFG(TxFmBuf), HeadMark3A, sizeof(HeadMark3A));
		crc16 = Crc16ModbusBlockCalc(INSCFG(TxFmBuf) + sizeof(HeadMark3A), INSINF(TxBlkSize));
		HexToAscii(crc16, INSCFG(TxFmBuf) + sizeof(HeadMark3A) + INSINF(TxBlkSize));
		HexToAscii(crc16 >> 8, INSCFG(TxFmBuf) + sizeof(HeadMark3A) + INSINF(TxBlkSize) + 2);
		memcpy(INSCFG(TxFmBuf) + sizeof(HeadMark3A) + INSINF(TxBlkSize) + CHECK_CRC_LEN * 2, TailMark3A, sizeof(TailMark3A));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), sizeof(HeadMark3A) + INSINF(TxBlkSize) + CHECK_CRC_LEN * 2 + sizeof(TailMark3A))) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_3B == INSCFG(Type)) {    //["qaz123aabbcdsadsadf" CRC16(ASCII) TailMark(0x00)]
		crc16 = Crc16ModbusBlockCalc(INSCFG(TxFmBuf), INSINF(TxBlkSize));
		HexToAscii(crc16, INSCFG(TxFmBuf) + INSINF(TxBlkSize));
		HexToAscii(crc16 >> 8, INSCFG(TxFmBuf) + INSINF(TxBlkSize) + 2);
		memcpy(INSCFG(TxFmBuf) + INSINF(TxBlkSize) + CHECK_CRC_LEN * 2, TailMark3B, sizeof(TailMark3B));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), INSINF(TxBlkSize) + CHECK_CRC_LEN * 2 + sizeof(TailMark3B))) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_4A == INSCFG(Type)) {    //[HeadMark(<) "00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(>)]
		memcpy(INSCFG(TxFmBuf), HeadMark4A, sizeof(HeadMark4A));
		HexsToAsciis(INSCFG(TxFmBuf) + sizeof(HeadMark4A), INSINF(TxBlkSize), GCFG(Pbuff));
		memcpy(INSCFG(TxFmBuf) + sizeof(HeadMark4A), GCFG(Pbuff), INSINF(TxBlkSize) * 2);
		crc16 = Crc16ModbusBlockCalc(INSCFG(TxFmBuf) + sizeof(HeadMark4A), INSINF(TxBlkSize) * 2);
		HexToAscii(crc16, INSCFG(TxFmBuf) + sizeof(HeadMark4A) + INSINF(TxBlkSize) * 2);
		HexToAscii(crc16 >> 8, INSCFG(TxFmBuf) + sizeof(HeadMark4A) + INSINF(TxBlkSize) * 2 + 2);
		memcpy(INSCFG(TxFmBuf) + sizeof(HeadMark4A) + INSINF(TxBlkSize) * 2 + CHECK_CRC_LEN * 2, TailMark4A, sizeof(TailMark4A));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), sizeof(HeadMark4A) + INSINF(TxBlkSize) * 2 + CHECK_CRC_LEN * 2 + sizeof(TailMark4A))) {
			return 1;    // 发送失败
		}
	} else if (UARTTP_TYPE_4B == INSCFG(Type)) {    //["00112233445566778899AABBCCDDEEFF" CRC16(ASCII) TailMark(>)]
		HexsToAsciis(INSCFG(TxFmBuf), INSINF(TxBlkSize), GCFG(Pbuff));
		memcpy(INSCFG(TxFmBuf), GCFG(Pbuff), INSINF(TxBlkSize) * 2);
		crc16 = Crc16ModbusBlockCalc(INSCFG(TxFmBuf), INSINF(TxBlkSize) * 2);
		HexToAscii(crc16, INSCFG(TxFmBuf) + INSINF(TxBlkSize) * 2);
		HexToAscii(crc16 >> 8, INSCFG(TxFmBuf) + INSINF(TxBlkSize) * 2 + 2);
		memcpy(INSCFG(TxFmBuf) + INSINF(TxBlkSize) * 2 + CHECK_CRC_LEN * 2, TailMark4B, sizeof(TailMark4B));
		if (GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), INSINF(TxBlkSize) * 2 + CHECK_CRC_LEN * 2 + sizeof(TailMark4B))) {
			return 1;    // 发送失败
		}
	}
	return 0;
}
/**
 * @brief
 *
 * @param ins:
 */
void UartTp_TransmitSync(uint8 ins)
{
	if (ins >= GCFG(InsNum) || NULL == GCFG(InsCfgPtr) || NULL == GCFG(InsInfPtr)) {
		return;
	}
	if (UartTp_Transmitc(ins))
		return;    // 失败
	if (GCFG(UartGetTxBusy_FuncPtr)) {
		while (GCFG(UartGetTxBusy_FuncPtr)(INSCFG(UartId)))
			;
	}
	if (GCFG(TxIndication_FuncPtr)) {
		GCFG(TxIndication_FuncPtr)
		(ins, FALS);
	}
}

/**
 * @brief
 *
 * @param ins:
 */
void UartTp_TransmitAsync(uint8 ins)
{
	if (ins >= GCFG(InsNum) || NULL == GCFG(InsCfgPtr) || NULL == GCFG(InsInfPtr)) {
		return;
	}
	if (UartTp_Transmitc(ins)) {
		return;    // 失败
	}
	INSINF(TxBusy) = TRUE;
}

// uint8 UartTp_TxDataEB(uint8 ins, uint8 *sData, uint16 size)
//{
//	if (ins >= GCFG(InsNum) || NULL == GCFG(InsCfgPtr) || NULL == GCFG(InsInfPtr)) {
//		return 1;
//	}
//	if (NULL == sData || !size) {
//		return 1;
//	}
//	if (INSINF(TxBusy)) {
//		return 1;
//	}
//	if (size + 2 > INSCFG(TxFmBufSz)) {
//		return 1;
//	}
//	if (GCFG(TxIndication_FuncPtr)) {
//		GCFG(TxIndication_FuncPtr)(ins, TRUE);
//	}
//	memcpy(INSCFG(TxFmBuf), sData, size);
//	Split2BytesLittle(Crc16ModbusBlockCalc(INSCFG(TxFmBuf), INSINF(TxBlkSize)), INSCFG(TxFmBuf) + INSINF(TxBlkSize));
//	GCFG(UartTx_FuncPtr)(INSCFG(UartId), INSCFG(TxFmBuf), INSINF(TxBlkSize) + 2);
//	INSINF(TxBusy) = TRUE;
//	return 0;
// }

/**
 * @brief
 *
 * @param ins:
 * @param rdata:
 */
void UartTp_RxData(uint8 ins, uint8 rdata)
{
	CBuff_Push(CbInf, &rdata, 1);
}
