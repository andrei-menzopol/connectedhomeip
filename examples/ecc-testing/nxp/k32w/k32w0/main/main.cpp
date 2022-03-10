/*
 *
 *    Copyright (c) 2021 Google LLC.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

// ================================================================================
// Main Code
// ================================================================================

#include "openthread/platform/logging.h"
#include "openthread/platform/alarm-milli.h"
#include <mbedtls/platform.h>
#include <openthread-system.h>
#include <openthread/cli.h>
#include <openthread/error.h>
#include <openthread/heap.h>

#include <lib/core/CHIPError.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CHIPPlatformMemory.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#include <platform/ThreadStackManager.h>
#include <app/tests/suites/commands/delay/DelayCommands.h>

#include "FreeRtosHooks.h"
#include "app_config.h"

#include "radio.h"

#include <crypto/CHIPCryptoPAL.h>

extern "C" uint32_t otPlatAlarmMilliGetNow(void);

using namespace ::chip;
using namespace ::chip::Inet;
using namespace ::chip::DeviceLayer;
using namespace ::chip::Logging;
using namespace ::chip::Crypto;

#include <AppTask.h>

typedef void (*InitFunc)(void);
extern InitFunc __init_array_start;
extern InitFunc __init_array_end;

/* needed for FreeRtos Heap 4 */
uint8_t __attribute__((section(".heap"))) ucHeap[HEAP_SIZE];

void delay(void)
{
	int j = 50000;
	while(j--);
}

CHIP_ERROR TestECDSA_KeyGeneration(uint32_t iterations)
{
    uint32_t start, stop;
    uint32_t sum = 0;
    uint32_t time;
    CHIP_ERROR error = CHIP_NO_ERROR;
    Crypto::P256Keypair keypair;

    K32W_LOG("Start ECDSA key generation test");

    for(int i = 0; i < iterations; i++)
    {
    	start = otPlatAlarmMilliGetNow();
    	error = keypair.Initialize();
    	stop = otPlatAlarmMilliGetNow();
    	SuccessOrExit(error != CHIP_NO_ERROR);

    	sum += (stop - start);
    }

    time = sum / iterations;

    K32W_LOG("ECDSA key generation time: %lu", time);

exit:
	return error;
}

CHIP_ERROR TestECDSA_Sign_and_Verify(uint32_t iterations)
{
    const char * msg  = "Hello, this is a very complex message!";
    size_t msg_length = strlen(msg);

    uint32_t start, stop;
	uint32_t sign_sum = 0, verify_sum = 0;
	uint32_t sign_time, verify_time;
	CHIP_ERROR error = CHIP_NO_ERROR;
	CHIP_ERROR signing_error = CHIP_NO_ERROR;
	CHIP_ERROR validation_error = CHIP_NO_ERROR;
	Crypto::P256Keypair keypair;
	P256ECDSASignature signature;

	K32W_LOG("Start ECDSA Sign and Verify test");

	error = keypair.Initialize();
	SuccessOrExit(error);

	for(int i = 0; i < iterations; i++)
	{
		start = otPlatAlarmMilliGetNow();
		signing_error = keypair.ECDSA_sign_msg(reinterpret_cast<const uint8_t *>(msg), msg_length, signature);
		stop = otPlatAlarmMilliGetNow();
		SuccessOrExit(signing_error);

		sign_sum += (stop - start);
		delay();

		start = otPlatAlarmMilliGetNow();
		validation_error =
			keypair.Pubkey().ECDSA_validate_msg_signature(reinterpret_cast<const uint8_t *>(msg), msg_length, signature);
		stop = otPlatAlarmMilliGetNow();
		SuccessOrExit(validation_error);

		verify_sum += (stop - start);
		delay();
	}

	sign_time = sign_sum / iterations;
	verify_time = verify_sum /iterations;

	K32W_LOG("ECDSA sign time: %lu", sign_time);
	K32W_LOG("ECDSA validate signature time: %lu", verify_time);

exit:
	return error;
}

CHIP_ERROR TestECDH_EstablishSecret(uint32_t iterations)
{

    const char * msg  = "Hello, this is a very complex message!";
    size_t msg_length = strlen(msg);

    uint32_t start, stop;
	uint32_t sum = 0;
	uint32_t time;
	uint8_t ret;
	CHIP_ERROR error = CHIP_NO_ERROR;
	Crypto::P256Keypair keypair1, keypair2;

	P256ECDHDerivedSecret out_secret1;
	out_secret1[0] = 0;

	P256ECDHDerivedSecret out_secret2;
	out_secret2[0] = 1;

	ret = memcmp(Uint8::to_uchar(out_secret1), Uint8::to_uchar(out_secret2), out_secret1.Capacity());
	VerifyOrExit(ret != 0, error = CHIP_ERROR_INTERNAL);

	K32W_LOG("Start ECDH Establish Secret test");

	for(int i = 0; i < iterations; i++)
	{
		error = keypair1.Initialize();
		SuccessOrExit(error);

		error = keypair2.Initialize();
		SuccessOrExit(error);

		start = otPlatAlarmMilliGetNow();
	    error = keypair2.ECDH_derive_secret(keypair1.Pubkey(), out_secret1);
	    stop = otPlatAlarmMilliGetNow();
	    SuccessOrExit(error);

	    sum += (stop - start);
	    delay();

	    start = otPlatAlarmMilliGetNow();
	    error = keypair1.ECDH_derive_secret(keypair2.Pubkey(), out_secret2);
	    stop = otPlatAlarmMilliGetNow();
	    SuccessOrExit(error);

	    sum += (stop - start);
	    delay();

	    ret = out_secret1.Length() == out_secret2.Length();
	    VerifyOrExit(ret != 0, error = CHIP_ERROR_INTERNAL);

	    ret = memcmp(Uint8::to_uchar(out_secret1), Uint8::to_uchar(out_secret2), out_secret1.Length());
	    VerifyOrExit(ret == 0, error = CHIP_ERROR_INTERNAL);
	}

	time = sum / (2*iterations);

	K32W_LOG("ECDH Establish Secret time: %lu", time);

exit:
	return error;
}

void TestECC_Operations(uint32_t iterations)
{
	CHIP_ERROR ret = CHIP_NO_ERROR;

#if defined(MBEDTLS_USE_TINYCRYPT)
	K32W_LOG("Tinycrypt used");
#else
	K32W_LOG("Standard mbedtls used");
#endif
	K32W_LOG("Iterations: %lu", iterations);

	ret = TestECDSA_KeyGeneration(iterations);
	if (ret != CHIP_NO_ERROR)
	{
		K32W_LOG("TestECDSA_KeyGeneration error");
	}

	ret = TestECDSA_Sign_and_Verify(iterations);
	if (ret != CHIP_NO_ERROR)
	{
		K32W_LOG("TestECDSA_Sign_and_Verify error");
	}

	ret = TestECDH_EstablishSecret(iterations);
	if (ret != CHIP_NO_ERROR)
	{
		K32W_LOG("TestECDH_EstablishSecret error");
	}
}



/* END_CASE */

extern "C" void main_task(void const * argument)
{
    /* Call C++ constructors */
    InitFunc * pFunc = &__init_array_start;
    for (; pFunc < &__init_array_end; ++pFunc)
    {
        (*pFunc)();
    }

    mbedtls_platform_set_calloc_free(CHIPPlatformMemoryCalloc, CHIPPlatformMemoryFree);

    /* Used for HW initializations */
    otSysInit(0, NULL);

    K32W_LOG("Welcome to NXP Lighting Demo App");

    /* Mbedtls Threading support is needed because both
     * Thread and Weave tasks are using it */
    freertos_mbedtls_mutex_init();

    // Init Chip memory management before the stack
    chip::Platform::MemoryInit();

    CHIP_ERROR ret = PlatformMgr().InitChipStack();
    if (ret != CHIP_NO_ERROR)
    {
        K32W_LOG("Error during PlatformMgr().InitWeaveStack()");
        goto exit;
    }

    ret = ThreadStackMgr().InitThreadStack();
    if (ret != CHIP_NO_ERROR)
    {
        K32W_LOG("Error during ThreadStackMgr().InitThreadStack()");
        goto exit;
    }

    ret = ConnectivityMgr().SetThreadDeviceType(ConnectivityManager::kThreadDeviceType_MinimalEndDevice);
    if (ret != CHIP_NO_ERROR)
    {
        goto exit;
    }

    ret = PlatformMgr().StartEventLoopTask();
    if (ret != CHIP_NO_ERROR)
    {
        K32W_LOG("Error during PlatformMgr().StartEventLoopTask();");
        goto exit;
    }

    TestECC_Operations(30);



exit:
    return;
}

extern "C" void otSysEventSignalPending(void)
{
    {
        BaseType_t yieldRequired = ThreadStackMgrImpl().SignalThreadActivityPendingFromISR();
        portYIELD_FROM_ISR(yieldRequired);
    }
}
