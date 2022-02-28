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

#include "FreeRtosHooks.h"
#include "app_config.h"

#include "radio.h"

#include <crypto/CHIPCryptoPAL.h>

#if defined(MBEDTLS_USE_TINYCRYPT)
#include <mbedtls/pk.h>
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/ecc_dsa.h>
#endif // defined(MBEDTLS_USE_TINYCRYPT)

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

static int uecc_rng_wrapper(uint8_t *dest, unsigned int size)
{
	CHIP_ERROR ret = CHIP_NO_ERROR;

	ret = chip::Crypto::DRBG_get_bytes(dest, size);

	return (ret == CHIP_NO_ERROR)?size:0;
}

/* BEGIN_CASE depends_on:MBEDTLS_USE_TINYCRYPT */
CHIP_ERROR test_ecdh()
{
    uint8_t private1[NUM_ECC_BYTES] = {0};
    uint8_t private2[NUM_ECC_BYTES] = {0};
    uint8_t public1[2*NUM_ECC_BYTES] = {0};
    uint8_t public2[2*NUM_ECC_BYTES] = {0};
    uint8_t secret1[NUM_ECC_BYTES] = {0};
    uint8_t secret2[NUM_ECC_BYTES] = {0};

    CHIP_ERROR error = CHIP_NO_ERROR;
	int result = UECC_FAILURE;

    uECC_set_rng( &uecc_rng_wrapper );

    ChipLogError(Crypto, "before uECC_make_key");
    result = uECC_make_key( public1, private1 );
    ChipLogError(Crypto, "after uECC_make_key");
    VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

    ChipLogError(Crypto, "before uECC_make_key");
    result = uECC_make_key( public2, private2 );
    ChipLogError(Crypto, "after uECC_make_key");
	VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

	ChipLogError(Crypto, "before uECC_shared_secret");
	result = uECC_shared_secret( public2, private1, secret1 );
	ChipLogError(Crypto, "after uECC_shared_secret");
	VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

	ChipLogError(Crypto, "before uECC_shared_secret");
	result = uECC_shared_secret( public1, private2, secret2 );
	ChipLogError(Crypto, "after uECC_shared_secret");
	VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

	result = memcmp( secret1, secret2, sizeof( secret1 ) );
	VerifyOrExit(result == 0, error = CHIP_ERROR_INTERNAL);

exit:
	return error;
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_USE_TINYCRYPT */
CHIP_ERROR test_ecdsa()
{
    uint8_t private_key[NUM_ECC_BYTES] = {0};
    uint8_t public_key[2*NUM_ECC_BYTES] = {0};
    uint8_t hash[NUM_ECC_BYTES] = {0};
    uint8_t sig[2*NUM_ECC_BYTES] = {0};

    CHIP_ERROR error = CHIP_NO_ERROR;
	int result = UECC_FAILURE;

    uECC_set_rng( &uecc_rng_wrapper );

    result = uecc_rng_wrapper(hash, NUM_ECC_BYTES);
    VerifyOrExit(result == NUM_ECC_BYTES, error = CHIP_ERROR_INTERNAL);

    ChipLogError(Crypto, "before uECC_make_key");
    result = uECC_make_key( public_key, private_key );
    ChipLogError(Crypto, "before uECC_make_key");
    VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

    ChipLogError(Crypto, "before uECC_sign");
    result = uECC_sign( private_key, hash, sizeof( hash ), sig );
    ChipLogError(Crypto, "after uECC_sign");
    VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

    ChipLogError(Crypto, "before uECC_verify");
    result = uECC_verify( public_key, hash, sizeof( hash ), sig );
    ChipLogError(Crypto, "after uECC_verify");
    VerifyOrExit(result == UECC_SUCCESS, error = CHIP_ERROR_INTERNAL);

exit:
	return error;

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

//    // Start OpenThread task
//    ret = ThreadStackMgrImpl().StartThreadTask();
//    if (ret != CHIP_NO_ERROR)
//    {
//        K32W_LOG("Error during ThreadStackMgrImpl().StartThreadTask()");
//        goto exit;
//    }
//
//    ret = GetAppTask().StartAppTask();
//    if (ret != CHIP_NO_ERROR)
//    {
//        K32W_LOG("Error during GetAppTask().StartAppTask()");
//        goto exit;
//    }

    ret = test_ecdh();
    if (ret != CHIP_NO_ERROR)
    {
        K32W_LOG("Error test_ecdh");
        goto exit;
    }

    ret = test_ecdsa();
    if (ret != CHIP_NO_ERROR)
    {
        K32W_LOG("Error test_ecdsa");
        goto exit;
    }


//    GetAppTask().AppTaskMain(NULL);

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
