/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
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

// THIS FILE IS GENERATED BY ZAP

// Prevent multiple inclusion
#pragma once

#include <lib/core/CHIPConfig.h>


// Default values for the attributes longer than a pointer,
// in a form of a binary blob
// Separate block is generated for big-endian and little-endian cases.
#if BIGENDIAN_CPU
#define GENERATED_DEFAULTS { \
\
  /* Endpoint: 0, Cluster: General Commissioning (server), big-endian */\
\
  /* 0 - Breadcrumb, */\
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
\
}


#else // !BIGENDIAN_CPU
#define GENERATED_DEFAULTS { \
\
  /* Endpoint: 0, Cluster: General Commissioning (server), little-endian */\
\
  /* 0 - Breadcrumb, */\
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
\
}

#endif // BIGENDIAN_CPU

#define GENERATED_DEFAULTS_COUNT (1)

#define ZAP_TYPE(type) ZCL_ ## type ## _ATTRIBUTE_TYPE
#define ZAP_LONG_DEFAULTS_INDEX(index) { &generatedDefaults[index] }
#define ZAP_MIN_MAX_DEFAULTS_INDEX(index) { &minMaxDefaults[index] }
#define ZAP_EMPTY_DEFAULT() {(uint32_t) 0}
#define ZAP_SIMPLE_DEFAULT(x) {(uint32_t) x}

// This is an array of EmberAfAttributeMinMaxValue structures.
#define GENERATED_MIN_MAX_DEFAULT_COUNT 2
#define GENERATED_MIN_MAX_DEFAULTS { \
\
  /* Endpoint: 1, Cluster: On/Off (server) */ \
  { (uint16_t)0xFF, (uint16_t)0x0, (uint16_t)0x2 }, /* StartUpOnOff */ \
\
  /* Endpoint: 1, Cluster: Level Control (server) */ \
  { (uint16_t)0x0, (uint16_t)0x0, (uint16_t)0x3 } /* Options */ \
}


#define ZAP_ATTRIBUTE_MASK(mask) ATTRIBUTE_MASK_ ## mask
// This is an array of EmberAfAttributeMetadata structures.
#define GENERATED_ATTRIBUTE_COUNT 170
#define GENERATED_ATTRIBUTES { \
\
  /* Endpoint: 0, Cluster: Descriptor (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* device list */  \
  { 0x00000001, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* server list */  \
  { 0x00000002, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* client list */  \
  { 0x00000003, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* parts list */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Access Control (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_EMPTY_DEFAULT() }, /* ACL */  \
  { 0x00000002, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* SubjectsPerAccessControlEntry */  \
  { 0x00000003, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TargetsPerAccessControlEntry */  \
  { 0x00000004, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* AccessControlEntriesPerFabric */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Basic (server) */ \
  { 0x00000000, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* DataModelRevision */  \
  { 0x00000001, ZAP_TYPE(CHAR_STRING), 33, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* VendorName */  \
  { 0x00000002, ZAP_TYPE(VENDOR_ID), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* VendorID */  \
  { 0x00000003, ZAP_TYPE(CHAR_STRING), 33, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* ProductName */  \
  { 0x00000004, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* ProductID */  \
  { 0x00000005, ZAP_TYPE(CHAR_STRING), 33, ZAP_ATTRIBUTE_MASK(TOKENIZE) | ZAP_ATTRIBUTE_MASK(SINGLETON) | ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_EMPTY_DEFAULT() }, /* NodeLabel */  \
  { 0x00000006, ZAP_TYPE(CHAR_STRING), 3, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON) | ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_EMPTY_DEFAULT() }, /* Location */  \
  { 0x00000007, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* HardwareVersion */  \
  { 0x00000008, ZAP_TYPE(CHAR_STRING), 65, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* HardwareVersionString */  \
  { 0x00000009, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* SoftwareVersion */  \
  { 0x0000000A, ZAP_TYPE(CHAR_STRING), 65, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_EMPTY_DEFAULT() }, /* SoftwareVersionString */  \
  { 0x00000013, ZAP_TYPE(STRUCT), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* CapabilityMinima */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(SINGLETON), ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: OTA Software Update Requestor (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_EMPTY_DEFAULT() }, /* DefaultOtaProviders */  \
  { 0x00000001, ZAP_TYPE(BOOLEAN), 1, 0, ZAP_SIMPLE_DEFAULT(1) }, /* UpdatePossible */  \
  { 0x00000002, ZAP_TYPE(ENUM8), 1, 0, ZAP_SIMPLE_DEFAULT(0) }, /* UpdateState */  \
  { 0x00000003, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_SIMPLE_DEFAULT(0) }, /* UpdateStateProgress */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: General Commissioning (server) */ \
  { 0x00000000, ZAP_TYPE(INT64U), 8, ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_LONG_DEFAULTS_INDEX(0) }, /* Breadcrumb */  \
  { 0x00000001, ZAP_TYPE(STRUCT), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* BasicCommissioningInfo */  \
  { 0x00000002, ZAP_TYPE(ENUM8), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RegulatoryConfig */  \
  { 0x00000003, ZAP_TYPE(ENUM8), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* LocationCapability */  \
  { 0x00000004, ZAP_TYPE(BOOLEAN), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* SupportsConcurrentConnection */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Network Commissioning (server) */ \
  { 0x00000000, ZAP_TYPE(INT8U), 1, 0, ZAP_EMPTY_DEFAULT() }, /* MaxNetworks */  \
  { 0x00000001, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* Networks */  \
  { 0x00000002, ZAP_TYPE(INT8U), 1, 0, ZAP_EMPTY_DEFAULT() }, /* ScanMaxTimeSeconds */  \
  { 0x00000003, ZAP_TYPE(INT8U), 1, 0, ZAP_EMPTY_DEFAULT() }, /* ConnectMaxTimeSeconds */  \
  { 0x00000004, ZAP_TYPE(BOOLEAN), 1, ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_EMPTY_DEFAULT() }, /* InterfaceEnabled */  \
  { 0x00000005, ZAP_TYPE(ENUM8), 1, ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* LastNetworkingStatus */  \
  { 0x00000006, ZAP_TYPE(OCTET_STRING), 33, ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* LastNetworkID */  \
  { 0x00000007, ZAP_TYPE(INT32S), 4, ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* LastConnectErrorValue */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(2) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: General Diagnostics (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* NetworkInterfaces */  \
  { 0x00000001, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RebootCount */  \
  { 0x00000008, ZAP_TYPE(BOOLEAN), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TestEventTriggersEnabled */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Software Diagnostics (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* ThreadMetrics */  \
  { 0x00000001, ZAP_TYPE(INT64U), 8, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* CurrentHeapFree */  \
  { 0x00000002, ZAP_TYPE(INT64U), 8, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* CurrentHeapUsed */  \
  { 0x00000003, ZAP_TYPE(INT64U), 8, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* CurrentHeapHighWatermark */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(1) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Thread Network Diagnostics (server) */ \
  { 0x00000000, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* channel */  \
  { 0x00000001, ZAP_TYPE(ENUM8), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* RoutingRole */  \
  { 0x00000002, ZAP_TYPE(CHAR_STRING), 17, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* NetworkName */  \
  { 0x00000003, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* PanId */  \
  { 0x00000004, ZAP_TYPE(INT64U), 8, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* ExtendedPanId */  \
  { 0x00000005, ZAP_TYPE(OCTET_STRING), 18, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* MeshLocalPrefix */  \
  { 0x00000006, ZAP_TYPE(INT64U), 8, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* OverrunCount */  \
  { 0x00000007, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* NeighborTableList */  \
  { 0x00000008, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RouteTableList */  \
  { 0x00000009, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* PartitionId */  \
  { 0x0000000A, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* weighting */  \
  { 0x0000000B, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* DataVersion */  \
  { 0x0000000C, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* StableDataVersion */  \
  { 0x0000000D, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* LeaderRouterId */  \
  { 0x0000000E, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* DetachedRoleCount */  \
  { 0x0000000F, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* ChildRoleCount */  \
  { 0x00000010, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RouterRoleCount */  \
  { 0x00000011, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* LeaderRoleCount */  \
  { 0x00000012, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* AttachAttemptCount */  \
  { 0x00000013, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* PartitionIdChangeCount */  \
  { 0x00000014, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* BetterPartitionAttachAttemptCount */  \
  { 0x00000015, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* ParentChangeCount */  \
  { 0x00000016, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxTotalCount */  \
  { 0x00000017, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxUnicastCount */  \
  { 0x00000018, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxBroadcastCount */  \
  { 0x00000019, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxAckRequestedCount */  \
  { 0x0000001A, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxAckedCount */  \
  { 0x0000001B, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxNoAckRequestedCount */  \
  { 0x0000001C, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxDataCount */  \
  { 0x0000001D, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxDataPollCount */  \
  { 0x0000001E, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxBeaconCount */  \
  { 0x0000001F, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxBeaconRequestCount */  \
  { 0x00000020, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxOtherCount */  \
  { 0x00000021, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxRetryCount */  \
  { 0x00000022, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxDirectMaxRetryExpiryCount */  \
  { 0x00000023, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxIndirectMaxRetryExpiryCount */  \
  { 0x00000024, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxErrCcaCount */  \
  { 0x00000025, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxErrAbortCount */  \
  { 0x00000026, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TxErrBusyChannelCount */  \
  { 0x00000027, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxTotalCount */  \
  { 0x00000028, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxUnicastCount */  \
  { 0x00000029, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxBroadcastCount */  \
  { 0x0000002A, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxDataCount */  \
  { 0x0000002B, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxDataPollCount */  \
  { 0x0000002C, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxBeaconCount */  \
  { 0x0000002D, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxBeaconRequestCount */  \
  { 0x0000002E, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxOtherCount */  \
  { 0x0000002F, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxAddressFilteredCount */  \
  { 0x00000030, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxDestAddrFilteredCount */  \
  { 0x00000031, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxDuplicatedCount */  \
  { 0x00000032, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxErrNoFrameCount */  \
  { 0x00000033, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxErrUnknownNeighborCount */  \
  { 0x00000034, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxErrInvalidSrcAddrCount */  \
  { 0x00000035, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxErrSecCount */  \
  { 0x00000036, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxErrFcsCount */  \
  { 0x00000037, ZAP_TYPE(INT32U), 4, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* RxErrOtherCount */  \
  { 0x0000003B, ZAP_TYPE(STRUCT), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* SecurityPolicy */  \
  { 0x0000003C, ZAP_TYPE(OCTET_STRING), 5, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* ChannelPage0Mask */  \
  { 0x0000003D, ZAP_TYPE(STRUCT), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* OperationalDatasetComponents */  \
  { 0x0000003E, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* ActiveNetworkFaultsList */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0x000F) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: AdministratorCommissioning (server) */ \
  { 0x00000000, ZAP_TYPE(ENUM8), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* WindowStatus */  \
  { 0x00000001, ZAP_TYPE(FABRIC_IDX), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* AdminFabricIndex */  \
  { 0x00000002, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_EMPTY_DEFAULT() }, /* AdminVendorId */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Operational Credentials (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* NOCs */  \
  { 0x00000001, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* Fabrics */  \
  { 0x00000002, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* SupportedFabrics */  \
  { 0x00000003, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* CommissionedFabrics */  \
  { 0x00000004, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* TrustedRootCertificates */  \
  { 0x00000005, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* CurrentFabricIndex */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 0, Cluster: Group Key Management (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE) | ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_EMPTY_DEFAULT() }, /* GroupKeyMap */  \
  { 0x00000001, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* GroupTable */  \
  { 0x00000002, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* MaxGroupsPerFabric */  \
  { 0x00000003, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* MaxGroupKeysPerFabric */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(1) }, /* ClusterRevision */  \
\
  /* Endpoint: 1, Cluster: Identify (server) */ \
  { 0x00000000, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_SIMPLE_DEFAULT(0x0000) }, /* identify time */  \
  { 0x00000001, ZAP_TYPE(ENUM8), 1, 0, ZAP_SIMPLE_DEFAULT(0x0) }, /* identify type */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(4) }, /* ClusterRevision */  \
\
  /* Endpoint: 1, Cluster: Groups (server) */ \
  { 0x00000000, ZAP_TYPE(BITMAP8), 1, 0, ZAP_EMPTY_DEFAULT() }, /* name support */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(4) }, /* ClusterRevision */  \
\
  /* Endpoint: 1, Cluster: On/Off (server) */ \
  { 0x00000000, ZAP_TYPE(BOOLEAN), 1, ZAP_ATTRIBUTE_MASK(TOKENIZE), ZAP_SIMPLE_DEFAULT(0x00) }, /* OnOff */  \
  { 0x00004000, ZAP_TYPE(BOOLEAN), 1, 0, ZAP_SIMPLE_DEFAULT(0x01) }, /* GlobalSceneControl */  \
  { 0x00004001, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_SIMPLE_DEFAULT(0x0000) }, /* OnTime */  \
  { 0x00004002, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_SIMPLE_DEFAULT(0x0000) }, /* OffWaitTime */  \
  { 0x00004003, ZAP_TYPE(ENUM8), 1, ZAP_ATTRIBUTE_MASK(MIN_MAX) | ZAP_ATTRIBUTE_MASK(TOKENIZE) | ZAP_ATTRIBUTE_MASK(WRITABLE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_MIN_MAX_DEFAULTS_INDEX(0) }, /* StartUpOnOff */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(1) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(4) }, /* ClusterRevision */  \
\
  /* Endpoint: 1, Cluster: Level Control (server) */ \
  { 0x00000000, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(TOKENIZE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_SIMPLE_DEFAULT(0x01) }, /* CurrentLevel */  \
  { 0x00000001, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(0x0000) }, /* RemainingTime */  \
  { 0x00000002, ZAP_TYPE(INT8U), 1, 0, ZAP_SIMPLE_DEFAULT(0x01) }, /* MinLevel */  \
  { 0x00000003, ZAP_TYPE(INT8U), 1, 0, ZAP_SIMPLE_DEFAULT(0xFE) }, /* MaxLevel */  \
  { 0x0000000F, ZAP_TYPE(BITMAP8), 1, ZAP_ATTRIBUTE_MASK(MIN_MAX) | ZAP_ATTRIBUTE_MASK(WRITABLE), ZAP_MIN_MAX_DEFAULTS_INDEX(1) }, /* Options */  \
  { 0x00000011, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(WRITABLE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_SIMPLE_DEFAULT(0xFF) }, /* OnLevel */  \
  { 0x00004000, ZAP_TYPE(INT8U), 1, ZAP_ATTRIBUTE_MASK(TOKENIZE) | ZAP_ATTRIBUTE_MASK(WRITABLE) | ZAP_ATTRIBUTE_MASK(NULLABLE), ZAP_SIMPLE_DEFAULT(254) }, /* StartUpCurrentLevel */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(3) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, 0, ZAP_SIMPLE_DEFAULT(5) }, /* ClusterRevision */  \
\
  /* Endpoint: 1, Cluster: Descriptor (server) */ \
  { 0x00000000, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* device list */  \
  { 0x00000001, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* server list */  \
  { 0x00000002, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* client list */  \
  { 0x00000003, ZAP_TYPE(ARRAY), 0, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* parts list */  \
  { 0x0000FFFC, ZAP_TYPE(BITMAP32), 4, 0, ZAP_SIMPLE_DEFAULT(0) }, /* FeatureMap */  \
  { 0x0000FFFD, ZAP_TYPE(INT16U), 2, ZAP_ATTRIBUTE_MASK(EXTERNAL_STORAGE), ZAP_EMPTY_DEFAULT() }, /* ClusterRevision */  \
}


// This is an array of EmberAfCluster structures.
#define ZAP_ATTRIBUTE_INDEX(index) (&generatedAttributes[index])

#define ZAP_GENERATED_COMMANDS_INDEX(index) ((chip::CommandId *) (&generatedCommands[index]))

// Cluster function static arrays
#define GENERATED_FUNCTION_ARRAYS   \
const EmberAfGenericClusterFunction chipFuncArrayBasicServer[] = {\
  (EmberAfGenericClusterFunction) emberAfBasicClusterServerInitCallback,\
};\
const EmberAfGenericClusterFunction chipFuncArrayIdentifyServer[] = {\
  (EmberAfGenericClusterFunction) emberAfIdentifyClusterServerInitCallback,\
  (EmberAfGenericClusterFunction) MatterIdentifyClusterServerAttributeChangedCallback,\
};\
const EmberAfGenericClusterFunction chipFuncArrayGroupsServer[] = {\
  (EmberAfGenericClusterFunction) emberAfGroupsClusterServerInitCallback,\
};\
const EmberAfGenericClusterFunction chipFuncArrayOnOffServer[] = {\
  (EmberAfGenericClusterFunction) emberAfOnOffClusterServerInitCallback,\
};\
const EmberAfGenericClusterFunction chipFuncArrayLevelControlServer[] = {\
  (EmberAfGenericClusterFunction) emberAfLevelControlClusterServerInitCallback,\
};\



// clang-format off
#define GENERATED_COMMANDS { \
  /* Endpoint: 0, Cluster: OTA Software Update Requestor (server) */\
  /*   AcceptedCommandList (index=0) */ \
  0x00000000 /* AnnounceOtaProvider */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: General Commissioning (server) */\
  /*   AcceptedCommandList (index=2) */ \
  0x00000000 /* ArmFailSafe */, \
  0x00000002 /* SetRegulatoryConfig */, \
  0x00000004 /* CommissioningComplete */, \
  chip::kInvalidCommandId /* end of list */, \
  /*   GeneratedCommandList (index=6)*/ \
  0x00000001 /* ArmFailSafeResponse */, \
  0x00000003 /* SetRegulatoryConfigResponse */, \
  0x00000005 /* CommissioningCompleteResponse */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: Network Commissioning (server) */\
  /*   AcceptedCommandList (index=10) */ \
  0x00000000 /* ScanNetworks */, \
  0x00000003 /* AddOrUpdateThreadNetwork */, \
  0x00000004 /* RemoveNetwork */, \
  0x00000006 /* ConnectNetwork */, \
  0x00000008 /* ReorderNetwork */, \
  chip::kInvalidCommandId /* end of list */, \
  /*   GeneratedCommandList (index=16)*/ \
  0x00000001 /* ScanNetworksResponse */, \
  0x00000005 /* NetworkConfigResponse */, \
  0x00000007 /* ConnectNetworkResponse */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: General Diagnostics (server) */\
  /*   AcceptedCommandList (index=20) */ \
  0x00000000 /* TestEventTrigger */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: Software Diagnostics (server) */\
  /*   AcceptedCommandList (index=22) */ \
  0x00000000 /* ResetWatermarks */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: Thread Network Diagnostics (server) */\
  /*   AcceptedCommandList (index=24) */ \
  0x00000000 /* ResetCounts */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: AdministratorCommissioning (server) */\
  /*   AcceptedCommandList (index=26) */ \
  0x00000000 /* OpenCommissioningWindow */, \
  0x00000002 /* RevokeCommissioning */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: Operational Credentials (server) */\
  /*   AcceptedCommandList (index=29) */ \
  0x00000000 /* AttestationRequest */, \
  0x00000002 /* CertificateChainRequest */, \
  0x00000004 /* CSRRequest */, \
  0x00000006 /* AddNOC */, \
  0x00000007 /* UpdateNOC */, \
  0x00000009 /* UpdateFabricLabel */, \
  0x0000000A /* RemoveFabric */, \
  0x0000000B /* AddTrustedRootCertificate */, \
  chip::kInvalidCommandId /* end of list */, \
  /*   GeneratedCommandList (index=38)*/ \
  0x00000001 /* AttestationResponse */, \
  0x00000003 /* CertificateChainResponse */, \
  0x00000005 /* CSRResponse */, \
  0x00000008 /* NOCResponse */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 0, Cluster: Group Key Management (server) */\
  /*   AcceptedCommandList (index=43) */ \
  0x00000000 /* KeySetWrite */, \
  0x00000001 /* KeySetRead */, \
  0x00000003 /* KeySetRemove */, \
  0x00000004 /* KeySetReadAllIndices */, \
  chip::kInvalidCommandId /* end of list */, \
  /*   GeneratedCommandList (index=48)*/ \
  0x00000002 /* KeySetReadResponse */, \
  0x00000005 /* KeySetReadAllIndicesResponse */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 1, Cluster: Identify (server) */\
  /*   AcceptedCommandList (index=51) */ \
  0x00000000 /* Identify */, \
  0x00000040 /* TriggerEffect */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 1, Cluster: Groups (server) */\
  /*   AcceptedCommandList (index=54) */ \
  0x00000000 /* AddGroup */, \
  0x00000001 /* ViewGroup */, \
  0x00000002 /* GetGroupMembership */, \
  0x00000003 /* RemoveGroup */, \
  0x00000004 /* RemoveAllGroups */, \
  0x00000005 /* AddGroupIfIdentifying */, \
  chip::kInvalidCommandId /* end of list */, \
  /*   GeneratedCommandList (index=61)*/ \
  0x00000000 /* AddGroupResponse */, \
  0x00000001 /* ViewGroupResponse */, \
  0x00000002 /* GetGroupMembershipResponse */, \
  0x00000003 /* RemoveGroupResponse */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 1, Cluster: On/Off (server) */\
  /*   AcceptedCommandList (index=66) */ \
  0x00000000 /* Off */, \
  0x00000001 /* On */, \
  0x00000002 /* Toggle */, \
  0x00000040 /* OffWithEffect */, \
  0x00000041 /* OnWithRecallGlobalScene */, \
  0x00000042 /* OnWithTimedOff */, \
  chip::kInvalidCommandId /* end of list */, \
  /* Endpoint: 1, Cluster: Level Control (server) */\
  /*   AcceptedCommandList (index=73) */ \
  0x00000000 /* MoveToLevel */, \
  0x00000001 /* Move */, \
  0x00000002 /* Step */, \
  0x00000003 /* Stop */, \
  0x00000004 /* MoveToLevelWithOnOff */, \
  0x00000005 /* MoveWithOnOff */, \
  0x00000006 /* StepWithOnOff */, \
  0x00000007 /* StopWithOnOff */, \
  chip::kInvalidCommandId /* end of list */, \
}

// clang-format on

#define ZAP_CLUSTER_MASK(mask) CLUSTER_MASK_ ## mask
#define GENERATED_CLUSTER_COUNT 18


// clang-format off
#define GENERATED_CLUSTERS { \
  { \
      /* Endpoint: 0, Cluster: Descriptor (server) */ \
      .clusterId = 0x0000001D,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(0), \
      .attributeCount = 6, \
      .clusterSize = 4, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = nullptr ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Access Control (server) */ \
      .clusterId = 0x0000001F,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(6), \
      .attributeCount = 6, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = nullptr ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Basic (server) */ \
      .clusterId = 0x00000028,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(12), \
      .attributeCount = 14, \
      .clusterSize = 39, \
      .mask = ZAP_CLUSTER_MASK(SERVER) | ZAP_CLUSTER_MASK(INIT_FUNCTION), \
      .functions = chipFuncArrayBasicServer, \
      .acceptedCommandList = nullptr ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: OTA Software Update Provider (client) */ \
      .clusterId = 0x00000029,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(26), \
      .attributeCount = 0, \
      .clusterSize = 0, \
      .mask = ZAP_CLUSTER_MASK(CLIENT), \
      .functions = NULL, \
      .acceptedCommandList = nullptr ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: OTA Software Update Requestor (server) */ \
      .clusterId = 0x0000002A,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(26), \
      .attributeCount = 6, \
      .clusterSize = 9, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 0 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: General Commissioning (server) */ \
      .clusterId = 0x00000030,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(32), \
      .attributeCount = 7, \
      .clusterSize = 14, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 2 ) ,\
      .generatedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 6 ) ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Network Commissioning (server) */ \
      .clusterId = 0x00000031,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(39), \
      .attributeCount = 10, \
      .clusterSize = 48, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 10 ) ,\
      .generatedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 16 ) ,\
    },\
  { \
      /* Endpoint: 0, Cluster: General Diagnostics (server) */ \
      .clusterId = 0x00000033,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(49), \
      .attributeCount = 5, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 20 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Software Diagnostics (server) */ \
      .clusterId = 0x00000034,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(54), \
      .attributeCount = 6, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 22 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Thread Network Diagnostics (server) */ \
      .clusterId = 0x00000035,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(60), \
      .attributeCount = 62, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 24 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: AdministratorCommissioning (server) */ \
      .clusterId = 0x0000003C,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(122), \
      .attributeCount = 5, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 26 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Operational Credentials (server) */ \
      .clusterId = 0x0000003E,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(127), \
      .attributeCount = 8, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 29 ) ,\
      .generatedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 38 ) ,\
    },\
  { \
      /* Endpoint: 0, Cluster: Group Key Management (server) */ \
      .clusterId = 0x0000003F,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(135), \
      .attributeCount = 6, \
      .clusterSize = 6, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 43 ) ,\
      .generatedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 48 ) ,\
    },\
  { \
      /* Endpoint: 1, Cluster: Identify (server) */ \
      .clusterId = 0x00000003,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(141), \
      .attributeCount = 4, \
      .clusterSize = 9, \
      .mask = ZAP_CLUSTER_MASK(SERVER) | ZAP_CLUSTER_MASK(INIT_FUNCTION) | ZAP_CLUSTER_MASK(ATTRIBUTE_CHANGED_FUNCTION), \
      .functions = chipFuncArrayIdentifyServer, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 51 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 1, Cluster: Groups (server) */ \
      .clusterId = 0x00000004,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(145), \
      .attributeCount = 3, \
      .clusterSize = 7, \
      .mask = ZAP_CLUSTER_MASK(SERVER) | ZAP_CLUSTER_MASK(INIT_FUNCTION), \
      .functions = chipFuncArrayGroupsServer, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 54 ) ,\
      .generatedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 61 ) ,\
    },\
  { \
      /* Endpoint: 1, Cluster: On/Off (server) */ \
      .clusterId = 0x00000006,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(148), \
      .attributeCount = 7, \
      .clusterSize = 13, \
      .mask = ZAP_CLUSTER_MASK(SERVER) | ZAP_CLUSTER_MASK(INIT_FUNCTION), \
      .functions = chipFuncArrayOnOffServer, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 66 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 1, Cluster: Level Control (server) */ \
      .clusterId = 0x00000008,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(155), \
      .attributeCount = 9, \
      .clusterSize = 14, \
      .mask = ZAP_CLUSTER_MASK(SERVER) | ZAP_CLUSTER_MASK(INIT_FUNCTION), \
      .functions = chipFuncArrayLevelControlServer, \
      .acceptedCommandList = ZAP_GENERATED_COMMANDS_INDEX( 73 ) ,\
      .generatedCommandList = nullptr ,\
    },\
  { \
      /* Endpoint: 1, Cluster: Descriptor (server) */ \
      .clusterId = 0x0000001D,  \
      .attributes = ZAP_ATTRIBUTE_INDEX(164), \
      .attributeCount = 6, \
      .clusterSize = 4, \
      .mask = ZAP_CLUSTER_MASK(SERVER), \
      .functions = NULL, \
      .acceptedCommandList = nullptr ,\
      .generatedCommandList = nullptr ,\
    },\
}

// clang-format on

#define ZAP_CLUSTER_INDEX(index) (&generatedClusters[index])

#define ZAP_FIXED_ENDPOINT_DATA_VERSION_COUNT 17

// This is an array of EmberAfEndpointType structures.
#define GENERATED_ENDPOINT_TYPES { \
  { ZAP_CLUSTER_INDEX(0), 13, 156 }, \
  { ZAP_CLUSTER_INDEX(13), 5, 47 }, \
}



// Largest attribute size is needed for various buffers
#define ATTRIBUTE_LARGEST (66)

static_assert(ATTRIBUTE_LARGEST <= CHIP_CONFIG_MAX_ATTRIBUTE_STORE_ELEMENT_SIZE,
              "ATTRIBUTE_LARGEST larger than expected");

// Total size of singleton attributes
#define ATTRIBUTE_SINGLETONS_SIZE (35)

// Total size of attribute storage
#define ATTRIBUTE_MAX_SIZE (203)

// Number of fixed endpoints
#define FIXED_ENDPOINT_COUNT (2)

// Array of endpoints that are supported, the data inside
// the array is the endpoint number.
#define FIXED_ENDPOINT_ARRAY { 0x0000, 0x0001 }

// Array of profile ids
#define FIXED_PROFILE_IDS { 0x0103, 0x0103 }

// Array of device types
#define FIXED_DEVICE_TYPES {{0x0016,1},{0x0100,1}}

// Array of device type offsets
#define FIXED_DEVICE_TYPE_OFFSETS { 0,1}

// Array of device type lengths
#define FIXED_DEVICE_TYPE_LENGTHS { 1,1}

// Array of endpoint types supported on each endpoint
#define FIXED_ENDPOINT_TYPES { 0, 1 }

// Array of networks supported on each endpoint
#define FIXED_NETWORKS { 0, 0 }

