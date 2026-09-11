#ifndef NETWORK_ENGINE_H
#define NETWORK_ENGINE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NE_OK                         0
#define NE_ERROR_INVALID_ARGUMENT    -1
#define NE_ERROR_INVALID_HANDLE      -2
#define NE_ERROR_NOT_INITIALIZED     -3
#define NE_ERROR_ALREADY_INITIALIZED -4
#define NE_ERROR_BACKEND_UNAVAILABLE -5
#define NE_ERROR_QUEUE_FULL          -6
#define NE_ERROR_BUFFER_EXHAUSTED    -7
#define NE_ERROR_ACTION_FAILED       -8
#define NE_ERROR_SHUTDOWN            -9
#define NE_ERROR_INTERNAL            -10

typedef struct NePacketHandle { uint64_t id; } NePacketHandle;
typedef struct NePacketDescriptor {
    uint64_t packet_handle;
    const void *data;
    uint32_t len;
    int32_t backend_source;
    int32_t direction;
} NePacketDescriptor;
typedef struct NeBackendInfo { char name[64]; int32_t status; uint32_t capability_count; } NeBackendInfo;
typedef struct NePacketAction { int32_t action; } NePacketAction;

enum { NE_PACKET_ACTION_PASS = 0, NE_PACKET_ACTION_DROP = 1, NE_PACKET_ACTION_MODIFY = 2, NE_PACKET_ACTION_REINJECT = 3 };

typedef struct NeStatistics {
    uint64_t packets_received;
    uint64_t bytes_received;
    uint64_t packets_dropped;
    uint64_t packets_forwarded;
    uint64_t flows_active;
} NeStatistics;

typedef struct NeInitConfig {
    uint32_t queue_capacity;
    uint32_t pool_max_size;
    uint32_t buffer_capacity;
    uint32_t max_flows;
} NeInitConfig;

/* Host-owned Gateway/NAT/Routing/Forwarding configuration. */
typedef struct NeGatewayConfig {
    uint32_t enabled;
    uint32_t default_decision;          /* 0 deny, 1 allow */
    uint32_t nat_enabled;
    uint32_t nat_mode;                  /* 0 disabled, 1 source, 2 destination, 3 masquerade */
    uint32_t external_interface_id;
    uint32_t forwarding_enabled;
    uint32_t ingress_interface_id;
    uint32_t egress_interface_id;
    uint32_t routing_table_id;
    uint32_t preferred_interface_id;
} NeGatewayConfig;

enum {
    NE_BACKEND_DISABLED = 0, NE_BACKEND_STARTING = 1, NE_BACKEND_RUNNING = 2,
    NE_BACKEND_DEGRADED = 3, NE_BACKEND_FAILED = 4, NE_BACKEND_STOPPING = 5,
    NE_BACKEND_STOPPED = 6
};
enum { NE_BACKEND_SOURCE_WINDIVERT = 0, NE_BACKEND_SOURCE_NPCAP = 1, NE_BACKEND_SOURCE_WFP = 2 };
enum { NE_DIRECTION_INBOUND = 0, NE_DIRECTION_OUTBOUND = 1 };
enum {
    NE_CAP_CAPTURE = 0, NE_CAP_INTERCEPTION = 1, NE_CAP_FILTERING = 2, NE_CAP_INSPECTION = 3,
    NE_CAP_DIRECTION = 4, NE_CAP_IPV4 = 10, NE_CAP_IPV6 = 11, NE_CAP_TCP = 12, NE_CAP_UDP = 13,
    NE_CAP_ICMP = 14, NE_CAP_ICMPV6 = 15, NE_CAP_NETWORK_LAYER = 20, NE_CAP_ADDRESS_METADATA = 21,
    NE_CAP_MODIFICATION = 30, NE_CAP_DROP = 31, NE_CAP_PASS = 32, NE_CAP_REINJECTION = 33,
    NE_CAP_QUEUE_CONTROL = 40, NE_CAP_HANDLE_LIFETIME = 41, NE_CAP_ERROR_REPORTING = 42,
    NE_CAP_L2_CAPTURE = 50, NE_CAP_RAW_ETHERNET = 51, NE_CAP_ADAPTER_ENUMERATION = 52,
    NE_CAP_WFP_ENGINE_ACCESS = 60, NE_CAP_WFP_FILTERS = 61, NE_CAP_WFP_LAYERS = 62,
    NE_CAP_WFP_FLOWS = 63, NE_CAP_INTERFACE_INFO = 70, NE_CAP_ROUTE_INFO = 71,
    NE_CAP_NEIGHBOR_INFO = 72, NE_CAP_GATEWAY_INFO = 73, NE_CAP_DIAGNOSTICS = 80,
    NE_CAP_TELEMETRY = 81
};
enum { NE_FAILOVER_NONE = 0, NE_FAILOVER_PREFER_PRIMARY = 1, NE_FAILOVER_PREFER_HEALTHY = 2, NE_FAILOVER_ROUND_ROBIN = 3 };

int32_t network_init(const NeInitConfig *config);
int32_t network_shutdown(void);
int32_t network_is_initialized(void);

uint32_t backend_count(void);
int32_t backend_list(char *buffer, uint32_t max_count, uint32_t name_len);
int32_t backend_status(const char *name);
int32_t backend_set_status(const char *name, int32_t status);
int32_t backend_health(const char *name);
uint32_t backend_capability_count(const char *name);
int32_t backend_capabilities(const char *name, char *buffer, uint32_t capacity);
int32_t backend_runtime_info(const char *name, char *buffer, uint32_t capacity);
int32_t backend_manager_stats(char *buffer, uint32_t capacity);
int32_t backend_failover_policy(void);
int32_t backend_set_failover_policy(int32_t policy);
int32_t backend_select(int32_t capability, char *buffer, uint32_t capacity);
int32_t backend_find_capable(int32_t capability, int32_t healthy_only, char *buffer, uint32_t capacity);
int32_t backend_record_success(const char *name);
int32_t backend_record_failure(const char *name, int32_t native_error);
int32_t backend_failover_capture(const char *name, char *buffer, uint32_t capacity);
int32_t backend_failover_reinjection(const char *name, char *buffer, uint32_t capacity);

int32_t capture_start(void);
int32_t capture_stop(void);
int32_t packet_inject(const void *data, uint32_t len, int32_t backend_source, int32_t direction, uint32_t interface_id);
int32_t packet_read(NePacketDescriptor *out);
int32_t packet_release(uint64_t packet_handle);
int32_t packet_pass(uint64_t packet_handle);
int32_t packet_drop(uint64_t packet_handle);
int32_t packet_modify(uint64_t packet_handle, const void *data, uint32_t len);
int32_t packet_reinject(uint64_t packet_handle);
int32_t packet_action(uint64_t packet_handle, int32_t action);

int32_t network_stats(NeStatistics *out);
int32_t engine_statistics(NeStatistics *out);
uint32_t bus_queue_depth(void);
uint32_t bus_queue_capacity(void);
uint32_t pool_allocated_count(void);
uint32_t pool_available_count(void);
uint32_t flow_count(void);
int32_t flow_get(char *buffer, uint32_t capacity);
int32_t flow_stats(const char *key, uint64_t *packets, uint64_t *bytes);
uint32_t flow_clear_expired(void);
int32_t interface_list(char *buffer, uint32_t capacity);
int32_t route_list(char *buffer, uint32_t capacity);
int32_t neighbor_list(char *buffer, uint32_t capacity);
int32_t interface_info(uint32_t interface_id, char *buffer, uint32_t capacity);

int32_t gateway_config(const NeGatewayConfig *config);
int32_t gateway_start(void);
int32_t gateway_stop(void);
int32_t gateway_status(void);
int32_t capability_check(const char *backend_name, int32_t capability);
int32_t engine_version(char *buffer, uint32_t capacity);
int32_t last_error_message(char *buffer, uint32_t capacity);

#ifdef __cplusplus
}
#endif
#endif /* NETWORK_ENGINE_H */
