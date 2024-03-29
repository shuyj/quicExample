// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: cached_network_parameters.proto

#ifndef PROTOBUF_INCLUDED_cached_5fnetwork_5fparameters_2eproto
#define PROTOBUF_INCLUDED_cached_5fnetwork_5fparameters_2eproto

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3005000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3005001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/message_lite.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/generated_enum_util.h>
// @@protoc_insertion_point(includes)
#include "net/base/net_export.h"
#define PROTOBUF_INTERNAL_EXPORT_protobuf_cached_5fnetwork_5fparameters_2eproto NET_EXPORT_PRIVATE

namespace protobuf_cached_5fnetwork_5fparameters_2eproto {
// Internal implementation detail -- do not use these members.
struct NET_EXPORT_PRIVATE TableStruct {
static const ::google::protobuf::internal::ParseTableField entries[];
static const ::google::protobuf::internal::AuxillaryParseTableField aux[];
static const ::google::protobuf::internal::ParseTable schema[1];
static const ::google::protobuf::internal::FieldMetadata field_metadata[];
static const ::google::protobuf::internal::SerializationTable serialization_table[];
static const ::google::protobuf::uint32 offsets[];
};
}  // namespace protobuf_cached_5fnetwork_5fparameters_2eproto
namespace quic {
class CachedNetworkParameters;
class CachedNetworkParametersDefaultTypeInternal;
NET_EXPORT_PRIVATE extern CachedNetworkParametersDefaultTypeInternal _CachedNetworkParameters_default_instance_;
}  // namespace quic
namespace google {
namespace protobuf {
template<> NET_EXPORT_PRIVATE ::quic::CachedNetworkParameters* Arena::CreateMaybeMessage<::quic::CachedNetworkParameters>(Arena*);
}  // namespace protobuf
}  // namespace google
namespace quic {

enum CachedNetworkParameters_PreviousConnectionState {
CachedNetworkParameters_PreviousConnectionState_SLOW_START = 0,
CachedNetworkParameters_PreviousConnectionState_CONGESTION_AVOIDANCE = 1
};
NET_EXPORT_PRIVATE bool CachedNetworkParameters_PreviousConnectionState_IsValid(int value);
const CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_MIN = CachedNetworkParameters_PreviousConnectionState_SLOW_START;
const CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_MAX = CachedNetworkParameters_PreviousConnectionState_CONGESTION_AVOIDANCE;
const int CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_ARRAYSIZE = CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_MAX + 1;

// ===================================================================

class NET_EXPORT_PRIVATE CachedNetworkParameters : public ::google::protobuf::MessageLite /* @@protoc_insertion_point(class_definition:quic.CachedNetworkParameters) */ {
public:
CachedNetworkParameters();
virtual ~CachedNetworkParameters();

CachedNetworkParameters(const CachedNetworkParameters& from);

inline CachedNetworkParameters& operator=(const CachedNetworkParameters& from) {
CopyFrom(from);
return *this;
}
#if LANG_CXX11
CachedNetworkParameters(CachedNetworkParameters&& from) noexcept
: CachedNetworkParameters() {
*this = ::std::move(from);
}

inline CachedNetworkParameters& operator=(CachedNetworkParameters&& from) noexcept {
if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
if (this != &from) InternalSwap(&from);
} else {
CopyFrom(from);
}
return *this;
}
#endif
inline const ::std::string& unknown_fields() const {
return _internal_metadata_.unknown_fields();
}
inline ::std::string* mutable_unknown_fields() {
return _internal_metadata_.mutable_unknown_fields();
}

static const CachedNetworkParameters& default_instance();

static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
static inline const CachedNetworkParameters* internal_default_instance() {
return reinterpret_cast<const CachedNetworkParameters*>(
&_CachedNetworkParameters_default_instance_);
}
static constexpr int kIndexInFileMessages =
0;

GOOGLE_ATTRIBUTE_NOINLINE void Swap(CachedNetworkParameters* other);
friend void swap(CachedNetworkParameters& a, CachedNetworkParameters& b) {
a.Swap(&b);
}

// implements Message ----------------------------------------------

inline CachedNetworkParameters* New() const final {
return CreateMaybeMessage<CachedNetworkParameters>(NULL);
}

CachedNetworkParameters* New(::google::protobuf::Arena* arena) const final {
return CreateMaybeMessage<CachedNetworkParameters>(arena);
}
void CheckTypeAndMergeFrom(const ::google::protobuf::MessageLite& from)
final;
void CopyFrom(const CachedNetworkParameters& from);
void MergeFrom(const CachedNetworkParameters& from);
void Clear() final;
bool IsInitialized() const final;

size_t ByteSizeLong() const final;
bool MergePartialFromCodedStream(
::google::protobuf::io::CodedInputStream* input) final;
void SerializeWithCachedSizes(
::google::protobuf::io::CodedOutputStream* output) const final;
void DiscardUnknownFields();
int GetCachedSize() const final { return _cached_size_.Get(); }

private:
void SharedCtor();
void SharedDtor();
void SetCachedSize(int size) const;
void InternalSwap(CachedNetworkParameters* other);
private:
inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
return NULL;
}
inline void* MaybeArenaPtr() const {
return NULL;
}
public:

::std::string GetTypeName() const final;

// nested types ----------------------------------------------------

typedef CachedNetworkParameters_PreviousConnectionState PreviousConnectionState;
static const PreviousConnectionState SLOW_START =
CachedNetworkParameters_PreviousConnectionState_SLOW_START;
static const PreviousConnectionState CONGESTION_AVOIDANCE =
CachedNetworkParameters_PreviousConnectionState_CONGESTION_AVOIDANCE;
static inline bool PreviousConnectionState_IsValid(int value) {
return CachedNetworkParameters_PreviousConnectionState_IsValid(value);
}
static const PreviousConnectionState PreviousConnectionState_MIN =
CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_MIN;
static const PreviousConnectionState PreviousConnectionState_MAX =
CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_MAX;
static const int PreviousConnectionState_ARRAYSIZE =
CachedNetworkParameters_PreviousConnectionState_PreviousConnectionState_ARRAYSIZE;

// accessors -------------------------------------------------------

// optional string serving_region = 1;
bool has_serving_region() const;
void clear_serving_region();
static const int kServingRegionFieldNumber = 1;
const ::std::string& serving_region() const;
void set_serving_region(const ::std::string& value);
#if LANG_CXX11
void set_serving_region(::std::string&& value);
#endif
void set_serving_region(const char* value);
void set_serving_region(const char* value, size_t size);
::std::string* mutable_serving_region();
::std::string* release_serving_region();
void set_allocated_serving_region(::std::string* serving_region);

// optional int32 bandwidth_estimate_bytes_per_second = 2;
bool has_bandwidth_estimate_bytes_per_second() const;
void clear_bandwidth_estimate_bytes_per_second();
static const int kBandwidthEstimateBytesPerSecondFieldNumber = 2;
::google::protobuf::int32 bandwidth_estimate_bytes_per_second() const;
void set_bandwidth_estimate_bytes_per_second(::google::protobuf::int32 value);

// optional int32 min_rtt_ms = 3;
bool has_min_rtt_ms() const;
void clear_min_rtt_ms();
static const int kMinRttMsFieldNumber = 3;
::google::protobuf::int32 min_rtt_ms() const;
void set_min_rtt_ms(::google::protobuf::int32 value);

// optional int32 previous_connection_state = 4;
bool has_previous_connection_state() const;
void clear_previous_connection_state();
static const int kPreviousConnectionStateFieldNumber = 4;
::google::protobuf::int32 previous_connection_state() const;
void set_previous_connection_state(::google::protobuf::int32 value);

// optional int32 max_bandwidth_estimate_bytes_per_second = 5;
bool has_max_bandwidth_estimate_bytes_per_second() const;
void clear_max_bandwidth_estimate_bytes_per_second();
static const int kMaxBandwidthEstimateBytesPerSecondFieldNumber = 5;
::google::protobuf::int32 max_bandwidth_estimate_bytes_per_second() const;
void set_max_bandwidth_estimate_bytes_per_second(::google::protobuf::int32 value);

// optional int64 max_bandwidth_timestamp_seconds = 6;
bool has_max_bandwidth_timestamp_seconds() const;
void clear_max_bandwidth_timestamp_seconds();
static const int kMaxBandwidthTimestampSecondsFieldNumber = 6;
::google::protobuf::int64 max_bandwidth_timestamp_seconds() const;
void set_max_bandwidth_timestamp_seconds(::google::protobuf::int64 value);

// optional int64 timestamp = 7;
bool has_timestamp() const;
void clear_timestamp();
static const int kTimestampFieldNumber = 7;
::google::protobuf::int64 timestamp() const;
void set_timestamp(::google::protobuf::int64 value);

// @@protoc_insertion_point(class_scope:quic.CachedNetworkParameters)
private:
void set_has_serving_region();
void clear_has_serving_region();
void set_has_bandwidth_estimate_bytes_per_second();
void clear_has_bandwidth_estimate_bytes_per_second();
void set_has_max_bandwidth_estimate_bytes_per_second();
void clear_has_max_bandwidth_estimate_bytes_per_second();
void set_has_max_bandwidth_timestamp_seconds();
void clear_has_max_bandwidth_timestamp_seconds();
void set_has_min_rtt_ms();
void clear_has_min_rtt_ms();
void set_has_previous_connection_state();
void clear_has_previous_connection_state();
void set_has_timestamp();
void clear_has_timestamp();

::google::protobuf::internal::InternalMetadataWithArenaLite _internal_metadata_;
::google::protobuf::internal::HasBits<1> _has_bits_;
mutable ::google::protobuf::internal::CachedSize _cached_size_;
::google::protobuf::internal::ArenaStringPtr serving_region_;
::google::protobuf::int32 bandwidth_estimate_bytes_per_second_;
::google::protobuf::int32 min_rtt_ms_;
::google::protobuf::int32 previous_connection_state_;
::google::protobuf::int32 max_bandwidth_estimate_bytes_per_second_;
::google::protobuf::int64 max_bandwidth_timestamp_seconds_;
::google::protobuf::int64 timestamp_;
friend struct ::protobuf_cached_5fnetwork_5fparameters_2eproto::TableStruct;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// CachedNetworkParameters

// optional string serving_region = 1;
inline bool CachedNetworkParameters::has_serving_region() const {
return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void CachedNetworkParameters::set_has_serving_region() {
_has_bits_[0] |= 0x00000001u;
}
inline void CachedNetworkParameters::clear_has_serving_region() {
_has_bits_[0] &= ~0x00000001u;
}
inline void CachedNetworkParameters::clear_serving_region() {
serving_region_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
clear_has_serving_region();
}
inline const ::std::string& CachedNetworkParameters::serving_region() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.serving_region)
return serving_region_.GetNoArena();
}
inline void CachedNetworkParameters::set_serving_region(const ::std::string& value) {
set_has_serving_region();
serving_region_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.serving_region)
}
#if LANG_CXX11
inline void CachedNetworkParameters::set_serving_region(::std::string&& value) {
set_has_serving_region();
serving_region_.SetNoArena(
&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
// @@protoc_insertion_point(field_set_rvalue:quic.CachedNetworkParameters.serving_region)
}
#endif
inline void CachedNetworkParameters::set_serving_region(const char* value) {
GOOGLE_DCHECK(value != NULL);
set_has_serving_region();
serving_region_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
// @@protoc_insertion_point(field_set_char:quic.CachedNetworkParameters.serving_region)
}
inline void CachedNetworkParameters::set_serving_region(const char* value, size_t size) {
set_has_serving_region();
serving_region_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
::std::string(reinterpret_cast<const char*>(value), size));
// @@protoc_insertion_point(field_set_pointer:quic.CachedNetworkParameters.serving_region)
}
inline ::std::string* CachedNetworkParameters::mutable_serving_region() {
set_has_serving_region();
// @@protoc_insertion_point(field_mutable:quic.CachedNetworkParameters.serving_region)
return serving_region_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* CachedNetworkParameters::release_serving_region() {
// @@protoc_insertion_point(field_release:quic.CachedNetworkParameters.serving_region)
if (!has_serving_region()) {
return NULL;
}
clear_has_serving_region();
return serving_region_.ReleaseNonDefaultNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void CachedNetworkParameters::set_allocated_serving_region(::std::string* serving_region) {
if (serving_region != NULL) {
set_has_serving_region();
} else {
clear_has_serving_region();
}
serving_region_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), serving_region);
// @@protoc_insertion_point(field_set_allocated:quic.CachedNetworkParameters.serving_region)
}

// optional int32 bandwidth_estimate_bytes_per_second = 2;
inline bool CachedNetworkParameters::has_bandwidth_estimate_bytes_per_second() const {
return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void CachedNetworkParameters::set_has_bandwidth_estimate_bytes_per_second() {
_has_bits_[0] |= 0x00000002u;
}
inline void CachedNetworkParameters::clear_has_bandwidth_estimate_bytes_per_second() {
_has_bits_[0] &= ~0x00000002u;
}
inline void CachedNetworkParameters::clear_bandwidth_estimate_bytes_per_second() {
bandwidth_estimate_bytes_per_second_ = 0;
clear_has_bandwidth_estimate_bytes_per_second();
}
inline ::google::protobuf::int32 CachedNetworkParameters::bandwidth_estimate_bytes_per_second() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.bandwidth_estimate_bytes_per_second)
return bandwidth_estimate_bytes_per_second_;
}
inline void CachedNetworkParameters::set_bandwidth_estimate_bytes_per_second(::google::protobuf::int32 value) {
set_has_bandwidth_estimate_bytes_per_second();
bandwidth_estimate_bytes_per_second_ = value;
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.bandwidth_estimate_bytes_per_second)
}

// optional int32 max_bandwidth_estimate_bytes_per_second = 5;
inline bool CachedNetworkParameters::has_max_bandwidth_estimate_bytes_per_second() const {
return (_has_bits_[0] & 0x00000010u) != 0;
}
inline void CachedNetworkParameters::set_has_max_bandwidth_estimate_bytes_per_second() {
_has_bits_[0] |= 0x00000010u;
}
inline void CachedNetworkParameters::clear_has_max_bandwidth_estimate_bytes_per_second() {
_has_bits_[0] &= ~0x00000010u;
}
inline void CachedNetworkParameters::clear_max_bandwidth_estimate_bytes_per_second() {
max_bandwidth_estimate_bytes_per_second_ = 0;
clear_has_max_bandwidth_estimate_bytes_per_second();
}
inline ::google::protobuf::int32 CachedNetworkParameters::max_bandwidth_estimate_bytes_per_second() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.max_bandwidth_estimate_bytes_per_second)
return max_bandwidth_estimate_bytes_per_second_;
}
inline void CachedNetworkParameters::set_max_bandwidth_estimate_bytes_per_second(::google::protobuf::int32 value) {
set_has_max_bandwidth_estimate_bytes_per_second();
max_bandwidth_estimate_bytes_per_second_ = value;
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.max_bandwidth_estimate_bytes_per_second)
}

// optional int64 max_bandwidth_timestamp_seconds = 6;
inline bool CachedNetworkParameters::has_max_bandwidth_timestamp_seconds() const {
return (_has_bits_[0] & 0x00000020u) != 0;
}
inline void CachedNetworkParameters::set_has_max_bandwidth_timestamp_seconds() {
_has_bits_[0] |= 0x00000020u;
}
inline void CachedNetworkParameters::clear_has_max_bandwidth_timestamp_seconds() {
_has_bits_[0] &= ~0x00000020u;
}
inline void CachedNetworkParameters::clear_max_bandwidth_timestamp_seconds() {
max_bandwidth_timestamp_seconds_ = GOOGLE_LONGLONG(0);
clear_has_max_bandwidth_timestamp_seconds();
}
inline ::google::protobuf::int64 CachedNetworkParameters::max_bandwidth_timestamp_seconds() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.max_bandwidth_timestamp_seconds)
return max_bandwidth_timestamp_seconds_;
}
inline void CachedNetworkParameters::set_max_bandwidth_timestamp_seconds(::google::protobuf::int64 value) {
set_has_max_bandwidth_timestamp_seconds();
max_bandwidth_timestamp_seconds_ = value;
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.max_bandwidth_timestamp_seconds)
}

// optional int32 min_rtt_ms = 3;
inline bool CachedNetworkParameters::has_min_rtt_ms() const {
return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void CachedNetworkParameters::set_has_min_rtt_ms() {
_has_bits_[0] |= 0x00000004u;
}
inline void CachedNetworkParameters::clear_has_min_rtt_ms() {
_has_bits_[0] &= ~0x00000004u;
}
inline void CachedNetworkParameters::clear_min_rtt_ms() {
min_rtt_ms_ = 0;
clear_has_min_rtt_ms();
}
inline ::google::protobuf::int32 CachedNetworkParameters::min_rtt_ms() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.min_rtt_ms)
return min_rtt_ms_;
}
inline void CachedNetworkParameters::set_min_rtt_ms(::google::protobuf::int32 value) {
set_has_min_rtt_ms();
min_rtt_ms_ = value;
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.min_rtt_ms)
}

// optional int32 previous_connection_state = 4;
inline bool CachedNetworkParameters::has_previous_connection_state() const {
return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void CachedNetworkParameters::set_has_previous_connection_state() {
_has_bits_[0] |= 0x00000008u;
}
inline void CachedNetworkParameters::clear_has_previous_connection_state() {
_has_bits_[0] &= ~0x00000008u;
}
inline void CachedNetworkParameters::clear_previous_connection_state() {
previous_connection_state_ = 0;
clear_has_previous_connection_state();
}
inline ::google::protobuf::int32 CachedNetworkParameters::previous_connection_state() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.previous_connection_state)
return previous_connection_state_;
}
inline void CachedNetworkParameters::set_previous_connection_state(::google::protobuf::int32 value) {
set_has_previous_connection_state();
previous_connection_state_ = value;
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.previous_connection_state)
}

// optional int64 timestamp = 7;
inline bool CachedNetworkParameters::has_timestamp() const {
return (_has_bits_[0] & 0x00000040u) != 0;
}
inline void CachedNetworkParameters::set_has_timestamp() {
_has_bits_[0] |= 0x00000040u;
}
inline void CachedNetworkParameters::clear_has_timestamp() {
_has_bits_[0] &= ~0x00000040u;
}
inline void CachedNetworkParameters::clear_timestamp() {
timestamp_ = GOOGLE_LONGLONG(0);
clear_has_timestamp();
}
inline ::google::protobuf::int64 CachedNetworkParameters::timestamp() const {
// @@protoc_insertion_point(field_get:quic.CachedNetworkParameters.timestamp)
return timestamp_;
}
inline void CachedNetworkParameters::set_timestamp(::google::protobuf::int64 value) {
set_has_timestamp();
timestamp_ = value;
// @@protoc_insertion_point(field_set:quic.CachedNetworkParameters.timestamp)
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace quic

namespace google {
namespace protobuf {

template <> struct is_proto_enum< ::quic::CachedNetworkParameters_PreviousConnectionState> : ::std::true_type {};

}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_INCLUDED_cached_5fnetwork_5fparameters_2eproto
