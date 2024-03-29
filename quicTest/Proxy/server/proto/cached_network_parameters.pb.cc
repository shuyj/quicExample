// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: cached_network_parameters.proto

#include "cached_network_parameters.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// This is a temporary google only hack
#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
#include "third_party/protobuf/version.h"
#endif
// @@protoc_insertion_point(includes)

namespace quic {
class CachedNetworkParametersDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<CachedNetworkParameters>
      _instance;
} _CachedNetworkParameters_default_instance_;
}  // namespace quic
namespace protobuf_cached_5fnetwork_5fparameters_2eproto {
static void InitDefaultsCachedNetworkParameters() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::quic::_CachedNetworkParameters_default_instance_;
    new (ptr) ::quic::CachedNetworkParameters();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::quic::CachedNetworkParameters::InitAsDefaultInstance();
}

NET_EXPORT_PRIVATE ::google::protobuf::internal::SCCInfo<0> scc_info_CachedNetworkParameters =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsCachedNetworkParameters}, {}};

void InitDefaults() {
  ::google::protobuf::internal::InitSCC(&scc_info_CachedNetworkParameters.base);
}

}  // namespace protobuf_cached_5fnetwork_5fparameters_2eproto
namespace quic {
bool CachedNetworkParameters_PreviousConnectionState_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
      return true;
    default:
      return false;
  }
}

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::SLOW_START;
const CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::CONGESTION_AVOIDANCE;
const CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::PreviousConnectionState_MIN;
const CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::PreviousConnectionState_MAX;
const int CachedNetworkParameters::PreviousConnectionState_ARRAYSIZE;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

// ===================================================================

void CachedNetworkParameters::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int CachedNetworkParameters::kServingRegionFieldNumber;
const int CachedNetworkParameters::kBandwidthEstimateBytesPerSecondFieldNumber;
const int CachedNetworkParameters::kMaxBandwidthEstimateBytesPerSecondFieldNumber;
const int CachedNetworkParameters::kMaxBandwidthTimestampSecondsFieldNumber;
const int CachedNetworkParameters::kMinRttMsFieldNumber;
const int CachedNetworkParameters::kPreviousConnectionStateFieldNumber;
const int CachedNetworkParameters::kTimestampFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

CachedNetworkParameters::CachedNetworkParameters()
  : ::google::protobuf::MessageLite(), _internal_metadata_(NULL) {
  ::google::protobuf::internal::InitSCC(
      &protobuf_cached_5fnetwork_5fparameters_2eproto::scc_info_CachedNetworkParameters.base);
  SharedCtor();
  // @@protoc_insertion_point(constructor:quic.CachedNetworkParameters)
}
CachedNetworkParameters::CachedNetworkParameters(const CachedNetworkParameters& from)
  : ::google::protobuf::MessageLite(),
      _internal_metadata_(NULL),
      _has_bits_(from._has_bits_) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  serving_region_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.has_serving_region()) {
    serving_region_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.serving_region_);
  }
  ::memcpy(&bandwidth_estimate_bytes_per_second_, &from.bandwidth_estimate_bytes_per_second_,
    static_cast<size_t>(reinterpret_cast<char*>(&timestamp_) -
    reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_)) + sizeof(timestamp_));
  // @@protoc_insertion_point(copy_constructor:quic.CachedNetworkParameters)
}

void CachedNetworkParameters::SharedCtor() {
  serving_region_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(&bandwidth_estimate_bytes_per_second_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&timestamp_) -
      reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_)) + sizeof(timestamp_));
}

CachedNetworkParameters::~CachedNetworkParameters() {
  // @@protoc_insertion_point(destructor:quic.CachedNetworkParameters)
  SharedDtor();
}

void CachedNetworkParameters::SharedDtor() {
  serving_region_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void CachedNetworkParameters::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const CachedNetworkParameters& CachedNetworkParameters::default_instance() {
  ::google::protobuf::internal::InitSCC(&protobuf_cached_5fnetwork_5fparameters_2eproto::scc_info_CachedNetworkParameters.base);
  return *internal_default_instance();
}


void CachedNetworkParameters::Clear() {
// @@protoc_insertion_point(message_clear_start:quic.CachedNetworkParameters)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    serving_region_.ClearNonDefaultToEmptyNoArena();
  }
  if (cached_has_bits & 126u) {
    ::memset(&bandwidth_estimate_bytes_per_second_, 0, static_cast<size_t>(
        reinterpret_cast<char*>(&timestamp_) -
        reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_)) + sizeof(timestamp_));
  }
  _has_bits_.Clear();
  _internal_metadata_.Clear();
}

bool CachedNetworkParameters::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  ::google::protobuf::internal::LiteUnknownFieldSetter unknown_fields_setter(
      &_internal_metadata_);
  ::google::protobuf::io::StringOutputStream unknown_fields_output(
      unknown_fields_setter.buffer());
  ::google::protobuf::io::CodedOutputStream unknown_fields_stream(
      &unknown_fields_output, false);
  // @@protoc_insertion_point(parse_start:quic.CachedNetworkParameters)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // optional string serving_region = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(10u /* 10 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_serving_region()));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // optional int32 bandwidth_estimate_bytes_per_second = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(16u /* 16 & 0xFF */)) {
          set_has_bandwidth_estimate_bytes_per_second();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &bandwidth_estimate_bytes_per_second_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // optional int32 min_rtt_ms = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(24u /* 24 & 0xFF */)) {
          set_has_min_rtt_ms();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &min_rtt_ms_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // optional int32 previous_connection_state = 4;
      case 4: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(32u /* 32 & 0xFF */)) {
          set_has_previous_connection_state();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &previous_connection_state_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // optional int32 max_bandwidth_estimate_bytes_per_second = 5;
      case 5: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(40u /* 40 & 0xFF */)) {
          set_has_max_bandwidth_estimate_bytes_per_second();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &max_bandwidth_estimate_bytes_per_second_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // optional int64 max_bandwidth_timestamp_seconds = 6;
      case 6: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(48u /* 48 & 0xFF */)) {
          set_has_max_bandwidth_timestamp_seconds();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &max_bandwidth_timestamp_seconds_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // optional int64 timestamp = 7;
      case 7: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(56u /* 56 & 0xFF */)) {
          set_has_timestamp();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &timestamp_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormatLite::SkipField(
            input, tag, &unknown_fields_stream));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:quic.CachedNetworkParameters)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:quic.CachedNetworkParameters)
  return false;
#undef DO_
}

void CachedNetworkParameters::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:quic.CachedNetworkParameters)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // optional string serving_region = 1;
  if (cached_has_bits & 0x00000001u) {
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      1, this->serving_region(), output);
  }

  // optional int32 bandwidth_estimate_bytes_per_second = 2;
  if (cached_has_bits & 0x00000002u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(2, this->bandwidth_estimate_bytes_per_second(), output);
  }

  // optional int32 min_rtt_ms = 3;
  if (cached_has_bits & 0x00000004u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(3, this->min_rtt_ms(), output);
  }

  // optional int32 previous_connection_state = 4;
  if (cached_has_bits & 0x00000008u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(4, this->previous_connection_state(), output);
  }

  // optional int32 max_bandwidth_estimate_bytes_per_second = 5;
  if (cached_has_bits & 0x00000010u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(5, this->max_bandwidth_estimate_bytes_per_second(), output);
  }

  // optional int64 max_bandwidth_timestamp_seconds = 6;
  if (cached_has_bits & 0x00000020u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(6, this->max_bandwidth_timestamp_seconds(), output);
  }

  // optional int64 timestamp = 7;
  if (cached_has_bits & 0x00000040u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(7, this->timestamp(), output);
  }

  output->WriteRaw(_internal_metadata_.unknown_fields().data(),
                   static_cast<int>(_internal_metadata_.unknown_fields().size()));
  // @@protoc_insertion_point(serialize_end:quic.CachedNetworkParameters)
}

size_t CachedNetworkParameters::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:quic.CachedNetworkParameters)
  size_t total_size = 0;

  total_size += _internal_metadata_.unknown_fields().size();

  if (_has_bits_[0 / 32] & 127u) {
    // optional string serving_region = 1;
    if (has_serving_region()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->serving_region());
    }

    // optional int32 bandwidth_estimate_bytes_per_second = 2;
    if (has_bandwidth_estimate_bytes_per_second()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int32Size(
          this->bandwidth_estimate_bytes_per_second());
    }

    // optional int32 min_rtt_ms = 3;
    if (has_min_rtt_ms()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int32Size(
          this->min_rtt_ms());
    }

    // optional int32 previous_connection_state = 4;
    if (has_previous_connection_state()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int32Size(
          this->previous_connection_state());
    }

    // optional int32 max_bandwidth_estimate_bytes_per_second = 5;
    if (has_max_bandwidth_estimate_bytes_per_second()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int32Size(
          this->max_bandwidth_estimate_bytes_per_second());
    }

    // optional int64 max_bandwidth_timestamp_seconds = 6;
    if (has_max_bandwidth_timestamp_seconds()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int64Size(
          this->max_bandwidth_timestamp_seconds());
    }

    // optional int64 timestamp = 7;
    if (has_timestamp()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int64Size(
          this->timestamp());
    }

  }
  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void CachedNetworkParameters::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
  MergeFrom(*::google::protobuf::down_cast<const CachedNetworkParameters*>(&from));
}

void CachedNetworkParameters::MergeFrom(const CachedNetworkParameters& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:quic.CachedNetworkParameters)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._has_bits_[0];
  if (cached_has_bits & 127u) {
    if (cached_has_bits & 0x00000001u) {
      set_has_serving_region();
      serving_region_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.serving_region_);
    }
    if (cached_has_bits & 0x00000002u) {
      bandwidth_estimate_bytes_per_second_ = from.bandwidth_estimate_bytes_per_second_;
    }
    if (cached_has_bits & 0x00000004u) {
      min_rtt_ms_ = from.min_rtt_ms_;
    }
    if (cached_has_bits & 0x00000008u) {
      previous_connection_state_ = from.previous_connection_state_;
    }
    if (cached_has_bits & 0x00000010u) {
      max_bandwidth_estimate_bytes_per_second_ = from.max_bandwidth_estimate_bytes_per_second_;
    }
    if (cached_has_bits & 0x00000020u) {
      max_bandwidth_timestamp_seconds_ = from.max_bandwidth_timestamp_seconds_;
    }
    if (cached_has_bits & 0x00000040u) {
      timestamp_ = from.timestamp_;
    }
    _has_bits_[0] |= cached_has_bits;
  }
}

void CachedNetworkParameters::CopyFrom(const CachedNetworkParameters& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:quic.CachedNetworkParameters)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CachedNetworkParameters::IsInitialized() const {
  return true;
}

void CachedNetworkParameters::Swap(CachedNetworkParameters* other) {
  if (other == this) return;
  InternalSwap(other);
}
void CachedNetworkParameters::InternalSwap(CachedNetworkParameters* other) {
  using std::swap;
  serving_region_.Swap(&other->serving_region_, &::google::protobuf::internal::GetEmptyStringAlreadyInited(),
    GetArenaNoVirtual());
  swap(bandwidth_estimate_bytes_per_second_, other->bandwidth_estimate_bytes_per_second_);
  swap(min_rtt_ms_, other->min_rtt_ms_);
  swap(previous_connection_state_, other->previous_connection_state_);
  swap(max_bandwidth_estimate_bytes_per_second_, other->max_bandwidth_estimate_bytes_per_second_);
  swap(max_bandwidth_timestamp_seconds_, other->max_bandwidth_timestamp_seconds_);
  swap(timestamp_, other->timestamp_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  _internal_metadata_.Swap(&other->_internal_metadata_);
}

::std::string CachedNetworkParameters::GetTypeName() const {
  return "quic.CachedNetworkParameters";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace quic
namespace google {
namespace protobuf {
template<> GOOGLE_PROTOBUF_ATTRIBUTE_NOINLINE ::quic::CachedNetworkParameters* Arena::CreateMaybeMessage< ::quic::CachedNetworkParameters >(Arena* arena) {
  return Arena::CreateInternal< ::quic::CachedNetworkParameters >(arena);
}
}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)
