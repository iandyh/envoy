#pragma once

#include "envoy/config/filter/http/tap/v2alpha/tap.pb.h"
#include "envoy/http/filter.h"
#include "envoy/server/admin.h"
#include "envoy/service/tap/v2alpha/common.pb.h"
#include "envoy/singleton/manager.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TapFilter {

/**
 * All stats for the tap filter. @see stats_macros.h
 */
// clang-format off
#define ALL_TAP_FILTER_STATS(COUNTER)                                                           \
  COUNTER(rq_tapped)
// clang-format on

/**
 * Wrapper struct for tap filter stats. @see stats_macros.h
 */
struct FilterStats {
  ALL_TAP_FILTER_STATS(GENERATE_COUNTER_STRUCT)
};

/*class TapFilterSettings : public Router::RouteSpecificFilterConfig {
public:
  TapFilterSettings(const envoy::config::filter::http::buffer::v2::Buffer&);
  TapFilterSettings(const envoy::config::filter::http::buffer::v2::BufferPerRoute&);

  bool disabled() const { return disabled_; }
  uint64_t maxRequestBytes() const { return max_request_bytes_; }
  std::chrono::seconds maxRequestTime() const { return max_request_time_; }

private:
  bool disabled_;
  uint64_t max_request_bytes_;
  std::chrono::seconds max_request_time_;
};*/

class Config;

/**
 * fixfix
 */
class AdminHandler : public Singleton::Instance, Logger::Loggable<Logger::Id::tap> {
public:
  AdminHandler(Server::Admin& admin);

  void registerConfig(Config& config, const std::string& config_id);
  void unregisterConfig(Config& config, const std::string& config_id);

private:
  Http::Code handler(absl::string_view path_and_query, Http::HeaderMap& response_headers,
                     Buffer::Instance& response, Server::AdminStream& admin_stream);

  std::unordered_map<std::string, std::unordered_set<Config*>> config_id_map_;
};

typedef std::shared_ptr<AdminHandler> AdminHandlerSharedPtr;

typedef std::shared_ptr<const envoy::service::tap::v2alpha::TapConfig> TapConfigConstSharedPtr;

/**
 * Configuration for the tap filter.
 */
class Config : Logger::Loggable<Logger::Id::tap> {
public:
  Config(const envoy::config::filter::http::tap::v2alpha::Tap& proto_config,
         const std::string& stats_prefix, Stats::Scope& scope, Server::Admin& admin,
         Singleton::Manager& singleton_manager, ThreadLocal::SlotAllocator& tls);
  ~Config();

  void newTapConfig(envoy::service::tap::v2alpha::TapConfig&& tap_config);
  FilterStats& stats() { return stats_; }

private:
  struct TlsConfig : public ThreadLocal::ThreadLocalObject {
    TapConfigConstSharedPtr config_;
  };

  const envoy::config::filter::http::tap::v2alpha::Tap proto_config_;
  FilterStats stats_;
  ThreadLocal::SlotPtr tls_slot_;
  AdminHandlerSharedPtr admin_handler_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * A filter that is capable of buffering an entire request before dispatching it upstream.
 */
class Filter : public Http::StreamFilter {
public:
  Filter(ConfigSharedPtr config) : config_(config) {}
  //~Filter() {}

  static FilterStats generateStats(const std::string& prefix, Stats::Scope& scope);

  // Http::StreamFilterBase
  void onDestroy() override {}

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::HeaderMap&, bool) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus decodeTrailers(Http::HeaderMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks&) override {}

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encode100ContinueHeaders(Http::HeaderMap&) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::HeaderMap&, bool) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus encodeTrailers(Http::HeaderMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override {}

private:
  /*void onRequestTimeout();
  void resetInternalState();
  void initConfig();

  const TapFilterSettings* settings_;
  Http::StreamDecoderFilterCallbacks* callbacks_{};
  Event::TimerPtr request_timeout_;
  bool config_initialized_{};*/

  ConfigSharedPtr config_;
};

} // namespace TapFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
