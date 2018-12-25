#include "extensions/filters/http/tap/tap_filter.h"

#include "envoy/admin/v2alpha/tap.pb.h"
#include "envoy/admin/v2alpha/tap.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TapFilter {

AdminHandler::AdminHandler(Server::Admin& admin) {
  bool rc = admin.addHandler("/tap", "tap filter control", MAKE_ADMIN_HANDLER(handler), true, true);
  RELEASE_ASSERT(rc, "/tap admin endpoint is taken");
}

Http::Code AdminHandler::handler(absl::string_view, Http::HeaderMap&, Buffer::Instance&,
                                 Server::AdminStream& admin_stream) {
  if (admin_stream.getRequestBody() == nullptr) {
    ASSERT(false); // fixfix
  }

  envoy::admin::v2alpha::TapRequest tap_request;
  MessageUtil::loadFromJson(admin_stream.getRequestBody()->toString(), tap_request);
  MessageUtil::validate(tap_request);
  // fixfix error checking on load

  ENVOY_LOG(debug, "tap admin request for config_id={}", tap_request.config_id());
  if (config_id_map_.count(tap_request.config_id()) == 0) {
    ASSERT(false); // fixfix
  }
  for (auto config : config_id_map_[tap_request.config_id()]) {
    config->newTapConfig(std::move(*tap_request.mutable_tap_config()));
  }

  return Http::Code::OK;
}

void AdminHandler::registerConfig(Config& config, const std::string& config_id) {
  // fixfix asserts
  config_id_map_[config_id].insert(&config);
}

void AdminHandler::unregisterConfig(Config& config, const std::string& config_id) {
  // fixfix asserts
  config_id_map_[config_id].erase(&config);
  // fixfix remove if empty
}

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(tap_admin_handler);

Config::Config(const envoy::config::filter::http::tap::v2alpha::Tap& proto_config,
               const std::string& stats_prefix, Stats::Scope& scope, Server::Admin& admin,
               Singleton::Manager& singleton_manager, ThreadLocal::SlotAllocator& tls)
    : proto_config_(proto_config), stats_(Filter::generateStats(stats_prefix, scope)),
      tls_slot_(tls.allocateSlot()) {

  if (proto_config_.has_admin_config()) {
    admin_handler_ = singleton_manager.getTyped<AdminHandler>(
        SINGLETON_MANAGER_REGISTERED_NAME(tap_admin_handler),
        [&admin] { return std::make_shared<AdminHandler>(admin); });

    admin_handler_->registerConfig(*this, proto_config_.admin_config().config_id());
    ENVOY_LOG(debug, "initializing tap filter with admin endpoint (config_id={})",
              proto_config_.admin_config().config_id());
  } else {
    ENVOY_LOG(debug, "initializing tap filter with no admin endpoint");
  }

  tls_slot_->set([](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return std::make_shared<TlsConfig>();
  });
}

Config::~Config() {
  if (admin_handler_) {
    admin_handler_->unregisterConfig(*this, proto_config_.admin_config().config_id());
  }
}

void Config::newTapConfig(envoy::service::tap::v2alpha::TapConfig&& tap_config) {
  TapConfigConstSharedPtr new_config(
      new envoy::service::tap::v2alpha::TapConfig(std::move(tap_config)));
  tls_slot_->runOnAllThreads(
      [this, new_config] { tls_slot_->getTyped<TlsConfig>().config_ = new_config; });
}

FilterStats Filter::generateStats(const std::string& prefix, Stats::Scope& scope) {
  std::string final_prefix = prefix + "tap.";
  return {ALL_TAP_FILTER_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

} // namespace TapFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
