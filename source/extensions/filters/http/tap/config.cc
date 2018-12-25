#include "extensions/filters/http/tap/config.h"

#include "envoy/registry/registry.h"

#include "extensions/filters/http/tap/tap_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TapFilter {

Http::FilterFactoryCb TapFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::config::filter::http::tap::v2alpha::Tap& proto_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {

  ConfigSharedPtr filter_config(new Config(proto_config, stats_prefix, context.scope(),
                                           context.admin(), context.singletonManager(),
                                           context.threadLocal()));
  return [filter_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<Filter>(filter_config));
  };
}

/**
 * Static registration for the tap filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<TapFilterFactory,
                                 Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace TapFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
