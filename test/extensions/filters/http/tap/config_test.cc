#include "extensions/filters/http/tap/config.h"

#include "test/mocks/server/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TapFilter {

TEST(BufferFilterFactoryTest, TapFilterEmptyProto) {
  TapFilterFactory factory;
  envoy::config::filter::http::tap::v2alpha::Tap config =
      *dynamic_cast<envoy::config::filter::http::tap::v2alpha::Tap*>(
          factory.createEmptyConfigProto().get());

  NiceMock<Server::Configuration::MockFactoryContext> context;
  Http::FilterFactoryCb cb = factory.createFilterFactoryFromProto(config, "stats", context);
  Http::MockFilterChainFactoryCallbacks filter_callback;
  EXPECT_CALL(filter_callback, addStreamFilter(_));
  cb(filter_callback);
}

} // namespace TapFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
