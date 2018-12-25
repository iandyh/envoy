#include "test/integration/http_integration.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace {

class TapIntegrationTest : public HttpIntegrationTest,
                           public testing::TestWithParam<Network::Address::IpVersion> {
public:
  TapIntegrationTest()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), realTime()) {}

  /*void createUpstreams() override {
    HttpIntegrationTest::createUpstreams();
    fake_upstreams_.emplace_back(
        new FakeUpstream(0, FakeHttpConnection::Type::HTTP1, version_, timeSystem()));
    fake_upstreams_.emplace_back(
        new FakeUpstream(0, FakeHttpConnection::Type::HTTP1, version_, timeSystem()));
  }*/

  void initializeFilter(const std::string& filter_config) {
    config_helper_.addFilter(filter_config);

    /*config_helper_.addConfigModifier([](envoy::config::bootstrap::v2::Bootstrap& bootstrap) {
      auto* lua_cluster = bootstrap.mutable_static_resources()->add_clusters();
      lua_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      lua_cluster->set_name("lua_cluster");

      auto* alt_cluster = bootstrap.mutable_static_resources()->add_clusters();
      alt_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      alt_cluster->set_name("alt_cluster");
    });

    config_helper_.addConfigModifier(
        [](envoy::config::filter::network::http_connection_manager::v2::HttpConnectionManager&
               hcm) {
          hcm.mutable_route_config()
              ->mutable_virtual_hosts(0)
              ->mutable_routes(0)
              ->mutable_match()
              ->set_prefix("/test/long/url");

          auto* new_route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->add_routes();
          new_route->mutable_match()->set_prefix("/alt/route");
          new_route->mutable_route()->set_cluster("alt_cluster");

          const std::string key = Extensions::HttpFilters::HttpFilterNames::get().Lua;
          const std::string yaml =
              R"EOF(
            foo.bar:
              foo: bar
              baz: bat
          )EOF";

          ProtobufWkt::Struct value;
          MessageUtil::loadFromYaml(yaml, value);

          // Sets the route's metadata.
          hcm.mutable_route_config()
              ->mutable_virtual_hosts(0)
              ->mutable_routes(0)
              ->mutable_metadata()
              ->mutable_filter_metadata()
              ->insert(
                  Protobuf::MapPair<Envoy::ProtobufTypes::String, ProtobufWkt::Struct>(key, value));
        });*/

    initialize();
  }

  /*void cleanup() {
    codec_client_->close();
    if (fake_lua_connection_ != nullptr) {
      AssertionResult result = fake_lua_connection_->close();
      RELEASE_ASSERT(result, result.message());
      result = fake_lua_connection_->waitForDisconnect();
      RELEASE_ASSERT(result, result.message());
    }
    if (fake_upstream_connection_ != nullptr) {
      AssertionResult result = fake_upstream_connection_->close();
      RELEASE_ASSERT(result, result.message());
      result = fake_upstream_connection_->waitForDisconnect();
      RELEASE_ASSERT(result, result.message());
    }
  }*/

  // FakeHttpConnectionPtr fake_lua_connection_;
  // FakeStreamPtr lua_request_;
};

INSTANTIATE_TEST_CASE_P(IpVersions, TapIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

// fixfix
TEST_P(TapIntegrationTest, NoAdmin) {
  const std::string FILTER_CONFIG =
      R"EOF(
name: envoy.filters.http.tap
config:
)EOF";

  initializeFilter(FILTER_CONFIG);

  BufferingStreamDecoderPtr response = IntegrationUtil::makeSingleRequest(
      lookupPort("admin"), "POST", "/tap", "", downstreamProtocol(), version_);
  EXPECT_TRUE(response->complete());
  EXPECT_STREQ("404", response->headers().Status()->value().c_str());
}

// fixfix
TEST_P(TapIntegrationTest, AdminBasicFlow) {
  const std::string FILTER_CONFIG =
      R"EOF(
name: envoy.filters.http.tap
config:
  admin_config:
    config_id: test_config_id
)EOF";

  initializeFilter(FILTER_CONFIG);

  const std::string admin_request_body =
      R"EOF(
{
  "config_id": "test_config_id",
  "tap_config": {
     "match_config": {
     },
     "output_config": {
       "sinks": [
         {
           "streaming_admin": {}
         }
       ]
     }
   }
}
)EOF";

  BufferingStreamDecoderPtr response = IntegrationUtil::makeSingleRequest(
      lookupPort("admin"), "POST", "/tap", admin_request_body, downstreamProtocol(), version_);
  EXPECT_TRUE(response->complete());
  EXPECT_STREQ("200", response->headers().Status()->value().c_str());
}

} // namespace
} // namespace Envoy
