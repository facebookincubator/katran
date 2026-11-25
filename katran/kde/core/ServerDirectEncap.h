#pragma once

#include <katran/kde/core/BaseDirectEncap.h>

namespace katran_tpr {

class ServerDirectEncap : public BaseDirectEncap {
 public:
  ServerDirectEncap(
      const std::string& iface,
      const folly::IPAddress& directAddress,
      kde_zone zones,
      decltype(oss_kde_zones)& zoneMap,
      bool set_limits,
      const std::optional<std::string>& vipsEnabled = std::nullopt,
      const std::optional<std::string>& vipsDisabled = std::nullopt);

  virtual ~ServerDirectEncap() override;

  virtual folly::Expected<folly::Unit, std::system_error> init() override;
  void detach() override;

  void shutdown();

  DirectEncapMode getDirectEncapMode() const override;

  std::string serverZonesStr() const;
  kde_zone serverZones() const {
    return zones_;
  }

  static std::vector<folly::IPAddress> parseVips(
      const std::optional<std::string>& csvVips);

 protected:
  folly::Expected<folly::Unit, std::system_error> setSockopsVars() override;

 private:
  folly::IPAddress directAddress_;
  kde_zone zones_;
  vip_filter vipMode_{KDE_VIP_FILTER_NONE};
  std::vector<folly::IPAddress> vipsEnabled_;
  std::vector<folly::IPAddress> vipsDisabled_;
};

} // namespace katran_tpr
