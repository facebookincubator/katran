#pragma once

#include <katran/kde/core/BaseDirectEncap.h>

// BaseDirectEncap.h (kde_types.h) must precede the generated skeleton header.
#include <katran/kde/bpf/katran_de_tc_bpf.skel.h>

namespace katran_tpr {

enum class GuePort : uint16_t {
  DEFAULT = 9886,
  KDE = 9887,
};

class ClientDirectEncap : public BaseDirectEncap {
 public:
  explicit ClientDirectEncap(
      const std::string& iface,
      kde_zone clientZone,
      decltype(oss_kde_zones)& zoneMap,
      bool set_limits = false,
      GuePort encapPort = GuePort::DEFAULT,
      bool hostMode = false,
      bool natMode = false);

  virtual ~ClientDirectEncap() override;

  folly::Expected<folly::Unit, std::system_error> init() override;
  void detach() override;

  void shutdown();

  DirectEncapMode getDirectEncapMode() const override;

  kde_tc_stats getTcStats();

  int getTcProgFd() const {
    return tcProgFd_;
  }

  std::string clientZoneStr() const;

  bool hostMode() const {
    return hostMode_;
  }

 protected:
  folly::Expected<folly::Unit, std::system_error> setSockopsVars() override;

 private:
  folly::Expected<folly::Unit, std::system_error> loadTc();

  BpfSkeleton<katran_de_tc_bpf> tcSkel_;
  unsigned int ifIndex_{0};
  int tcProgFd_{0};
  int tcProgId_{0};
  // host mode only: tc is attached via tcx
  bpf_link* tcLink_{nullptr};
  kde_zone clientZone_{KDE_ZONE_NONE};
  GuePort encapPort_{GuePort::DEFAULT};
  bool hostMode_{false};
  bool natMode_{false};
};

} // namespace katran_tpr
