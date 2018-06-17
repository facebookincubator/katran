cpp_include "<unordered_map>"

namespace cpp2 lb.katran
namespace py lb.katran

enum Action {
  ADD = 0,
  DEL = 1,
}

struct Vip {
  1: string address,
  2: i32 port,
  3: i32 protocol,
}

struct VipMeta {
  1: Vip vip,
  2: i64 flags,
  /*
   * setFlag controls if we setting this flags or removing it from the VIP
   */
  3: optional bool setFlag = 1,
}

struct Real {
  1: string address,
  2: i32 weight,
}

struct QuicReal {
  1: string address,
  2: i32 id,
}

struct Mac {
  1: string mac,
}

struct Stats {
  1: i64 v1,
  2: i64 v2,
}

struct Healthcheck {
  1: i32 somark,
  2: string address,
}

typedef map<i32, string> ( cpp.template = "std::unordered_map" ) hcMap

typedef list<Real> Reals
typedef list<QuicReal> QuicReals


service KatranService {

  bool changeMac(1: Mac newMac);

  Mac getMac();

  bool addVip(1: VipMeta vipMeta);

  bool delVip(1: Vip vip);

  list<Vip> getAllVips();

  bool modifyVip (1: VipMeta vipMeta);

  i64 getVipFlags(1: Vip vip);

  bool addRealForVip(1: Real real, 2: Vip vip);

  bool delRealForVip(1: Real real, 2: Vip vip);

  bool modifyRealsForVip(
    1: Action action,
    2: Reals real,
    3: Vip vip);

  Reals getRealsForVip(1: Vip vip);

  bool modifyQuicRealsMapping(1: Action action, 2:QuicReals reals);

  QuicReals getQuicRealsMapping();

  Stats getStatsForVip(1: Vip vip);

  Stats getLruStats();

  Stats getLruMissStats();

  Stats getLruFallbackStats();

  Stats getIcmpTooBigStats();

  bool addHealthcheckerDst(1: Healthcheck healthcheck);

  bool delHealthcheckerDst(1: i32 somark);

  hcMap getHealthcheckersDst();
}
