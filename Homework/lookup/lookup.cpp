#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>
#include <cstdio>

std::vector<RoutingTableEntry> routing_table;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  auto match = [&entry](const RoutingTableEntry &x) { return x.addr == entry.addr && x.len == entry.len; };
  if (insert) {
    auto it = std::find_if(routing_table.begin(), routing_table.end(), match);
    if (it != routing_table.end()) {
      it->if_index = entry.if_index; // replace
      it->nexthop = entry.nexthop;
    }
    else
      routing_table.push_back(entry);
  }
  else {
    auto it = std::find_if(routing_table.begin(), routing_table.end(), match);
    if (it == routing_table.end()) {
      printf("\033[31m Fail to delete in routing table, the entry is not found.\033[0m");
      printf("ip: %u.%u.%u.%u/%u \n", (uint8_t)entry.addr, (uint8_t)(entry.addr>>8), (uint8_t)(entry.addr>>16), (uint8_t)(entry.addr>>24), entry.len);
      return;
    }
    routing_table.erase(it);
  }
}

std::vector<RoutingTableEntry>::iterator find(const RoutingTableEntry &entry) {
  auto match = [&entry](const RoutingTableEntry &x) { return x.addr == entry.addr && x.len == entry.len; };
  return std::find_if(routing_table.begin(), routing_table.end(), match);
}

template<typename T>
static void showBits(T a)
{
	auto b = (T *) (&a);  // low bit at right
	for (int k = 8 * sizeof(T) - 1; k >= 0; --k) {
		printf("%u", (bool) (*b & (1 << k)));
	}
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  if(routing_table.empty()) return false;

  auto rank = [addr](const RoutingTableEntry &entry) -> uint32_t { 
    // return the number of matching bits, (start with lowbit)
    uint32_t mask = (uint32_t)(entry.len < 32u ? (1u << entry.len) - 1u : 0xffffffff); // look like 0x000fff
    return (addr & mask) == (entry.addr & mask) ? entry.len : 0;
  };

  auto it = std::max_element(routing_table.begin(), routing_table.end(), 
  [&rank](const RoutingTableEntry &x, const RoutingTableEntry &y) { return rank(x) < rank(y); });

  if (rank(*it) == 0) return false; // not found
  *nexthop = it->nexthop;
  *if_index = it->if_index;
  return true;
}
