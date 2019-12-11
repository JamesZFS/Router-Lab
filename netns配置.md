## netns配置

ip netns add pc1

ip netns add r1

ip netns add r2

ip netns add r3

ip netns add pc2

// pc1r1

ip link add veth-pc1 type veth peer name veth-r1

ip link set veth-pc1 netns pc1

ip link set veth-r1 netns r1

ip netns exec pc1 ip link set veth-pc1 up

ip netns exec r1 ip link set veth-r1 up

ip netns exec pc1 ip addr add 192.168.1.2/24 dev veth-pc1

ip netns exec r1 ip addr add 192.168.1.1/24 dev veth-r1

// r1r2

ip link add veth-r12 type veth peer name veth-r21

ip link set veth-r12 netns r1

ip link set veth-r21 netns r2

ip netns exec r1 ip link set veth-r12 up

ip netns exec r2 ip link set veth-r21 up

ip netns exec r1 ip addr add 192.168.3.1/24 dev veth-r12

// 这里不配置r2的ip地址。

// r2r3

ip link add veth-r22 type veth peer name veth-r31

ip link set veth-r22 netns r2

ip link set veth-r31 netns r3

ip netns exec r2 ip link set veth-r22 up

ip netns exec r3 ip link set veth-r31 up

ip netns exec r3 ip addr add 192.168.4.2/24 dev veth-r31

// 这里不配置r2的ip地址。

// r3pc2

ip link add veth-r32 type veth peer name veth-pc2

ip link set veth-r32 netns r3

ip link set veth-pc2 netns pc2

ip netns exec r3 ip link set veth-r32 up

ip netns exec pc2 ip link set veth-pc2 up

ip netns exec r3 ip addr add 192.168.5.2/24 dev veth-r32

ip netns exec pc2 ip addr add 192.168.5.1/24 dev veth-pc2

