//generate the filter code with the following
//  sudo tcpdump -dd "udp port 53"
struct sock_filter rawsock_filter[] = {{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x000086dd},
    {0x30, 0, 0, 0x00000014}, {0x15, 0, 15, 0x00000011}, {0x28, 0, 0, 0x00000036},
    {0x15, 12, 0, 0x00000035}, {0x28, 0, 0, 0x00000038}, {0x15, 10, 11, 0x00000035},
    {0x15, 0, 10, 0x00000800}, {0x30, 0, 0, 0x00000017}, {0x15, 0, 8, 0x00000011},
    {0x28, 0, 0, 0x00000014}, {0x45, 6, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
    {0x48, 0, 0, 0x0000000e}, {0x15, 2, 0, 0x00000035}, {0x48, 0, 0, 0x00000010},
    {0x15, 0, 1, 0x00000035}, {0x6, 0, 0, 0x00040000}, {0x6, 0, 0, 0x00000000}};
