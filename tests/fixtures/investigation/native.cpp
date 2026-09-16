struct Packet {
    int length;
};

void consume(int value);

int adjust(int len) {
    Packet packet{};
    packet.length = len;
    consume(packet.length);
    len += 1;
    return len;
}
