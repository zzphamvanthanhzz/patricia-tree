#include <vector>
#include <utility>
#include <memory>
#include <bitset>
#include <string>
#include <cstring>
#include <iostream>

#include <arpa/inet.h>

inline std::bitset<32>  addr2bits(const std::string& addr) {
    unsigned long addr_ul;
    auto err = inet_pton(AF_INET, addr.c_str(), &addr_ul);
    if (err != 1 ) { return 0; }
    return std::bitset<32>(ntohl(addr_ul));
}

inline std::string bits2addr(std::bitset<32> ip_) {
    auto result = new char[16];
    auto ip = ip_.to_ulong();
    sprintf(result, "%lu.%lu.%lu.%lu", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, (ip) & 0xFF);
    return std::string(result);
}

template <class DataType>
struct Node {
    std::shared_ptr<Node> left, right;
    std::bitset<32> addr;
    unsigned int len;
    std::shared_ptr<DataType> data;
    Node(const std::bitset<32> addr_, unsigned int len, std::shared_ptr<DataType> data)
        : addr(addr_ & (std::bitset<32>(-1) << (32-len)))
        , len(len)
        , data(data) {};
    inline bool match(std::bitset<32> addr_) {return (addr ^ (addr_ & (std::bitset<32>(-1) << (32-len)))).to_ulong(); }
    inline void dump() { 
        std::cout << bits2addr(addr) << "/"<<len; 
        if (data != nullptr) {
            std::cout << " -> " << *data;
        }
        std::cout << std::endl;
        if (left != nullptr) left->dump(); 
        if (right != nullptr) right->dump(); 
    }
};

template <class DataType>
class IP2Net
{
public:
    IP2Net(const std::shared_ptr<DataType> default_): root_(new Node<DataType>(addr2bits("0.0.0.0"), 0, nullptr)), default_(default_){};

    IP2Net(const std::vector<std::pair<std::string, std::shared_ptr<DataType>>> data, const std::shared_ptr<DataType> default_)
    : IP2Net(default_) {
        for (auto& item: data) {
            add(item.first, item.second);
        } 
    };

    virtual ~IP2Net (){};

    std::shared_ptr<DataType> LookUp(const std::string& addr) {
        auto data = longest_common_path(addr2bits(addr)).first->data;
        if (data == nullptr) {
            return std::make_shared<DataType>(default_);
        }
        return data;
    }

    void add(const std::string& addr, std::shared_ptr<DataType> data) {
        auto idx = std::strchr(addr.c_str(), '/');
        auto addr_ = addr;
        int mask = 0;

        if (idx != nullptr) {
            mask =  std::stoi(addr.substr(idx - addr.c_str() + 1));
            addr_ = addr.substr(0, idx - addr.c_str());
        }
        insert(addr2bits(addr_) & (std::bitset<32>(-1) << (32 -mask)), mask, data);
    }
    void dump() { root_->dump();}
    
private:
    std::shared_ptr<Node<DataType>> root_;
    std::shared_ptr<DataType> default_;


    std::shared_ptr<Node<DataType>> longest_common_path(std::bitset<32> addr) {
        auto cur = root_;
        while (true) {
            auto next = cur->addr[cur->len+1] ? cur->left: cur->right;
            if (next == nullptr || !next->match(addr)) { break; }
            cur = next; 
        }
        return cur;
    }

    void insert(const std::bitset<32> addr, unsigned int mask, std::shared_ptr<DataType> data) {
        auto cur = longest_common_path(addr);
        cur->dump();
        if (cur->len == 32) return;

        auto next = addr[cur->len+1] ? cur->left: cur->right;
        if (next == nullptr) {
            if (data == cur->data && mask < cur->len) {
                cur->len = mask;
                cur->addr = addr;
                return;
            }
            auto n = std::make_shared<Node<DataType>>(addr, mask, data);
            (addr[cur->len+1])? cur->left = n: cur->right = n; 
            return;
        }

        // merge here
        if (next->data == data) {
            if (next->len > mask) {
                if (addr[cur->len+1]) {
                    cur->left->addr = addr;
                    cur->left->len = mask;
                } else {
                    cur->right->addr = addr;
                    cur->right->len = mask;
                }
            }
            return;
        }

        // split here 
        auto n = std::make_shared<Node<DataType>>(addr, mask, data);
        if (addr[cur->len+1]) {
            n->left = next;
            cur->left = n;
        } else {
            n->right = next; 
            cur->right = n; 
        }
    }
};

//int main(int argc, char *argv[])
//{
//    auto vt = std::make_shared<std::string>("Viettel");
//    auto fpt = std::make_shared<std::string>("FPT");
//    IP2Net<std::string> ipmap({
//        {"10.42.42.2/32", vt},
//        {"10.42.42.1/32", vt},
//        {"10.42.42.3/32", vt},
//        {"10.42.42.0/16", vt},
//        {"10.0.0.0/8", fpt},
//        {"10.0.0.0/28", fpt},
//    }, std::make_shared<std::string>("QT"));
//    ipmap.dump();
//
//    return 0;
//}

