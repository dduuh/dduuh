#include <iostream>
#include <string>
#include <ctime>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <cmath>
#include <windows.h>
#include <iomanip>
#include <cstdint>
#include <functional>
#include <chrono>
#define PI 3.14
#define H 7
#define W 8
using namespace std;
/*SHA256
#ifndef SHA256_H
#define SHA256_H
class SHA256
{
protected:
    typedef unsigned char uint8;
    typedef unsigned int uint32;
    typedef unsigned long long uint64;
 
    const static uint32 sha256_k[];
    static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);
public:
    void init();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int DIGEST_SIZE = ( 256 / 8);
 
protected:
    void transform(const unsigned char *message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
    uint32 m_h[8];
};
std::string sha256(std::string input);
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                   \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}
#endif
const unsigned int SHA256::sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
void SHA256::transform(const unsigned char *message, unsigned int block_nb)
{
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] =  SHA256_F4(w[j -  2]) + w[j -  7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}
void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}
void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}
void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
} 
std::string sha256(std::string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);
 
    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);
 
    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}*/
/*class Token
{
public:
    string name;
    string symbol;
    double value;
    
    Token()
    {
        name = nullptr;
        symbol = nullptr;
        value = 0.0;
    }
    Token(string name, string symbol, double value) : name(name), symbol(symbol), value(value)
    {
        name = "Strongest";
        symbol = "STR";
        value = 1.0;
    }
};
/////////////////////////          TRANSACTION            /////////////////////////////
class Transaction
{
public:
    Transaction()
    {
        _sender = nullptr;
        _receiver = nullptr;
        _amount = 0;
    }
    Transaction(string sender, string receiver, double amount,const Token& token) :
    _sender(sender),
    _receiver(receiver),
    _amount(amount),
    token(token),
    _timestamp(chrono::system_clock::to_time_t(chrono::system_clock::now())),
    _transactionId(generateUniqueTransactionId(sender, receiver, amount))
    {
        _fee = calculateTransactionFee(amount, 0.001, 0.0001, congestionFactor);
    }

    string GetSender() const  { return _sender; }
    string GetReceiver() const { return _receiver; }
    double GetAmount() const { return _amount; }
    time_t GetTimeStamp() const { return _timestamp; }
    string GetTransactionID() const { return _transactionId; }
    double GetFee() const { return _fee; }

    
    string GetHash() const;
private:
    string _sender;
    string _receiver;
    double _amount;
    time_t _timestamp;
    string _transactionId;
    double _fee;
    Token token;

    string generateUniqueTransactionId(const string& _sender, const string& _receiver, double _amount) const
    {
        stringstream ss;
        ss << _sender << _receiver << _amount;

        size_t hash = std::hash<string>()(ss.str());

        stringstream hexSs;
        hexSs << setfill('0') << setw(16) << hash;

        return hexSs.str();
    }
    double calculateTransactionFee(double amount, double baseFee, double perUnitFee, double congestionFactor)
    {
        return (baseFee + (amount * perUnitFee)) * congestionFactor;
    }
};

string Transaction::GetHash() const
{
    stringstream ss;
    ss << _sender << _receiver << _amount;
    return sha256(ss.str());
}
///////////////////////        BLOCK               ///////////////////////
class Block
{
public:
    string sPrevHash; // предыдущий хеш блока

    Block(uint32_t _nIndex, const string &sDataIn, string sPrevHash = ""); // индекс + данные

    string GetHash() const; // получить хеш
    void MineBlock(uint32_t nDifficulty); // майним блок


    void AddTransaction(const Transaction& tx);
    vector<Transaction> GetTransactions() const { return _transactions; }
    uint32_t GetIndex() const { return _nIndex; }
private:
    uint32_t _nIndex; // Индекс блока
    int64_t _nNonce; // Специальная величина, которая корректируется в процессе майнинга.
                    // Часть данных для вычисления хеша блока 
    string _sData; // Данные о блоке
    string _sHash; // сам Хеш
    time_t _tTime; // временная метка при создании блока
    vector<Transaction> _transactions;
    Transaction tx;
    string _CalculateHash() const;
};

Block::Block(uint32_t nIndexIn, const string &sDataIn, string sPrevHash) : _nIndex(nIndexIn), _sData(sDataIn), sPrevHash(sPrevHash)
{
    _nNonce = 1; // найти действительный хеш блока
    _tTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}


string Block::GetHash() const
{
    return _sHash; // тут понятно ))
}

void Block::MineBlock(uint32_t nDifficulty) // Mining
{
    char cstr[nDifficulty + 1];
    for (uint32_t i = 0; i < nDifficulty; ++i)
    {
        cstr[i] = '0';
    }
    cstr[nDifficulty] = '\0';

    string str(cstr);

    do
    {
        _nNonce++;
        _sHash = _CalculateHash();
    } while (_sHash.substr(0, nDifficulty) != str);
    
    cout << "Block mined: " << _sHash << endl;
}

void Block::AddTransaction(const Transaction &tx)
{
    _transactions.push_back(tx);
}

inline string Block::_CalculateHash() const
{
    stringstream ss;
    ss << _nIndex << _tTime << _sData << _nNonce << sPrevHash;
    for (const Transaction&tx : _transactions)
        ss << tx.GetHash();
    
    return sha256(ss.str());
}
////////////////////////////          BLOCKCHAIN                    /////////////////////////////////
class Blockchain
{
public:
    Blockchain();

    void AddBlock(Block bNew);
    vector<Block> GetChain() const { return _vChain; }
private:
    vector<Block> _vChain;
    uint32_t _nDifficulty;
    Block _GetLastBlock() const;
};
Blockchain::Blockchain()
{
    _vChain.emplace_back(Block(0, "Genesis Block"));
    _nDifficulty = 6;
}
void Blockchain::AddBlock(Block bNew)
{
    bNew.sPrevHash = _GetLastBlock().GetHash();
    bNew.MineBlock(_nDifficulty);
    _vChain.push_back(bNew);
}

Block Blockchain::_GetLastBlock() const
{
    return _vChain.back();
}*/


int insertionSort(int arr[], int n)
{
    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int j = i - 1;

        while (j >= 0 && arr[j] > key)
        {
            arr[j + 1] = arr[j];
            j--;
        }

        arr[j + 1] = key;
    }
    
}
int bubbleSort(int arr[], int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        for (int j = 0; j < n - i - 1; j++)
        {
            if (arr[j] > arr[j + 1])
            {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
        
    }
    
}
int partition(int arr[], int low, int high)
{
    int pivot = arr[high];
    int i = (low - 1);


    for (int j = low; j <= high - 1; j++)
    {
        if (arr[j] <= pivot)
        {
            i++;
            swap(arr[i], arr[j]);
        }
    }
    swap(arr[i + 1], arr[high]);
    return (i + 1);
}
int QuickSort(int arr[], int low, int high)
{
    if (low < high)
    {
        int pi = partition(arr, low, high);

        QuickSort(arr, low, pi - 1);
        QuickSort(arr, pi + 1, high);
    }
}
int Merge(int arr[], int left, int mid, int right)
{
    int n1 = mid - left + 1;
    int n2 = right - mid;

    int L[n1], R[n2];

    for (int i = 0; i < n1; i++)
    {
        L[i] = arr[left + i];
    }
    for (int j = 0; j < n2; j++)
    {
        R[j] = arr[mid + 1 + j];
    }
    
    int i = 0, j = 0, k = left;
    while (i < n1 && j < n2)
    {
        if (L[i] <= R[j])
        {
            arr[k] = L[i];
            i++;
        }
        else
        {
            arr[k] = R[j];
            j++;
        }
        k++;
    }
    

    while (i < n1)
    {
        arr[k] = L[i];
        i++;
        k++;
    }
    while (j < n2)
    {
        arr[k] = R[j];
        j++;
        k++;
    }
    
}
void MergeSort(int arr[], int left, int right)
{
    if (left < right)
    {
        int mid = left + (right - left) / 2;

        MergeSort(arr, left, mid);
        MergeSort(arr, mid + 1, right);
        
        Merge(arr, left, mid, right);
    }
}
void printedSort(int arr[], int n)
{
    for (int i = 0; i < n; i++)
    {
        cout << arr[i] << " ";
    }
    cout << endl;
}
int main()
{
    int arr[] = { 23, 1, 3, 4, 10, 5, 2, 9};
    int n = sizeof(arr) / sizeof(arr[0]);

    printedSort(arr, n);

    MergeSort(arr, 0, n - 1);

    printedSort(arr, n);
}
/* Files:
fstream - library
ofstream - writing
ifstream - reading

/////////////////////////

fstream::in - reading
fstream::out - writing
fstream::app - history of writing!
*/