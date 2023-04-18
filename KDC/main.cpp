#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include<string>
#include<ctime>
#include<winsock2.h>
#include <stdlib.h>
#include "RSA.h"
#pragma comment(lib,"ws2_32.lib")
using namespace std;

//获取当前系统日期和时间
char* get_time()
{
	time_t now = time(0); // 把 now 转换为字符串形式 
	char* dt = ctime(&now);
	return dt;
}

//用户和KDC的地址及端口
#define A_IP "127.0.0.1"
#define A_Port 6000
#define B_IP "127.0.0.1"
#define B_Port 7000
#define KDC_IP "127.0.0.1"
#define KDC_Port 8000
SOCKET sockKDC;
SOCKADDR_IN addrA;
SOCKADDR_IN addrB;
SOCKADDR_IN addrKDC;

//接受请求的随机数
int N1;
//保存会话密钥
int Ks[4][4];
//A的RSA公钥
my_Int n_A;
my_Int e_A;
//B的公钥
my_Int n_B;
my_Int e_B;

//为公钥赋值
void RSA_init()
{
	n_A.sign = true;
	for (int i = 0; i < MAXSIZE; i++)
		n_A.data[i] = 0;
	n_A.data[0] = 0xF96374BB; n_A.data[1] = 0xF77F3D61; n_A.data[2] = 0x0D9EAA43; n_A.data[3] = 0x6B0D4522; n_A.data[4] = 0x638D84D6;
	n_A.data[5] = 0xCA14F5CA; n_A.data[6] = 0xB6E55EEF; n_A.data[7] = 0x23BA8986; n_A.data[8] = 0xDAC0D2C1; n_A.data[9] = 0xA708ED34;
	n_A.data[10] = 0xC75826CD; n_A.data[11] = 0x4F4BDDB5; n_A.data[12] = 0xB9F206CD; n_A.data[13] = 0x6AA87B7B; n_A.data[14] = 0x7A951B37;
	n_A.data[15] = 0xB4CC2879; n_A.data[16] = 0x76E34E34; n_A.data[17] = 0xC3DE5FF0; n_A.data[18] = 0x31563EB7; n_A.data[19] = 0x22364880;
	n_A.data[20] = 0xBF7901DD; n_A.data[21] = 0x840A650F; n_A.data[22] = 0x6BE76968; n_A.data[23] = 0x0C3C526F; n_A.data[24] = 0x2DB5A3F4;
	n_A.data[25] = 0x9F99A696; n_A.data[26] = 0x51261B45; n_A.data[27] = 0x74D4EC13; n_A.data[28] = 0xD9E93C42; n_A.data[29] = 0xD4A25E55;
	n_A.data[30] = 0xD468366D; n_A.data[31] = 0x37F528DF;

	e_A.sign = true;
	for (int i = 0; i < MAXSIZE; i++)
		e_A.data[i] = 0;
	e_A.data[0] = 0x559A34A9; e_A.data[1] = 0x273F3DC4; e_A.data[2] = 0x6E06819F; e_A.data[3] = 0xE53C05EF; e_A.data[4] = 0xB10FD0C3;
	e_A.data[5] = 0xB34B7914; e_A.data[6] = 0xE9EFD58B; e_A.data[7] = 0xF7AD4585; e_A.data[8] = 0x2BA52653; e_A.data[9] = 0xB0ED360C;
	e_A.data[10] = 0xA99B3616; e_A.data[11] = 0xD7B86CF4; e_A.data[12] = 0xF737B518; e_A.data[13] = 0x5FB5F500; e_A.data[14] = 0xDA3FD0C9;
	e_A.data[15] = 0x75027637;

	n_B.sign = true;
	for (int i = 0; i < MAXSIZE; i++)
		n_B.data[i] = 0;
	n_B.data[0] = 0xEE9106EF; n_B.data[1] = 0x2383432D; n_B.data[2] = 0x29640186; n_B.data[3] = 0x1FC03C44; n_B.data[4] = 0x96C778F5;
	n_B.data[5] = 0x15FF7D62; n_B.data[6] = 0x4B2C7515; n_B.data[7] = 0xD347E1F0; n_B.data[8] = 0xB252C838; n_B.data[9] = 0xDCFD9EC2;
	n_B.data[10] = 0x87A291EF; n_B.data[11] = 0x4A1A2384; n_B.data[12] = 0xD205411E; n_B.data[13] = 0x692E74E8; n_B.data[14] = 0x47AE0081;
	n_B.data[15] = 0x6B8BFAC1; n_B.data[16] = 0x2860A10C; n_B.data[17] = 0xA5199DCB; n_B.data[18] = 0x93C43CAD; n_B.data[19] = 0xAA3E20A6;
	n_B.data[20] = 0x432582C2; n_B.data[21] = 0x490F2CEC; n_B.data[22] = 0xA69D6C43; n_B.data[23] = 0xE0E78721; n_B.data[24] = 0x5A6FAD56;
	n_B.data[25] = 0xE5793237; n_B.data[26] = 0xC3264CCF; n_B.data[27] = 0x1B6FDF85; n_B.data[28] = 0x7A116FA4; n_B.data[29] = 0x89FD8789;
	n_B.data[30] = 0x64984C1F; n_B.data[31] = 0x219DEFB6;

	e_B.sign = true;
	for (int i = 0; i < MAXSIZE; i++)
		e_B.data[i] = 0;
	e_B.data[0] = 0x0A503A77; e_B.data[1] = 0x486943A7; e_B.data[2] = 0x2F51ABF4; e_B.data[3] = 0xC1DEECF2; e_B.data[4] = 0x3FFB76AE;
	e_B.data[5] = 0x03E123E9; e_B.data[6] = 0x2D1DB7F2; e_B.data[7] = 0xB51CA812; e_B.data[8] = 0xC7A08082; e_B.data[9] = 0x9A340226;
	e_B.data[10] = 0xD16E05AA; e_B.data[11] = 0xB830E416; e_B.data[12] = 0xCAE6F5EA; e_B.data[13] = 0x27FC3186; e_B.data[14] = 0x07553484;
	e_B.data[15] = 0x48302353;
}

//产生随机会话密钥
void randomKey()
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			Ks[i][j] = rand() % 256;
}

//等待A的会话密钥请求
void wait_Request()
{
	cout << "正在监听..." << endl;
	int len = sizeof(sockaddr);
	if (recvfrom(sockKDC, (char*)&N1, sizeof(N1), 0, (struct sockaddr*)&addrA, &len))
	{
		cout << "[log]" << get_time() << ">>>" << "收到会话请求,产生128位随机AES密钥" << endl;
		//随机产生AES密钥
		randomKey();
		cout << "AES密钥: ";
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				if (Ks[j][i] < 16)
					cout << "0";
				cout << (hex) << Ks[j][i] << " ";
			}
		}
		cout << endl;

		//将AES密钥存成大数形式
		my_Int KEY;
		KEY.sign = true;
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				KEY.data[i * 4 + j] = Ks[i][j];
		//对大数形式的密钥用A的公钥进行RSA加密
		my_Int E_KEY = PowerMode(KEY, e_A, n_A);
		cout << "用A的公钥加密AES密钥: ";
		E_KEY.display();

		//发送给A
		if (sendto(sockKDC, (char*)&E_KEY, sizeof(E_KEY), 0, (struct sockaddr*)&addrA, sizeof(sockaddr)))
			cout << "[log]" << get_time() << ">>>" << "发送给A" << endl;
	}
}

int main()
{
	srand((unsigned)time(NULL));
	RSA_init();
	WORD wVersionRequested = MAKEWORD(2, 2);  //调用者希望使用的socket的最高版本
	WSADATA wsaData;  //可用的Socket的详细信息，通过WSAStartup函数赋值
	int state = WSAStartup(wVersionRequested, &wsaData);  //初始化Socket DLL，协商使用的Socket版本；初始化成功则返回0，否则为错误的int型数字
	if (state == 0)
		cout << "[log]" << get_time() << ">>>" << "初始化Socket成功" << endl;
	else
		cout << "[log]" << get_time() << ">>>" << "初始化Socket失败" << endl;

	//KDC套接字
	sockKDC = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//KDC地址
	addrKDC.sin_family = AF_INET;
	addrKDC.sin_addr.s_addr = inet_addr(KDC_IP);  //IP
	addrKDC.sin_port = htons(KDC_Port);  //Port
	//套接字绑定地址
	bind(sockKDC, (SOCKADDR*)&addrKDC, sizeof(SOCKADDR));

	//用户B地址
	addrB.sin_family = AF_INET;
	addrB.sin_addr.s_addr = inet_addr(B_IP);  //IP
	addrB.sin_port = htons(B_Port);  //Port
	//用户A地址
	addrA.sin_family = AF_INET;
	addrA.sin_addr.s_addr = inet_addr(A_IP);  //IP
	addrA.sin_port = htons(A_Port);  //Port

	//等待请求
	wait_Request();

	//结束使用Socket，释放Socket资源
	closesocket(sockKDC);
	WSACleanup();

	system("pause");
	return 0;
}