#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include<string>
#include<ctime>
#include<winsock2.h>
#include <stdlib.h>
#include "RSA.h"
#include "AES.h"
#pragma comment(lib,"ws2_32.lib")
using namespace std;

//��ȡ��ǰϵͳ���ں�ʱ��
char* get_time()
{
	time_t now = time(0); // �� now ת��Ϊ�ַ�����ʽ 
	char* dt = ctime(&now);
	return dt;
}

//�û���KDC�ĵ�ַ���˿�
#define A_IP "127.0.0.1"
#define A_Port 6000
#define B_IP "127.0.0.1"
#define B_Port 7000
#define KDC_IP "127.0.0.1"
#define KDC_Port 8000
SOCKET sockA;
SOCKADDR_IN addrA;
SOCKADDR_IN addrB;
SOCKADDR_IN addrKDC;


//����Ự��Կ
int Ks[4][4];
//����Ự��Կʱ�������
int N1;
//A��RSA��Կ
my_Int n_A;
my_Int e_A;
my_Int d_A;
//B�Ĺ�Կ
my_Int n_B;
my_Int e_B;

//Ϊ��Կ��ֵ
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

	d_A.sign = false;
	for (int i = 0; i < MAXSIZE; i++)
		d_A.data[i] = 0;
	d_A.data[0] = 0x4AFAE4A9; d_A.data[1] = 0x471908E3; d_A.data[2] = 0xECA2EB33; d_A.data[3] = 0x7E2AE220; d_A.data[4] = 0x00656604;
	d_A.data[5] = 0xFA7C38A5; d_A.data[6] = 0x476FB2EF; d_A.data[7] = 0x40C97FC2; d_A.data[8] = 0x7E76F139; d_A.data[9] = 0x9F0A2CFB;
	d_A.data[10] = 0x0079834E; d_A.data[11] = 0xE4643A8C; d_A.data[12] = 0x647676A5; d_A.data[13] = 0x3531EE8D; d_A.data[14] = 0xF72C637B;
	d_A.data[15] = 0x02E5FA0B; d_A.data[16] = 0x3795C051; d_A.data[17] = 0x62F281C6; d_A.data[18] = 0x19457072; d_A.data[19] = 0x8F25F9DB;
	d_A.data[20] = 0x811ED2A6; d_A.data[21] = 0x7F538350; d_A.data[22] = 0x94FA6A41; d_A.data[23] = 0xD3EFD814; d_A.data[24] = 0xCB4D69DA;
	d_A.data[25] = 0x4A339E21; d_A.data[26] = 0x504E45B8; d_A.data[27] = 0xF99C107C; d_A.data[28] = 0x94694A17; d_A.data[29] = 0x29B41B18;
	d_A.data[30] = 0x36E81626; d_A.data[31] = 0x1225ED64;

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

//��KDC����Ự��Կ
void get_Key()
{
	int len = sizeof(sockaddr);
	//�����������������B�ĻỰ��Կ
	N1 = rand();
	if (sendto(sockA, (char*)&N1, sizeof(N1), 0, (struct sockaddr*)&addrKDC, sizeof(sockaddr)))
		cout << "[log]" << get_time() << ">>>" << "��������� " << N1 << " ����Ự��Կ" << endl;

	//�յ�KDC�ļ��ܺ�ĻỰ��Կ
	my_Int E_KEY;
	if (recvfrom(sockA, (char*)&E_KEY, sizeof(E_KEY), 0, (struct sockaddr*)&addrKDC, &len))
	{
		cout << "[log]" << get_time() << ">>>" << "�յ����ܵ�AES��Կ,˽Կ����" << endl;
		cout << "���ܵ�AES��Կ: ";
		E_KEY.display();

		//���ܵõ�������ʽ�ĻỰ��Կ
		my_Int KEY = PowerMode(E_KEY, d_A, n_A);
		//�õ��Ự��Կ
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				Ks[i][j] = KEY.data[i * 4 + j];
		cout << "���ܵõ��Ự��Կ: ";
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
	}
}

//��B���Ự��Կ
void send_Key()
{
	cout << "[log]" << get_time() << ">>>" << "��B�Ĺ�Կ����AES��Կ,���͸�B" << endl;
	//��AES��Կ��ɴ�����ʽ
	my_Int KEY;
	KEY.sign = true;
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			KEY.data[i * 4 + j] = Ks[i][j];
	//�Դ�����ʽ����Կ��B�Ĺ�Կ����RSA����
	my_Int E_KEY = PowerMode(KEY, e_B, n_B);
	cout << "���ܺ����Կ: ";
	E_KEY.display();
	//���͸�B
	if (sendto(sockA, (char*)&E_KEY, sizeof(E_KEY), 0, (struct sockaddr*)&addrB, sizeof(sockaddr)))
		cout << "[log]" << get_time() << ">>>" << "���͸�B" << endl;
}

//����ȷ�ϣ���ֹ�طŹ���
void Confirm()
{
	int len = sizeof(sockaddr);
	//���ջ�����
	int text[4][4];
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			text[i][j] = 0;
	if (recvfrom(sockA, (char*)&text, sizeof(text), 0, (struct sockaddr*)&addrB, &len))
	{
		//���ܵõ�N2
		Decode(4, text, Ks);
		cout << "[log]" << get_time() << ">>>" << "�յ�B�ķ��ط������N2 " << text[0][0] << ", ���ܣ�Ȼ��ظ���AES���ܵ� N2 + 1" << endl;
		//N2 ++
		text[0][0]++;
		//�ټ���
		Encode(4, text, Ks);
		//����B
		sendto(sockA, (char*)&text, sizeof(text), 0, (struct sockaddr*)&addrB, sizeof(sockaddr));
	}
}

//������Ϣ
void send_message()
{
	cout << "[log]" << get_time() << ">>>" << "��ʼ������Ϣ..." << endl;
	L:cout << "��������������(�ĸ���Ϊһ�����ķ���)��";
	int num; cin >> num;
	int(*temp)[4] = new int[num][4];

	cout << "����������(16����)��";
	for (int i = 0; i < num; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			cin >> (hex) >> temp[i][j];
		}
	}
	//��չ����0���
	int ex_num = (num / 4) * 4 == num ? num : (num / 4) * 4 + 4;
	int(*extemp)[4] = new int[ex_num][4];
	for (int i = 0; i < num; i++)
		for (int j = 0; j < 4; j++)
			extemp[i][j] = temp[i][j];
	for (int i = num; i < ex_num; i++)
		for (int j = 0; j < 4; j++)
			extemp[i][j] = 0x00;

	//���ͻ�����
	int text[8][4];
	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 4; j++)
			text[i][j] = 0x00;
	if (ex_num > 8)
	{
		cout << "���͵�����̫��, ������������С, ����������" << endl;
		goto L;
	}
	else
	{
		for (int i = 0; i < ex_num; i++)
			for (int j = 0; j < 4; j++)
				text[i][j] = extemp[i][j];
	}

	//����
	Encode(8, text, Ks);
	cout << "��AES���ܵõ�����: ";
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			if (text[i][j] < 16)
				cout << "0";
			cout << (hex) << text[i][j] << " ";
		}
	}
	cout << endl;
	//��������
	cout << "[log]" << get_time() << ">>>" << "���͸�B..." << endl;
	sendto(sockA, (char*)&text, sizeof(text), 0, (struct sockaddr*)&addrB, sizeof(sockaddr));
}

int main()
{
	srand((unsigned)time(NULL));
	RSA_init();
	WORD wVersionRequested = MAKEWORD(2, 2);  //������ϣ��ʹ�õ�socket����߰汾
	WSADATA wsaData;  //���õ�Socket����ϸ��Ϣ��ͨ��WSAStartup������ֵ
	int state = WSAStartup(wVersionRequested, &wsaData);  //��ʼ��Socket DLL��Э��ʹ�õ�Socket�汾����ʼ���ɹ��򷵻�0������Ϊ�����int������
	if (state == 0)
		cout << "[log]" << get_time() << ">>>" << "��ʼ��Socket�ɹ�" << endl;
	else
		cout << "[log]" << get_time() << ">>>" << "��ʼ��Socketʧ��" << endl;

	//�û�A�׽���
	sockA = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//�û�A��ַ
	addrA.sin_family = AF_INET;
	addrA.sin_addr.s_addr = inet_addr(A_IP);  //IP
	addrA.sin_port = htons(A_Port);  //Port
	//�׽��ְ󶨵�ַ
	bind(sockA, (SOCKADDR*)&addrA, sizeof(SOCKADDR));

	//�û�B��ַ
	addrB.sin_family = AF_INET;
	addrB.sin_addr.s_addr = inet_addr(B_IP);  //IP
	addrB.sin_port = htons(B_Port);  //Port
	//KDC��ַ
	addrKDC.sin_family = AF_INET;
	addrKDC.sin_addr.s_addr = inet_addr(KDC_IP);  //IP
	addrKDC.sin_port = htons(KDC_Port);  //Port

	//��KDC����AES�Ự��Կ
	get_Key();
	//��B���ͻỰ��Կ
	send_Key();
	//�ȴ�B����Կ��ȷ��
	Confirm();
	//������Ϣ
	send_message();

	//����ʹ��Socket���ͷ�Socket��Դ
	closesocket(sockA);
	WSACleanup();

	system("pause");
	return 0;
}