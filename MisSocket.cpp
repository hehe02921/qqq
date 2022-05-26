// MisSocket.cpp: implementation of the CMisSocket class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MisSocket.h"
#include <stdio.h>
#include <tchar.h>
#include <process.h>
#include <crtdbg.h>
#include "GenTool.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

extern CGenTool m_gentool;
 
///////////////////////////////////////////////////////////////////////////////
// Copy
SockAddrIn& SockAddrIn::Copy(const SockAddrIn& sin)
{
	memcpy(&this->sockAddrIn, &sin.sockAddrIn, Size());
	return *this;
}

///////////////////////////////////////////////////////////////////////////////
// IsEqual
bool SockAddrIn::IsEqual(const SockAddrIn& sin)
{
	// Is it Equal? - ignore 'sin_zero'
	return (memcmp(&this->sockAddrIn, &sin.sockAddrIn, Size()-sizeof(sockAddrIn.sin_zero)) == 0);
}

///////////////////////////////////////////////////////////////////////////////
// IsGreater
bool SockAddrIn::IsGreater(const SockAddrIn& sin)
{
	// Is it Greater? - ignore 'sin_zero'
	return (memcmp(&this->sockAddrIn, &sin.sockAddrIn, Size()-sizeof(sockAddrIn.sin_zero)) > 0);
}

///////////////////////////////////////////////////////////////////////////////
// IsLower
bool SockAddrIn::IsLower(const SockAddrIn& sin)
{
	// Is it Lower? - ignore 'sin_zero'
	return (memcmp(&this->sockAddrIn, &sin.sockAddrIn, Size()-sizeof(sockAddrIn.sin_zero)) < 0);
}


BOOL SockAddrIn::CreateFrom( LPCTSTR sAddr, LPCTSTR sService )
{
	sockAddrIn.sin_addr.s_addr = htonl( CMisSocket::GetIPAddress(sAddr) );
	sockAddrIn.sin_port = htons( CMisSocket::GetPortNumber( sService ) );
	sockAddrIn.sin_family = AF_INET;
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
CMisSocket::CMisSocket() : m_hSocket(INVALID_SOCKET),m_wVersion(0),m_iErrorNumber(0),
	m_hMutex(NULL),m_hCommSocket(INVALID_HANDLE_VALUE), m_hThread(NULL),m_bServer(FALSE),
	m_bBroadcast(FALSE)
{
	WSADATA MisWsadata;
	m_wVersion = MAKEWORD(2,2);

	memset( m_cLastError, 0, ERR_MAXLENGTH );
	memset( &m_sockaddr, 0, sizeof( m_sockaddr ) );
	memset( &m_rsockaddr, 0, sizeof( m_rsockaddr ) );
	// 默认超时时间
	m_OutTime.tv_sec	 = 60;
	m_OutTime.tv_usec	 = 0;

	int iWSARet = WSAStartup( m_wVersion, &MisWsadata );	// Initialize Winsock
	if( iWSARet != 0 )
	{
        SetSocketError( "WSAStartup failed!", WSAGetLastError() );
        return;
	}

	sprintf(cSocketMode,"HEX");
}

CMisSocket::~CMisSocket()
{
	WSACleanup();
}
/**************************************************************
 *　名称: Create                                              *
 *　类型: int                                                 *
 *　功能: 连接服务主机指定端口服务                            *
 *　入参: void                                  　            *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::CreateSocket( int nDomain, int nType, int nProtocol /* =0 */ )
{
/*
	if ( (m_hSocket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP )) == INVALID_SOCKET )
	{
        SetSocketError( "socket() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	return ERR_SUCCESS;	
*/
	if ( IsOpen() )
		return ERR_WSAERROR;

	// domain 指定使用何种的地址类型
	// nType SOCK_STREAM 提供双向连续且可信赖的数据流，即TCP。支持OOB 机制，在所有数据传送前必须使用connect()来建立连线状态。
	//       SOCK_DGRAM 使用不连续不可信赖的数据包连接
	// protocol 用来指定socket所使用的传输协议编号，通常此参考不用管它，设为0即可
	//       IPPROTO_TCP
	m_hSocket = socket( nDomain, nType, nProtocol );
	if (INVALID_SOCKET != m_hSocket )
	{
		m_hCommSocket = (HANDLE) m_hSocket;
		return ERR_SUCCESS;	
	}
	SetSocketError( "socket() failed", WSAGetLastError() );
	return ERR_WSAERROR;	

}
/**************************************************************
 *　名称: CreateSocket                                        *
 *　类型: int                                                 *
 *　功能: 创建服务器应用SOCKET                                *
 *　入参: strServiceName    服务名或者端口号   　             *
 *        nDomain           地址类型            　            *
 *        nProtocol         协议类型            　            *
 *　出参: 无                                                  *
 *　返回: ERR_WSAERROR 失败                                   *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::CreateSocket(LPCTSTR strServiceName, int nDomain, int nProtocol, UINT uOptions /* = 0 */)
{
	if ( IsOpen() )
		return ERR_WSAERROR;

	memset( &m_sockaddr,0, sizeof( m_sockaddr ) );

	SOCKET SSock = socket(nDomain, nProtocol, 0 );

	if ( INVALID_SOCKET != SSock )
	{
		// 指定服务提供端口号
		m_sockaddr.sin_port = htons( CMisSocket::GetPortNumber( strServiceName ) );
		if ( 0 != m_sockaddr.sin_port )
		{
			m_sockaddr.sin_addr.s_addr = htonl( INADDR_ANY );
			m_sockaddr.sin_family = nDomain;

			if ( uOptions & SO_REUSEADDR )
			{
				//设定相关选项
				BOOL optval = TRUE;
				if ( SOCKET_ERROR == setsockopt( SSock, SOL_SOCKET, SO_REUSEADDR, (char *) &optval, sizeof( BOOL ) ) )
				{
					closesocket( SSock );
					return ERR_WSAERROR;
				}
			}
			// 判断是否为UDP协议
			if( SOCK_DGRAM == nProtocol)
			{
				//如果允许广播
				if ( uOptions & SO_BROADCAST)
				{
					BOOL optval = TRUE;
					if ( SOCKET_ERROR == setsockopt( SSock, SOL_SOCKET, SO_BROADCAST, (char *) &optval, sizeof( BOOL ) ) )
					{
						closesocket( SSock );
						return ERR_WSAERROR;
					}
					m_bBroadcast = TRUE;
				}
				// 如果需要广播，则需要设定互斥体
				m_hMutex = CreateMutex(NULL, FALSE, NULL);
				if ( NULL == m_hMutex)
				{
					closesocket( SSock );
					return ERR_WSAERROR;
				}

			}
			// 绑定一个本地地址
			if ( SOCKET_ERROR == bind(SSock, (LPSOCKADDR)&m_sockaddr, sizeof(SOCKADDR_IN)))
			{
				closesocket( SSock );
				m_bBroadcast = FALSE;
				if (NULL != m_hMutex)
					CloseHandle( m_hMutex );
				m_hMutex = NULL;
				return ERR_WSAERROR;
			}
			// 如果是TCP连接需要监听
			if (SOCK_STREAM == nProtocol)
			{
				if ( SOCKET_ERROR == listen(SSock, SOMAXCONN))
				{
					closesocket( SSock );
					return ERR_WSAERROR;
				}
			}
			// 保存socket
			m_hCommSocket = (HANDLE) SSock;
			return ERR_SUCCESS;
		}
		else
			SetLastError(ERROR_INVALID_PARAMETER);
		// 关闭socket
		closesocket( SSock );
	}

	return ERR_WSAERROR;
}
/**************************************************************
 *　名称: Connect                                             *
 *　类型: int                                                 *
 *　功能: 连接服务主机指定端口服务                            *
 *　入参: pStrRemote    远程主机IP                            *
 *        iPort         端口　    　                          *
 *　　　　pStrData  要发送的字符串              　            *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR 发送错误                               *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::Connect( char* pStrRemote, unsigned int iPort )
{
	if( strlen( pStrRemote ) == 0 || iPort == 0 )
		return ERR_BADPARAM;

	hostent *hostEnt = NULL;
	long lIPAddress = 0;

	hostEnt = gethostbyname( pStrRemote );

	if( hostEnt != NULL )
	{
		lIPAddress = ((in_addr*)hostEnt->h_addr)->s_addr;
		m_sockaddr.sin_addr.s_addr = lIPAddress;
	}
	else
	{
		m_sockaddr.sin_addr.s_addr = inet_addr( pStrRemote );
	}

	m_sockaddr.sin_family = AF_INET;
	m_sockaddr.sin_port = htons( iPort );

	if( connect( m_hSocket, (SOCKADDR*)&m_sockaddr, sizeof( m_sockaddr ) ) == SOCKET_ERROR )
	{
        SetSocketError( "connect() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}

static int checkRange(const char *str,int min)
{
	/*	printf("\t%s\t",str);*/
	int i=atoi(str);
	if (i>255 || i<min)
		return 0;
	else
		return 1;
}
static int checkIPStr(char *str)
{
	char *p;
	int count=0;	
	if (str==NULL)
		return -1;
	if (!strstr(str,"."))
		return -2;
	
	p=strtok(str,".");	
	while (p !=NULL)
	{
		count+=1;
		if (count==1 || count==4)
		{
			if ( checkRange(p,1)==0)
				return -3;
		}
		else
		{
			if (checkRange(p,0)==0)
				return -3;
		}
		p=strtok(NULL,".");
	}
	if (count==4) 
		return 0;
	return -4;
}
/**************************************************************
 *　名称: ConnectTo                                           *
 *　类型: BOOL                                                *
 *　功能: 连接服务主机指定端口服务                            *
 *　入参: strDestination    远程主机名称或点IP串格式          *
 *        strServiceName    服务名或者端口号   　             *
 *        nDomain           地址类型            　            *
 *        nProtocol         协议类型            　            *
 *　出参: 无                                                  *
 *　返回: FALSE		   失败                                   *
 *        TRUE         成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
BOOL CMisSocket::ConnectTo(LPCTSTR strDestination, LPCTSTR strServiceName, int nDomain, int nProtocol)
{
	if ( IsOpen() )
		return FALSE;

	SOCKADDR_IN sockAddr = { 0 };
	// 创建客户端SOCKET
	SOCKET sock = socket(nDomain, nProtocol, 0);
	
	if ( INVALID_SOCKET != sock )
	{
		// 通过主机名获得IP地址值
		TCHAR strHost[HOSTNAME_SIZE] = { 0 };
		if (FALSE == CMisSocket::GetLocalName( strHost, sizeof(strHost)/sizeof(TCHAR)) )
		{
			m_gentool.WriteLog(LOG_LEVEL2,"获取主机名称[%s]失败[%d]", strHost,GetLastError() ); 
			closesocket( sock );
			return FALSE;
		}
		/*
		char cSocketType[30]={0};
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "GSM", cSocketType );
		if (strlen(cSocketType)>7)
		{
			if(0==checkIPStr(cSocketType)) //是IP地址
			{
				sockAddr.sin_addr.s_addr = inet_addr( cSocketType ); 
			}
			else
			{
				sockAddr.sin_addr.s_addr = htonl( CMisSocket::GetIPAddress( strHost ) );
			}
					
		}
		else
		*/
		{
			sockAddr.sin_addr.s_addr = htonl( CMisSocket::GetIPAddress( strHost ) );
		}

		//sockAddr.sin_addr.s_addr = htonl( CMisSocket::GetIPAddress( strHost ) );
		sockAddr.sin_family = nDomain;

		//m_gentool.WriteLog(LOG_LEVEL2,"主机名称[%s]",  strHost );
	
// 		// 根据IP地址串或者主机名取得服务器地址值
 		if ( strDestination[0] )
 		{
 			sockAddr.sin_addr.s_addr = htonl(CMisSocket::GetIPAddress( strDestination ) );
 		}
		// 根据服务名或者端口串值取得16位字节码端口,返回0为失败
		sockAddr.sin_port = htons( CMisSocket::GetPortNumber( strServiceName ) );
		if ( 0 != sockAddr.sin_port )
		{
// 			int nNetTimeout= 5000;
// 			//setsockopt(sock,SOL_SOCKET, SO_CONNECT_TIME, (char *)&nNetTimeout,sizeof(int));
// 			sock.set_SendTimeout(iTimeOut); //
// 			sock.set_RecvTimeout(iTimeOut);//
			// 连接服务器
			if (SOCKET_ERROR == connect( sock, (LPSOCKADDR)&sockAddr, sizeof(SOCKADDR_IN)))
			{
				closesocket( sock );
				DWORD tt=GetLastError();
				return FALSE;
			}
			// ADD BY FSW AT 20080426 阻塞模式
			ULONG ulMode = 0;
 			ioctlsocket(sock, FIONBIO, &ulMode);  
			// 保存socket
			m_hCommSocket = (HANDLE) sock;
			// 初始化事件
			m_sCommEvent.EventArray[m_sCommEvent.EventTotal] = WSACreateEvent();
			WSAEventSelect((SOCKET)m_hCommSocket,m_sCommEvent.EventArray[m_sCommEvent.EventTotal],  FD_READ|FD_CLOSE);
			m_sCommEvent.EventTotal++;
			return TRUE;
		}
	}
	return FALSE;
}
/**************************************************************
 *　名称: Close                                               *
 *　类型: int                                                 *
 *　功能: 关闭端口连接                                        *
 *　入参: 无                                    　            *
 *　出参: 无                                                  *
 *　返回: ERR_WSAERROR 发送错误                               *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::Close( void )
{
	if ( closesocket( m_hSocket ) == SOCKET_ERROR )
	{
        SetSocketError( "closesocket() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	m_hSocket = INVALID_SOCKET;

	memset( &m_sockaddr,  0, sizeof( sockaddr_in ) );
	memset( &m_rsockaddr, 0, sizeof( sockaddr_in ) );

	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: Send                                                *
 *　类型: int                                                 *
 *　功能: 从指定端口发送数据	                              *
 *　入参: MisS      端口套接字                                *
 *　　　　iLen      字符指针长度　　                          *
 *　　　　pStrData  要发送的字符串              　            *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR 发送错误                               *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::Send( SOCKET MisS, char* pStrData, int iLen )
{
	if( pStrData == NULL || iLen == 0 )
		return ERR_BADPARAM;

	if( send( MisS, pStrData, iLen, 0 ) == SOCKET_ERROR )
	{
        SetSocketError( "send() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	
	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: Send                                                *
 *　类型: int                                                 *
 *　功能: 从默认端口发送数据	                              *
 *　入参: iLen      字符指针长度　　                          *
 *　　　　pStrData  要发送的字符串              　            *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR 发送错误                               *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::Send( char* pStrData, int iLen )
{
	// 参数检查
	if( pStrData == NULL || iLen == 0 || m_hSocket == INVALID_SOCKET)
		return ERR_BADPARAM;
	// 发送数据
	if( send( m_hSocket, pStrData, iLen, 0 ) == SOCKET_ERROR )
	{
        SetSocketError( "send() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	
	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: Receive                                             *
 *　类型: int                                                 *
 *　功能: 从默认端口接收数据	                              *
 *　入参: MisS      端口套接字                                *
 *　出参: pStrRev   接收字符缓冲区指针                        *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR 发送错误                               *
 *        iRet         成功返回接收字节数                     *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::Receive( SOCKET MisS, char* pStrRev, int iLen )
{
	if( pStrRev == NULL )
		return ERR_BADPARAM;

	int iRet = 0;
	
	iRet = recv( MisS, pStrRev, iLen, 0 );

	if ( iRet == SOCKET_ERROR )
	{
        SetSocketError( "recv() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	return iRet;
}
/**************************************************************
 *　名称: Receive                                             *
 *　类型: int                                                 *
 *　功能: 从默认端口接收数据	                              *
 *　入参: iLen      接收缓冲区最大长度                        *
 *　出参: pStrRev   接收字符缓冲区指针                        *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR 发送错误                               *
 *        iRet         成功返回接收字节数                     *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::Receive( char* pStrRev, int iLen , DWORD dwTimeout)
{
	int		 iRead = 0;		// 从网络接收的全部数据
	long	 lRecv = 0L;	// 已经接收到缓冲的数据
	int		 i;				// 每次接收到的数据长度

	if( pStrRev == NULL )
		return ERR_BADPARAM;

	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;
	if ( INFINITE != dwTimeout ) 
	{
		stTime.tv_sec = 0;
		stTime.tv_usec = dwTimeout*1000;
		pstTime = &stTime;
	}
	
	SOCKET sLocal = (SOCKET) m_hCommSocket;
	// 设定描述符
	fd_set	fdWrite  = { 0 };
	if ( !FD_ISSET( sLocal, &fdWrite ) )
		FD_SET( sLocal, &fdWrite );
	// 发送的字节数
	DWORD dwBytesWritten = 0L;
	// 选择函数设定超时时间
	int iResult = select( sLocal+1, NULL, &fdWrite, NULL, pstTime );

//	int iRet = 0;
//	iRet = recv( m_hSocket, pStrRev, iLen, 0 );
	while ( iLen > iRead )
	{
		// 取得到达数据的数据长度
		lRecv = 0L;
		if ( ioctlsocket(sLocal, FIONREAD, (u_long *)(&lRecv)) < 0 )
		{
			return -1;
		}
		// 判断准备接受的数据长度
		i = ( lRecv<iLen ) ? (int)lRecv : iLen;
		// 从端口读取数据
		if ( (i = recv(sLocal, (char *)pStrRev, i, 0)) < 0 )
		{
			return -1;
		}
		// 累计接收的的数据长度并偏移接收缓冲区的指针
		iRead	 += i;
		pStrRev  += i;
	}
	return iRead;
/*
	if ( iRet == SOCKET_ERROR )
	{
        SetSocketError( "recv() failed", WSAGetLastError() );
		return ERR_WSAERROR;
	}

	return iRet;
*/
}
/**************************************************************
 *　名称: STBind                                              *
 *　类型: int                                                 *
 *　功能: 设置SOCKET对象的IP地址与端口                        *
 *　入参: pStrIP   IP地址    　                               *
 *        iPort    本地端口                                   *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR UPON 错误                              *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/

int CMisSocket::STBind( char* pStrIP, unsigned int iPort )
{

	if( strlen( pStrIP ) == 0 || iPort == 0 )
		return ERR_BADPARAM;

	memset( &m_sockaddr,0, sizeof( m_sockaddr ) );

	m_sockaddr.sin_family = AF_INET;
	m_sockaddr.sin_addr.s_addr = inet_addr( pStrIP );
	m_sockaddr.sin_port = htons( iPort );

	if ( bind( m_hSocket, (SOCKADDR*)&m_sockaddr, sizeof( m_sockaddr ) ) == SOCKET_ERROR )
	{
        SetSocketError( "bind() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	return ERR_SUCCESS;
}

/**************************************************************
 *　名称: STListen                                            *
 *　类型: int                                                 *
 *　功能: 设置SOCKET对象的为监听状态                          *
 *　入参: iQueuedConnections   允许连接客户端数               *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR UPON 错误                              *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::STListen( int iQueuedConnections )
{
	if( iQueuedConnections == 0 )
		return ERR_BADPARAM;

	if( listen( m_hSocket, iQueuedConnections ) == SOCKET_ERROR )
	{
        SetSocketError( "listen() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: STAccept                                            *
 *　类型: int                                                 *
 *　功能: 设置SOCKET对象的为监听状态                          *
 *　入参: MisS   允许连接客户端数               *
 *　出参: 无                                                  *
 *　返回: ERR_WSAERROR UPON 错误                              *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::STAccept( SOCKET MisS )
{	
	int Len = sizeof( m_rsockaddr );
	memset( &m_rsockaddr, 0, sizeof( m_rsockaddr ) );
	/*
	从MisS的等待连接队列中抽取第一个连接，创建一个与MisS同类的新的套接口并返回句柄。如果队列中无等待连接，
	且套接口为非阻塞方式，则accept()阻塞调用进程直至新的连接出现。如果套接口为非阻塞方式且队列中等
	待连接，则accept()返回一错误代码。已接受连接的套接口不能用于接受新的连接，原套接口仍保持开放。
	addr参数为一个返回参数，其中填写的是为通讯层所知的连接实体地址。addr参数的实际格式由通讯时产生的地址族确定。
	addrlen参数也是一个返回参数，在调用时初始化为addr所指的地址空间；在调用结束时它包含了实际返回的地址的长度
	（用字节数表示）。该函数与SOCK_STREAM类型的面向连接的套接口一起使用。如果addr与addrlen中有一个为零NULL，
	将不返回所接受的套接口远程地址的任何信息。*/
	if( ( m_hClientSocket = accept( MisS, (SOCKADDR*)&m_rsockaddr, &Len ) ) == INVALID_SOCKET )
	{
        SetSocketError( "accept() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}

int CMisSocket::STAsyncSelect( HWND hWnd, unsigned int wMsg, long lEvent, BOOL bServer/* =TRUE */ )
{
	/**************************************************
	* FUNCTION: asyncSelect                           *
	*                                                 *
	* PURPOSE: Enables Windows Messaging notification *
	* for the object. (wMsg) will be sent to the      *
	* Window Procedure of (hWnd) whenever one of the  *
	* events in (lEvent) has occurred. See MSDN docs  *
	* for WSAAsyncSelect() for more information.	  *
	*                                                 *
	* RETURNS: ERR_BADPARAM for invalid               *
	* parameters, ERR_WSAERROR upon error,            *
	* otherwise ERR_SUCCESS                           *
	*                                                 *
	***************************************************/

	if( !IsWindow( hWnd ) || wMsg == 0 || lEvent == 0 )
        return ERR_BADPARAM;
/*
	if( WSAAsyncSelect( bServer?m_hSocket:m_hClientSocket, hWnd, wMsg, lEvent ) == SOCKET_ERROR )
	{
        SetSocketError( "WSAAsyncSelect() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
*/
	if( bServer )
	{
		if( WSAAsyncSelect( m_hSocket, hWnd, wMsg, lEvent ) == SOCKET_ERROR )
		{
			SetSocketError( "WSAAsyncSelect() failed", WSAGetLastError() );
			return ERR_WSAERROR;
		}
	}
	else
	{
		if( WSAAsyncSelect( m_hClientSocket, hWnd, wMsg, lEvent ) == SOCKET_ERROR )
		{
			SetSocketError( "WSAAsyncSelect() failed", WSAGetLastError() );
			return ERR_WSAERROR;
		}
	}
	return ERR_SUCCESS;
}

int CMisSocket::GetRemoteIP( char* pStrIP )
{
	if( pStrIP == NULL )
        return ERR_BADPARAM;

	int namelen = sizeof( m_rsockaddr );

//	if( getpeername( m_hSocket, (SOCKADDR*)&m_rsockaddr, &namelen ) == SOCKET_ERROR )
	if( getpeername( (SOCKET)m_hCommSocket, (SOCKADDR*)&m_rsockaddr, &namelen ) == SOCKET_ERROR )
	{
        SetSocketError( "getpeername() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}

	Long2DottedQuad( m_rsockaddr.sin_addr.s_addr, pStrIP );

	return ERR_SUCCESS;
}

int CMisSocket::GetRemotePort( int* iPort )
{
	if( iPort == NULL )
		return ERR_BADPARAM;

	int namelen = sizeof( m_rsockaddr );
	
//	if( getpeername( m_hSocket, (SOCKADDR*)&m_rsockaddr, &namelen ) == SOCKET_ERROR )
	if( getpeername( (SOCKET)m_hCommSocket, (SOCKADDR*)&m_rsockaddr, &namelen ) == SOCKET_ERROR )
	{
        SetSocketError( "getpeername() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}

	*iPort = ntohs( m_rsockaddr.sin_port );

	return ERR_SUCCESS;
}




int CMisSocket::GetLocalPort( int* iPort )
{
	if( iPort == NULL )
        return ERR_BADPARAM;

	*iPort = ntohs(m_sockaddr.sin_port);

	return ERR_SUCCESS;
}
//获得socket要连接的地址
BOOL CMisSocket::GetPeerName(SockAddrIn& saddr_in)
{
	if (IsOpen())
	{
		int namelen = saddr_in.Size();
		return (SOCKET_ERROR != getpeername(GetSocket(), (LPSOCKADDR)saddr_in, &namelen));	
	}

	return FALSE;
}



/**************************************************************
 *　名称: GetRemoteHost                                       *
 *　类型: int                                                 *
 *　功能: 取得连接的远程主机名称                              *
 *　入参: iBufLen   远程主机名最大长度          　            *
 *　出参: pStrBuf   远程主机名缓冲区                          *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR UPON 错误                              *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::GetRemoteHost( char* pStrBuf, int iBufLen )
{
	if( pStrBuf == NULL )
		return ERR_BADPARAM;

	hostent* hostEnt = NULL;
	int iLen = 0;
	int namelen = sizeof( m_rsockaddr );

//	if( getpeername( m_hSocket, (SOCKADDR*)&m_rsockaddr, &namelen ) == SOCKET_ERROR )
	if( getpeername( (SOCKET)m_hCommSocket, (SOCKADDR*)&m_rsockaddr, &namelen ) == SOCKET_ERROR )
		return ERR_WSAERROR;

	hostEnt = gethostbyaddr( (char*)&m_rsockaddr.sin_addr.s_addr, 4 ,PF_INET );

	if( hostEnt != NULL )
	{
		iLen = strlen( hostEnt->h_name );
		if( iLen > iBufLen )
			return ERR_BADPARAM;

		memcpy( pStrBuf, hostEnt->h_name, iLen );
		return ERR_SUCCESS;
	}

	return ERR_WSAERROR;
}
/**************************************************************
 *　名称: SetSendTimeout                                      *
 *　类型: int                                                 *
 *　功能: 设置发送超时时间                                    *
 *　入参: iTime  发送超时时间                   　            *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR Socket错误                             *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::SetSendTimeout( int iTime )
{
	if( iTime < 0 )
		return ERR_BADPARAM;

	if( setsockopt( m_hSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&iTime, sizeof( iTime ) ) == SOCKET_ERROR )
	{
		SetSocketError( "setsockopt 失败.", WSAGetLastError() );
		return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: SetRecvTimeout                                      *
 *　类型: int                                                 *
 *　功能: 设置接收超时时间                                    *
 *　入参: iTime  接收超时时间                   　            *
 *　出参: 无                                                  *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR Socket错误                             *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::SetRecvTimeout( int iTime )
{
	if( iTime < 0 )
		return ERR_BADPARAM;

	if( setsockopt( m_hSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTime, sizeof( iTime ) ) == SOCKET_ERROR )
	{
		SetSocketError( "SetRecvTimeout 失败.", WSAGetLastError() );
		return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: SetSocketError                                      *
 *　类型: void                                                *
 *　功能: 设置错误信息及错误返回码                            *
 *　入参: pStrErr   错误信息串                  　            *
 *        iErr      错误索引值  　　                          *
 *　出参: 无                                                  *
 *　返回: 无                                                  *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
void CMisSocket::SetSocketError( char* pStrErr, int iErrID )
{
	memset( m_cLastError, 0, ERR_MAXLENGTH ); 
	memcpy( m_cLastError, pStrErr, strlen( pStrErr ) );
	m_cLastError[strlen(pStrErr)+1] = '\0';

	m_iErrorNumber = iErrID ;
}
/**************************************************************
 *　名称: GetSocketError                                      *
 *　类型: void                                                *
 *　功能: 设置错误信息及错误返回码                            *
 *　入参: 无                    　　                          *
 *　出参: pStrErr   错误信息缓冲区                            *
 *        piErrID   错误信息值                                *
 *　返回: 无                                                  *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
void CMisSocket::GetSocketError( char* pStrErr, int* piErrID )
{
	// 取得错误信息长度
	int iLen = strlen( m_cLastError );
	if( iLen > 0 )
	{
        memset( pStrErr, 0, iLen );
        memcpy( pStrErr, m_cLastError, iLen );
        pStrErr[iLen+1] = '\0';

        *piErrID = m_iErrorNumber;
	}
}
/**************************************************************
 *　名称: Long2DottedQuad                                     *
 *　类型: void                                                *
 *　功能: 从32位LONG值转换IP地址为字符串形式(255.255.255.255) *
 *　入参: uLong   IP地址32位值                  　            *
 *　出参: pCBuf   返回的字符串                                *
 *　返回: 无                                                  *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
void CMisSocket::Long2DottedQuad( unsigned long uLong, char* pCBuf )
{
	wsprintf( pCBuf, "%d.%d.%d.%d",(int)((BYTE*)&uLong)[0],
		(int)((BYTE*)&uLong)[1],(int)((BYTE*)&uLong)[2],(int)((BYTE*)&uLong)[3] );
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
void CMisSocket::RunThread( )
{
	BYTE	buffer[MAX_CFG_BUF];
	DWORD	dwBytes  = 0L;

	HANDLE	hThread = GetCurrentThread();
	DWORD	dwTimeout = m_OutTime.tv_sec;

	if ( IsServer() )
	{
		//是否广播模式
		if ( !IsBroadcast() )
		{
			SOCKET sock = (SOCKET) m_hCommSocket;
			sock = WaitForConnection( sock );

			// 等待新的连接
			if (sock != INVALID_SOCKET)
			{
				//关闭连接
				ShutdownConnection( (SOCKET) m_hCommSocket);
				m_hCommSocket = (HANDLE) sock;
				OnEvent( EVT_CONSUCCESS ); // connect
			}
			else
			{
				// 如果已经关闭则不发送事件，否则发送
				if (IsOpen())
					OnEvent( EVT_CONFAILURE ); // 等待失败
				return;
			}
		}
	}
	//如果socket已经创建
	while( IsOpen() )
	{
/*
		// 采用阻塞式socket，等待事件通知
		dwBytes = ReadComm(buffer, sizeof(buffer), dwTimeout);

		// 如果有错误发生
		if (dwBytes == (DWORD)-1)
		{
			// 如果要关闭，则不发送事件
			if ( IsOpen() )
				OnEvent( EVT_CONDROP ); // 失去连接
			break;
		}

		// 是否有数据收到
		if ( IsSmartAddressing() && dwBytes == sizeof(SOCKADDR_IN) )
			OnEvent( EVT_ZEROLENGTH );
		else if ( dwBytes > 0L )
		{
			buffer[dwBytes]=0;
			OnDataReceived( buffer, dwBytes);
		}
		Sleep(0);
*/
		DWORD dwIndex;
		WSANETWORKEVENTS networkEvents;

		dwIndex = WSAWaitForMultipleEvents(m_sCommEvent.EventTotal, m_sCommEvent.EventArray, FALSE, INFINITE, FALSE);

//		dwIndex = WSAWaitForMultipleEvents(m_sCommEvent.EventTotal, m_sCommEvent.EventArray, FALSE, m_OutTime.tv_sec*1000, FALSE);
		// 复位网络信号事件
		WSAEnumNetworkEvents( (SOCKET)m_hCommSocket,m_sCommEvent.EventArray[dwIndex - WSA_WAIT_EVENT_0], &networkEvents );
		// 如果是超时了
		if(  dwIndex-WSA_WAIT_TIMEOUT ==0 )
		{
			OnEvent( EVT_CONDROP );
			return;
		}
		if( networkEvents.lNetworkEvents & FD_READ )			//如果是数据到达
		{
			if(networkEvents.iErrorCode[FD_READ_BIT] != 0)
			{ 
				break;
			}
			memset( buffer,0, sizeof(buffer) );
			int iSend =0;
			// 先读取长度
 			if (memcmp(cSocketMode,"ASC",3)==0)
 			{
 				dwBytes = ReadComm(buffer, 4, dwTimeout);
 				iSend = atoi((char*)buffer);
 			}
 			else //if (m_TranCfg.iSocketMode==1 || m_TranCfg.iSocketMode==3)
			{
				dwBytes = ReadComm(buffer, 2, dwTimeout);
				char cLenHex[5]={0};
				m_gentool.FunBin2Hex( (char*)buffer, cLenHex, 2);
				iSend = strtol(cLenHex, NULL, 16 );
			}
			/*
#ifdef USE_CUP_LEN
			dwBytes = ReadComm(buffer, 2, dwTimeout);
			char cLenHex[5];
			memset( cLenHex, 0, sizeof(cLenHex));
			FunBin2Hex((char*)buffer, cLenHex, 2 );
			int iSend = strtol(cLenHex, NULL, 16);
#else
#ifdef USE_YADA_PREHOST 

#else
			dwBytes = ReadComm(buffer, 2, dwTimeout);
			char cLenHex[5]={0};
			m_gentool.FunBin2Hex( (char*)buffer, cLenHex, 2);
			int iSend = strtol(cLenHex, NULL, 16 );
#endif
#endif
			*/
			// 在读取内容 读取指定长度
			dwBytes = ReadComm(buffer, iSend, dwTimeout);
			if( dwBytes > 0 )
			{ 				
				buffer[dwBytes]=0;
				OnDataReceived( buffer, dwBytes);

			}
		}
		else if( networkEvents.lNetworkEvents & FD_CLOSE )	//如果是网络断路
		{
			WSAResetEvent(m_sCommEvent.EventArray[dwIndex - WSA_WAIT_EVENT_0]);
			m_gentool.WriteLog( LOG_LEVEL1,"前置机关闭网络连接!");
			OnEvent( EVT_CONDROP );
			return;
		}
	}
}
bool CMisSocket::IsOpen() const
{
	return ( INVALID_HANDLE_VALUE != m_hCommSocket );
}
bool CMisSocket::IsStart() const
{
	return ( NULL != m_hThread );
}

BOOL CMisSocket::IsServer() const
{
	return m_bServer;
}
BOOL CMisSocket::IsBroadcast() const
{
	return m_bBroadcast;
}
BOOL CMisSocket::IsSmartAddressing() const
{
	return m_bSmartAddressing;
}

SOCKET CMisSocket::GetSocket() const
{
	return (SOCKET) m_hCommSocket;
}
void CMisSocket::LockList()
{
	if ( NULL != m_hMutex )
		WaitForSingleObject( m_hMutex, INFINITE );
}
void CMisSocket::UnlockList()
{
	if ( NULL != m_hMutex )
		ReleaseMutex( m_hMutex );
}
UINT WINAPI CMisSocket::SocketThreadProc(LPVOID pParam)
{
	// reinterpret_cast用于各种指针的转化
	CMisSocket* pThis = reinterpret_cast<CMisSocket*>( pParam );
	_ASSERTE( pThis != NULL );

	pThis->RunThread();

	return 0L;
} 
SOCKET CMisSocket::WaitForConnection(SOCKET sock)
{
	// 接收一个连接
	return accept(sock, 0, 0);
}
void CMisSocket::OnEvent(UINT uEvent)
{
}
void CMisSocket::OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount)
{
}
void CMisSocket::SetSmartAddressing(BOOL bSmartAddressing)
{
	if ( !IsStart() )
		m_bSmartAddressing = bSmartAddressing;
}
void CMisSocket::SetServerState( BOOL bServer)
{
	// 非活动端口实例
	if ( !IsStart() )
		m_bServer = bServer;
}
//关闭一个连接并关闭一个socket，这将强迫所有的传输和接收失败
bool CMisSocket::ShutdownConnection(SOCKET sock)
{
	//
	shutdown(sock, SD_BOTH);
	return ( 0 == closesocket( sock ));
}

/**************************************************************
 *　名称: ReadComm                                            *
 *　类型: DWORD                                               *
 *　功能: 接收网络通讯数据                                    *
 *　入参: dwSize    指定读取的长度              　            *
 *        dwTimeout 等待端口状态变化超时时间                  *
 *　出参: lpBuffer  接收数据缓冲区                            *
 *　返回: 实际接收数据长度                                    *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 *  2008/04/27    采用Receive函数接收指定长度的数据，如果发生 *
 *                错误[-1]                                  *
**************************************************************/
DWORD CMisSocket::ReadComm(LPBYTE lpBuffer, DWORD dwSize, DWORD dwTimeout)
{
	_ASSERTE( IsOpen() );
	_ASSERTE( lpBuffer != NULL );
	if (lpBuffer == NULL || dwSize < 1L)
		return 0L;
	// 取端口状态变化的超时时间
	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;
	if ( INFINITE != dwTimeout ) 
	{
		stTime.tv_sec = 0;
		stTime.tv_usec = dwTimeout*1000;
		pstTime = &stTime;
	}
	SOCKET sLocal = (SOCKET) m_hCommSocket;
	// 设定描述符
	fd_set	fdRead  = { 0 };
	if ( !FD_ISSET( sLocal, &fdRead ) )
		FD_SET( sLocal, &fdRead );
	// 读取到的字节数
	DWORD dwBytesRead = 0L;
	// 执行成功则返回文件描述词状态已改变的个数，如果返回0代表在描述词状态改变前已超过timeout时间，
	// 当有错误发生时则返回-1
	int iResult = select( sLocal+1, &fdRead, NULL, NULL, pstTime );

	if ( iResult >= 0 )
	{
		// 发送消息广播或者点对点发送
		if (IsBroadcast() || IsSmartAddressing())
		{
			SOCKADDR_IN sockAddr = { 0 }; 
			int nOffset = IsSmartAddressing() ? sizeof(sockAddr) : 0;
			// 点对点传送时要在接收缓冲取存放发送方地址信息结构
			int nLen = sizeof(sockAddr);
			if ( dwSize < (DWORD) nLen)
			{
				SetLastError( ERROR_INVALID_USER_BUFFER );
				return -1L;
			}
			// 用来接收远程主机经指定的socket 传来的数据，并把数据存到由参数buf 指向的内存空间，参数len 为可接收数据的最大长度。
			// 参数flags 一般设0，参数sockAddr用来指定欲传送的网络地址
			iResult = recvfrom( sLocal, (LPSTR)&lpBuffer[nOffset], dwSize, 0, (LPSOCKADDR)&sockAddr, &nLen);
			// clear 'sin_zero', we will ignore them with 'SockAddrIn' anyway!
			memset(&sockAddr.sin_zero, 0, sizeof(sockAddr.sin_zero));
			if ( iResult >= 0)
			{	
				//锁定地址列表
				LockList();
				// 将发送地址转换到列表末尾
				SockAddrIn sockin;
				sockin.SetAddr( &sockAddr );
				m_AddrList.remove( sockin );
				m_AddrList.insert( m_AddrList.end(), sockin );
				// 点对点发送接收长度修改
				if ( IsSmartAddressing() )
				{
					memcpy(lpBuffer, &sockAddr, sizeof(sockAddr));
					iResult += sizeof(sockAddr);
				}
				// 解开地址列表 
				UnlockList();
			}
		}
		else
		{
			// TCP方式直接接收消息
			// 用来接收远端主机经指定的socket传来的数据，并把数据存到由参数buf 指向的内存空间，
			// 参数len为可接收数据的最大长度
			iResult = recv( sLocal, (LPSTR)lpBuffer, dwSize, 0);
			//iResult = Receive( (LPSTR)lpBuffer, dwSize, dwTimeout );
		}
		//dwBytesRead = (DWORD)((iResult > 0)?(iResult) : (-1));
		dwBytesRead = (DWORD)((iResult == dwSize)?(iResult) : (iResult));
	}

	return dwBytesRead;
}
/**************************************************************
 *　名称: WriteComm                                           *
 *　类型: DWORD                                               *
 *　功能: 发送网络通讯数据                                    *
 *　入参: lpBuffer  发送数据缓冲区                            *
 *        dwSize    发送数据长度                　            *
 *        dwTimeout 等待端口状态变化超时时间(单位秒)          *
 *　出参: 无                                                  *
 *　返回: 成功 实际发送数据长度                               *
 *        失败 返回 -1                                        *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 *  2008/04/27    修改返回值的初始化，如果没有发送指定长度返回*
 *                [-1]                                      *
 **************************************************************/
DWORD CMisSocket::WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout)
{
	_ASSERTE( IsOpen() );
	_ASSERTE( NULL != lpBuffer );
	// 如果没有建立连接或者缓冲区为空，则返回
	if( !IsOpen() || NULL == lpBuffer)
		return 0L;
	// 取端口状态变化的超时时间
	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;
	if ( INFINITE != dwTimeout )
	{
		stTime.tv_sec = 0;
		stTime.tv_usec = dwTimeout*1000*1000;
		pstTime = &stTime;
	}
	SOCKET s = (SOCKET) m_hCommSocket;
	// 设定描述符
	fd_set	fdWrite  = { 0 };
	if ( !FD_ISSET( s, &fdWrite ) )
		FD_SET( s, &fdWrite );
	// 发送的字节数
	DWORD dwBytesWritten = 0L;
	// 选择函数设定超时时间
	int iResult = select( s+1, NULL, &fdWrite, NULL, pstTime );
	if ( iResult >= 0)
	{
		// 发送消息广播或者点对点发送
		if (IsBroadcast() || IsSmartAddressing())
		{
			// use offset for Smart addressing
			int nOffset = IsSmartAddressing() ? sizeof(SOCKADDR_IN) : 0;
			if (IsSmartAddressing())
			{
				if ( dwCount < sizeof(SOCKADDR_IN))
				{
					SetLastError( ERROR_INVALID_USER_BUFFER );
					return -1L;
				}
				// 从缓冲区中获得地址
				SockAddrIn sockAddr;
				sockAddr.SetAddr((SOCKADDR_IN*) lpBuffer);

				// 获得地址然后发送
				if (sockAddr.sockAddrIn.sin_addr.s_addr != htonl(INADDR_BROADCAST) )
				{
					iResult = sendto( s, (LPCSTR)&lpBuffer[nOffset], dwCount-nOffset, 0,
						(LPSOCKADDR)sockAddr, sockAddr.Size());
					dwBytesWritten = (DWORD)((iResult >= 0)?(iResult) : (-1));
					return dwBytesWritten;
				}
			}
			// 向所有用户广播
			LockList();
			//循环发送信息
			CSockAddrList::iterator iter = m_AddrList.begin();
			for( ; iter != m_AddrList.end();  )
			{
				iResult = sendto( s, (LPCSTR)&lpBuffer[nOffset], dwCount-nOffset, 0, (LPSOCKADDR)(*iter), iter->Size());
				if (iResult < 0)
				{
					CSockAddrList::iterator deladdr = iter;
					++iter;	// 下一个
					m_AddrList.erase( deladdr );
				}
				else
					++iter;	// 下一个
			}
			UnlockList(); 
			// UDP总是返回true
			iResult = (int) dwCount - nOffset;
		}
		else
		{
			// 发送到单个客户端
			iResult = send( s, (LPCSTR)lpBuffer, dwCount, 0);
//			WriteLog( LOG_LEVEL2,"请求发送[%d]实际发送[%d]",dwCount, iResult);

		}
		// 修改返回值的初始化
		//dwBytesWritten = (DWORD)((iResult >= 0)?(iResult) : (-1));
		dwBytesWritten = (DWORD)((iResult == dwCount)?(iResult) : (-1));
	}
	return dwBytesWritten;
}
/**************************************************************
 *　名称: GetIPAddress                                        *
 *　类型: ULONG                                               *
 *　功能: 通过点IP地址串或者主机名取得32位字节码IP地址        *
 *　入参: strHostName   点IP地址串或者主机名    　            *
 *　出参: 无                                                  *
 *　返回: INADDR_NONE  IP地址错误                             *
		  ULONG        主机长整型表示的地址                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
ULONG CMisSocket::GetIPAddress( LPCTSTR strHostName )
{
	LPHOSTENT	lphostent;
	ULONG		uAddr = INADDR_NONE;

	if ( NULL != strHostName )
	{
#ifdef _UNICODE
		char strHost[HOSTNAME_SIZE] = { 0 };
		WideCharToMultiByte(CP_ACP, 0, strHostName, -1, strHost, sizeof(strHost), NULL, NULL );
#else
		LPCTSTR strHost = strHostName;
#endif
		// 将IP地址字符串转换成网络字节顺序的IP地址表示，用一个32位的无符号长整型表示,顺序从左到右,
		uAddr = inet_addr( strHostName );

		if ( (INADDR_NONE == uAddr) && ( strcmp( strHost, "255.255.255.255" ) ) )
		{
			// 通过主机名称取得IP地址
			if ( lphostent = gethostbyname( strHost ) )
				uAddr = *((ULONG *) lphostent->h_addr_list[0]);
		}
	}
	// 返回转换成主机长整型表示的地址 Intel处理器的字节是从右向左排列的
	return ntohl( uAddr );
}
/**************************************************************
 *　名称: GetPortNumber                                       *
 *　类型: USHORT                                              *
 *　功能: 通过服务名或者端口串值取得16位字节码端口            *
 *　入参: strServiceName   服务名或者端口串值   　            *
 *　出参: 无                                                  *
 *　返回: nPortNumber  服务端口值，为0错误                    *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
USHORT CMisSocket::GetPortNumber( LPCTSTR strServiceName )
{
	LPSERVENT	lpservent;
	USHORT		nPortNumber = 0;
	// 判断服务名是否为端口串
	if ( _istdigit( strServiceName[0] ) )
	{
		nPortNumber = (USHORT) _ttoi( strServiceName );
	}
	else 
	{
		LPCTSTR pstrDevice = strServiceName;
		// 通过服务名取得端口值
		if ( (lpservent = getservbyname( pstrDevice, NULL )) != NULL )
			nPortNumber = ntohs( lpservent->s_port );
	}

	return nPortNumber;
}
/**************************************************************
 *　名称: GetLocalName                                        *
 *　类型: BOOL                                                *
 *　功能: 取得连接的远程主机名称                              *
 *　入参: nSize   接收缓冲区长度                　            *
 *　出参: pName   接收缓冲区指针                              *
 *　返回: FALSE     失败                                      *
 *        TRUE      成功                                      *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
BOOL CMisSocket::GetLocalName( LPTSTR pName, UINT nSize )
{
	if ( pName != NULL && nSize > 0 )
	{
		char strHost[HOSTNAME_SIZE] = { 0 };
		// 获得机器名
		if (SOCKET_ERROR != gethostname( strHost, sizeof(strHost)) )
		{
			struct hostent* hp;
			hp = gethostbyname(strHost);
			if (hp != NULL)
			{
				// 检查缓冲区大小
				if (strlen(hp->h_name) > nSize)
				{
					SetLastError(ERROR_INSUFFICIENT_BUFFER);
					return FALSE;
				}
				strcpy(strHost, hp->h_name);
			}
			// Unicode转化
#ifdef _UNICODE
			return ( 0 != MultiByteToWideChar(CP_ACP, 0, strHost, -1, strName, nSize, NULL, NULL ) );
#else
			_tcscpy( pName, strHost );
			return TRUE;
#endif
		}
	}
	else
		SetLastError(ERROR_INVALID_PARAMETER);

	return FALSE;
}
/**************************************************************
 *　名称: GetLocalNameHost                                    *
 *　类型: int                                                 *
 *　功能: 取得连接的远程主机名称                              *
 *　入参: iBufLen   远程主机名最大长度          　            *
 *　出参: pStrBuf   远程主机名缓冲区                          *
 *　返回: ERR_BADPARAM 参数错误                               *
 *        ERR_WSAERROR UPON 错误                              *
 *        ERR_SUCCESS  成功                                   *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
int CMisSocket::GetLocalNameHost( char* pStrBuf, int iBufLen )
{
	if( pStrBuf == NULL )
		return ERR_BADPARAM;

	char strHost[512] = {0};
	hostent* hostEnt = NULL;
	int iLen = 0;

	gethostname( strHost, 512 );
	hostEnt = gethostbyname( strHost );

	if( hostEnt == NULL )
		return ERR_WSAERROR;

	iLen = strlen( hostEnt->h_name );

	if( iLen > iBufLen )
		return ERR_BADPARAM;

	memset( pStrBuf, 0, iBufLen );
	memcpy( pStrBuf, hostEnt->h_name, iLen );

	return ERR_SUCCESS;
}
/**************************************************************
 *　名称: GetLocalAddress                                     *
 *　类型: BOOL                                                *
 *　功能: 取得本地主机IP地址                                  *
 *　入参: nSize      接收缓冲区长度             　            *
 *　出参: pAddress   接收缓冲区指针                           *
 *　返回: FALSE     失败                                      *
 *        TRUE      成功                                      *
 *　修改记录      日期时间       操作者      原因       　　  *
 *　　　　　　　　----------    --------    ------　　   　　 *
 *　　　　　　    -08/03/28-    --FSW---     改版             *
 **************************************************************/
BOOL CMisSocket::GetLocalAddress(LPTSTR pAddress, UINT nSize)
{
	// 获得计算机本地地址
	if( pAddress != NULL && nSize > 0 )
	{
		char strHost[HOSTNAME_SIZE] = { 0 };
		// 获得机器名
		if (SOCKET_ERROR != gethostname( strHost, sizeof(strHost)) )
		{
			// 通过机器名获得本地地址信息
			struct hostent* hp;
			hp = gethostbyname(strHost);
			if ( hp != NULL && hp->h_addr_list[0] != NULL )
			{
				// 查看地址是否是4字节大小
				if ( hp->h_length < 4)
					return FALSE;
				// 转化地址到点
				strHost[0] = 0;
				// 创建地址字符串
				sprintf(strHost, "%u.%u.%u.%u",
					(UINT)(((PBYTE) hp->h_addr_list[0])[0]),
					(UINT)(((PBYTE) hp->h_addr_list[0])[1]),
					(UINT)(((PBYTE) hp->h_addr_list[0])[2]),
					(UINT)(((PBYTE) hp->h_addr_list[0])[3]));
				// 检查缓冲区是否足够
				if (strlen(strHost) > nSize)
				{
					SetLastError(ERROR_INSUFFICIENT_BUFFER);
					return FALSE;
				}
				// Unicode转换
#ifdef _UNICODE
				return ( 0 != MultiByteToWideChar(CP_ACP, 0, strHost, -1, strAddress, nSize, NULL, NULL ));
#else
				_tcscpy(pAddress, strHost);
				return TRUE;
#endif
			}
		}
	}
	else
		SetLastError(ERROR_INVALID_PARAMETER);

	return FALSE;
}
int CMisSocket::GetLocalIP( char* pStrIP )
{
	HOSTENT* hEnt = NULL;
	char szHostName[512] = {0};
	char szIP[30] = {0};
	char szAddrField[4] = {0};
	unsigned int ufield = 0;

	if( pStrIP == NULL )
		return ERR_BADPARAM;
	
	int  namelen = sizeof( m_sockaddr );

	if( getsockname( m_hSocket, (SOCKADDR*)&m_sockaddr, &namelen ) == SOCKET_ERROR )
		return ERR_WSAERROR;

	Long2DottedQuad( m_sockaddr.sin_addr.s_addr, pStrIP );

	return ERR_SUCCESS;
}

//获得socket名称
bool CMisSocket::GetSockName(SockAddrIn& saddr_in)
{
	if (IsOpen())
	{
		int namelen = saddr_in.Size();
		return (SOCKET_ERROR != getsockname(GetSocket(), (LPSOCKADDR)saddr_in, &namelen));
	}

	return false;
}
//关闭socket
void CMisSocket::CloseComm()
{
	if (IsOpen())
	{
		//调用ShutdownConnection关闭
		ShutdownConnection((SOCKET)m_hCommSocket);
		m_hCommSocket = INVALID_HANDLE_VALUE;
		m_bBroadcast = FALSE;
	}
}
//启动socket通信线程
bool CMisSocket::WatchComm()
{
	// 首先判断是否启动
	if ( !IsStart() )
	{
		// 判断是否打开通信，即socket是否成功创建
		if (IsOpen())
		{
			HANDLE hThread=NULL;
			UINT uiThreadId = 0;
			// 启动线程使用_beginthreadex
			// 安全参数// 堆栈// 线程程序// 线程参数//创建模式// 线程ID
			hThread = (HANDLE)_beginthreadex(NULL,0,SocketThreadProc,this,CREATE_SUSPENDED,&uiThreadId);			
			if ( NULL != hThread)
			{
				// 继续线程
				ResumeThread( hThread );
				m_hThread = hThread;
				return true;
			}
		}
	}
	return false;
}
void CMisSocket::StopComm()
{
	// Close Socket
	if (IsOpen())
	{
		CloseComm();
		//Sleep(50);
	}
	// Kill Thread
	if ( IsStart() )
	{
		//if (WaitForSingleObject(m_hThread, 5000L) == WAIT_TIMEOUT)
			TerminateThread(m_hThread, 1L);
		CloseHandle(m_hThread);
		m_hThread = NULL;
	}
	// Clear Address list
	if (!m_AddrList.empty())
		m_AddrList.clear();

	// Destroy Synchronization objects
	if (NULL != m_hMutex)
	{
		CloseHandle( m_hMutex );
		m_hMutex = NULL;
	}
//	WriteLog( LOG_LEVEL2,"关闭网络终端连接" );

}

void CMisSocket::SetOutTime(int iTime)
{
	m_OutTime.tv_sec	 = iTime;
	m_OutTime.tv_usec	 = 0;

}

int CMisSocket::GetLocalIP_More(char *cStrIP)
{
	char strHost[HOSTNAME_SIZE] = { 0 };
	// 获得机器名
	if( cStrIP == NULL )
		return ERR_BADPARAM;
	
	gethostname( strHost, sizeof(strHost));
	hostent *pHost=::gethostbyname(strHost);
	if( pHost == NULL )
		return ERR_WSAERROR;
	char buf[20]={0};
	for (int i = 0; pHost != NULL && pHost->h_addr_list[i] != NULL; i++) 
	{   
		//将它放入字符数组中便于应用
		strcpy(buf,inet_ntoa(*(struct in_addr *)pHost->h_addr_list[i]));
		//inet_ntoa(*(struct in_addr *)pHost->h_addr_list[i]); //IP地址
		sprintf(cStrIP,"%s",buf);
		
	} 
	if (strlen(cStrIP)>0)
		return ERR_SUCCESS;
	else
		return ERR_WSAERROR;
}
