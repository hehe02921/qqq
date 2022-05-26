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
	// Ĭ�ϳ�ʱʱ��
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
 *������: Create                                              *
 *������: int                                                 *
 *������: ���ӷ�������ָ���˿ڷ���                            *
 *�����: void                                  ��            *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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

	// domain ָ��ʹ�ú��ֵĵ�ַ����
	// nType SOCK_STREAM �ṩ˫�������ҿ�����������������TCP��֧��OOB ���ƣ����������ݴ���ǰ����ʹ��connect()����������״̬��
	//       SOCK_DGRAM ʹ�ò������������������ݰ�����
	// protocol ����ָ��socket��ʹ�õĴ���Э���ţ�ͨ���˲ο����ù�������Ϊ0����
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
 *������: CreateSocket                                        *
 *������: int                                                 *
 *������: ����������Ӧ��SOCKET                                *
 *�����: strServiceName    ���������߶˿ں�   ��             *
 *        nDomain           ��ַ����            ��            *
 *        nProtocol         Э������            ��            *
 *������: ��                                                  *
 *������: ERR_WSAERROR ʧ��                                   *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
int CMisSocket::CreateSocket(LPCTSTR strServiceName, int nDomain, int nProtocol, UINT uOptions /* = 0 */)
{
	if ( IsOpen() )
		return ERR_WSAERROR;

	memset( &m_sockaddr,0, sizeof( m_sockaddr ) );

	SOCKET SSock = socket(nDomain, nProtocol, 0 );

	if ( INVALID_SOCKET != SSock )
	{
		// ָ�������ṩ�˿ں�
		m_sockaddr.sin_port = htons( CMisSocket::GetPortNumber( strServiceName ) );
		if ( 0 != m_sockaddr.sin_port )
		{
			m_sockaddr.sin_addr.s_addr = htonl( INADDR_ANY );
			m_sockaddr.sin_family = nDomain;

			if ( uOptions & SO_REUSEADDR )
			{
				//�趨���ѡ��
				BOOL optval = TRUE;
				if ( SOCKET_ERROR == setsockopt( SSock, SOL_SOCKET, SO_REUSEADDR, (char *) &optval, sizeof( BOOL ) ) )
				{
					closesocket( SSock );
					return ERR_WSAERROR;
				}
			}
			// �ж��Ƿ�ΪUDPЭ��
			if( SOCK_DGRAM == nProtocol)
			{
				//�������㲥
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
				// �����Ҫ�㲥������Ҫ�趨������
				m_hMutex = CreateMutex(NULL, FALSE, NULL);
				if ( NULL == m_hMutex)
				{
					closesocket( SSock );
					return ERR_WSAERROR;
				}

			}
			// ��һ�����ص�ַ
			if ( SOCKET_ERROR == bind(SSock, (LPSOCKADDR)&m_sockaddr, sizeof(SOCKADDR_IN)))
			{
				closesocket( SSock );
				m_bBroadcast = FALSE;
				if (NULL != m_hMutex)
					CloseHandle( m_hMutex );
				m_hMutex = NULL;
				return ERR_WSAERROR;
			}
			// �����TCP������Ҫ����
			if (SOCK_STREAM == nProtocol)
			{
				if ( SOCKET_ERROR == listen(SSock, SOMAXCONN))
				{
					closesocket( SSock );
					return ERR_WSAERROR;
				}
			}
			// ����socket
			m_hCommSocket = (HANDLE) SSock;
			return ERR_SUCCESS;
		}
		else
			SetLastError(ERROR_INVALID_PARAMETER);
		// �ر�socket
		closesocket( SSock );
	}

	return ERR_WSAERROR;
}
/**************************************************************
 *������: Connect                                             *
 *������: int                                                 *
 *������: ���ӷ�������ָ���˿ڷ���                            *
 *�����: pStrRemote    Զ������IP                            *
 *        iPort         �˿ڡ�    ��                          *
 *��������pStrData  Ҫ���͵��ַ���              ��            *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR ���ʹ���                               *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: ConnectTo                                           *
 *������: BOOL                                                *
 *������: ���ӷ�������ָ���˿ڷ���                            *
 *�����: strDestination    Զ���������ƻ��IP����ʽ          *
 *        strServiceName    ���������߶˿ں�   ��             *
 *        nDomain           ��ַ����            ��            *
 *        nProtocol         Э������            ��            *
 *������: ��                                                  *
 *������: FALSE		   ʧ��                                   *
 *        TRUE         �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
BOOL CMisSocket::ConnectTo(LPCTSTR strDestination, LPCTSTR strServiceName, int nDomain, int nProtocol)
{
	if ( IsOpen() )
		return FALSE;

	SOCKADDR_IN sockAddr = { 0 };
	// �����ͻ���SOCKET
	SOCKET sock = socket(nDomain, nProtocol, 0);
	
	if ( INVALID_SOCKET != sock )
	{
		// ͨ�����������IP��ֵַ
		TCHAR strHost[HOSTNAME_SIZE] = { 0 };
		if (FALSE == CMisSocket::GetLocalName( strHost, sizeof(strHost)/sizeof(TCHAR)) )
		{
			m_gentool.WriteLog(LOG_LEVEL2,"��ȡ��������[%s]ʧ��[%d]", strHost,GetLastError() ); 
			closesocket( sock );
			return FALSE;
		}
		/*
		char cSocketType[30]={0};
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "GSM", cSocketType );
		if (strlen(cSocketType)>7)
		{
			if(0==checkIPStr(cSocketType)) //��IP��ַ
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

		//m_gentool.WriteLog(LOG_LEVEL2,"��������[%s]",  strHost );
	
// 		// ����IP��ַ������������ȡ�÷�������ֵַ
 		if ( strDestination[0] )
 		{
 			sockAddr.sin_addr.s_addr = htonl(CMisSocket::GetIPAddress( strDestination ) );
 		}
		// ���ݷ��������߶˿ڴ�ֵȡ��16λ�ֽ���˿�,����0Ϊʧ��
		sockAddr.sin_port = htons( CMisSocket::GetPortNumber( strServiceName ) );
		if ( 0 != sockAddr.sin_port )
		{
// 			int nNetTimeout= 5000;
// 			//setsockopt(sock,SOL_SOCKET, SO_CONNECT_TIME, (char *)&nNetTimeout,sizeof(int));
// 			sock.set_SendTimeout(iTimeOut); //
// 			sock.set_RecvTimeout(iTimeOut);//
			// ���ӷ�����
			if (SOCKET_ERROR == connect( sock, (LPSOCKADDR)&sockAddr, sizeof(SOCKADDR_IN)))
			{
				closesocket( sock );
				DWORD tt=GetLastError();
				return FALSE;
			}
			// ADD BY FSW AT 20080426 ����ģʽ
			ULONG ulMode = 0;
 			ioctlsocket(sock, FIONBIO, &ulMode);  
			// ����socket
			m_hCommSocket = (HANDLE) sock;
			// ��ʼ���¼�
			m_sCommEvent.EventArray[m_sCommEvent.EventTotal] = WSACreateEvent();
			WSAEventSelect((SOCKET)m_hCommSocket,m_sCommEvent.EventArray[m_sCommEvent.EventTotal],  FD_READ|FD_CLOSE);
			m_sCommEvent.EventTotal++;
			return TRUE;
		}
	}
	return FALSE;
}
/**************************************************************
 *������: Close                                               *
 *������: int                                                 *
 *������: �رն˿�����                                        *
 *�����: ��                                    ��            *
 *������: ��                                                  *
 *������: ERR_WSAERROR ���ʹ���                               *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: Send                                                *
 *������: int                                                 *
 *������: ��ָ���˿ڷ�������	                              *
 *�����: MisS      �˿��׽���                                *
 *��������iLen      �ַ�ָ�볤�ȡ���                          *
 *��������pStrData  Ҫ���͵��ַ���              ��            *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR ���ʹ���                               *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: Send                                                *
 *������: int                                                 *
 *������: ��Ĭ�϶˿ڷ�������	                              *
 *�����: iLen      �ַ�ָ�볤�ȡ���                          *
 *��������pStrData  Ҫ���͵��ַ���              ��            *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR ���ʹ���                               *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
int CMisSocket::Send( char* pStrData, int iLen )
{
	// �������
	if( pStrData == NULL || iLen == 0 || m_hSocket == INVALID_SOCKET)
		return ERR_BADPARAM;
	// ��������
	if( send( m_hSocket, pStrData, iLen, 0 ) == SOCKET_ERROR )
	{
        SetSocketError( "send() failed", WSAGetLastError() );
        return ERR_WSAERROR;
	}
	
	return ERR_SUCCESS;
}
/**************************************************************
 *������: Receive                                             *
 *������: int                                                 *
 *������: ��Ĭ�϶˿ڽ�������	                              *
 *�����: MisS      �˿��׽���                                *
 *������: pStrRev   �����ַ�������ָ��                        *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR ���ʹ���                               *
 *        iRet         �ɹ����ؽ����ֽ���                     *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: Receive                                             *
 *������: int                                                 *
 *������: ��Ĭ�϶˿ڽ�������	                              *
 *�����: iLen      ���ջ�������󳤶�                        *
 *������: pStrRev   �����ַ�������ָ��                        *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR ���ʹ���                               *
 *        iRet         �ɹ����ؽ����ֽ���                     *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
int CMisSocket::Receive( char* pStrRev, int iLen , DWORD dwTimeout)
{
	int		 iRead = 0;		// ��������յ�ȫ������
	long	 lRecv = 0L;	// �Ѿ����յ����������
	int		 i;				// ÿ�ν��յ������ݳ���

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
	// �趨������
	fd_set	fdWrite  = { 0 };
	if ( !FD_ISSET( sLocal, &fdWrite ) )
		FD_SET( sLocal, &fdWrite );
	// ���͵��ֽ���
	DWORD dwBytesWritten = 0L;
	// ѡ�����趨��ʱʱ��
	int iResult = select( sLocal+1, NULL, &fdWrite, NULL, pstTime );

//	int iRet = 0;
//	iRet = recv( m_hSocket, pStrRev, iLen, 0 );
	while ( iLen > iRead )
	{
		// ȡ�õ������ݵ����ݳ���
		lRecv = 0L;
		if ( ioctlsocket(sLocal, FIONREAD, (u_long *)(&lRecv)) < 0 )
		{
			return -1;
		}
		// �ж�׼�����ܵ����ݳ���
		i = ( lRecv<iLen ) ? (int)lRecv : iLen;
		// �Ӷ˿ڶ�ȡ����
		if ( (i = recv(sLocal, (char *)pStrRev, i, 0)) < 0 )
		{
			return -1;
		}
		// �ۼƽ��յĵ����ݳ��Ȳ�ƫ�ƽ��ջ�������ָ��
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
 *������: STBind                                              *
 *������: int                                                 *
 *������: ����SOCKET�����IP��ַ��˿�                        *
 *�����: pStrIP   IP��ַ    ��                               *
 *        iPort    ���ض˿�                                   *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR UPON ����                              *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: STListen                                            *
 *������: int                                                 *
 *������: ����SOCKET�����Ϊ����״̬                          *
 *�����: iQueuedConnections   �������ӿͻ�����               *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR UPON ����                              *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: STAccept                                            *
 *������: int                                                 *
 *������: ����SOCKET�����Ϊ����״̬                          *
 *�����: MisS   �������ӿͻ�����               *
 *������: ��                                                  *
 *������: ERR_WSAERROR UPON ����                              *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
int CMisSocket::STAccept( SOCKET MisS )
{	
	int Len = sizeof( m_rsockaddr );
	memset( &m_rsockaddr, 0, sizeof( m_rsockaddr ) );
	/*
	��MisS�ĵȴ����Ӷ����г�ȡ��һ�����ӣ�����һ����MisSͬ����µ��׽ӿڲ����ؾ��������������޵ȴ����ӣ�
	���׽ӿ�Ϊ��������ʽ����accept()�������ý���ֱ���µ����ӳ��֡�����׽ӿ�Ϊ��������ʽ�Ҷ����е�
	�����ӣ���accept()����һ������롣�ѽ������ӵ��׽ӿڲ������ڽ����µ����ӣ�ԭ�׽ӿ��Ա��ֿ��š�
	addr����Ϊһ�����ز�����������д����ΪͨѶ����֪������ʵ���ַ��addr������ʵ�ʸ�ʽ��ͨѶʱ�����ĵ�ַ��ȷ����
	addrlen����Ҳ��һ�����ز������ڵ���ʱ��ʼ��Ϊaddr��ָ�ĵ�ַ�ռ䣻�ڵ��ý���ʱ��������ʵ�ʷ��صĵ�ַ�ĳ���
	�����ֽ�����ʾ�����ú�����SOCK_STREAM���͵��������ӵ��׽ӿ�һ��ʹ�á����addr��addrlen����һ��Ϊ��NULL��
	�������������ܵ��׽ӿ�Զ�̵�ַ���κ���Ϣ��*/
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
//���socketҪ���ӵĵ�ַ
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
 *������: GetRemoteHost                                       *
 *������: int                                                 *
 *������: ȡ�����ӵ�Զ����������                              *
 *�����: iBufLen   Զ����������󳤶�          ��            *
 *������: pStrBuf   Զ��������������                          *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR UPON ����                              *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: SetSendTimeout                                      *
 *������: int                                                 *
 *������: ���÷��ͳ�ʱʱ��                                    *
 *�����: iTime  ���ͳ�ʱʱ��                   ��            *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR Socket����                             *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
int CMisSocket::SetSendTimeout( int iTime )
{
	if( iTime < 0 )
		return ERR_BADPARAM;

	if( setsockopt( m_hSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&iTime, sizeof( iTime ) ) == SOCKET_ERROR )
	{
		SetSocketError( "setsockopt ʧ��.", WSAGetLastError() );
		return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}
/**************************************************************
 *������: SetRecvTimeout                                      *
 *������: int                                                 *
 *������: ���ý��ճ�ʱʱ��                                    *
 *�����: iTime  ���ճ�ʱʱ��                   ��            *
 *������: ��                                                  *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR Socket����                             *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
int CMisSocket::SetRecvTimeout( int iTime )
{
	if( iTime < 0 )
		return ERR_BADPARAM;

	if( setsockopt( m_hSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTime, sizeof( iTime ) ) == SOCKET_ERROR )
	{
		SetSocketError( "SetRecvTimeout ʧ��.", WSAGetLastError() );
		return ERR_WSAERROR;
	}

	return ERR_SUCCESS;
}
/**************************************************************
 *������: SetSocketError                                      *
 *������: void                                                *
 *������: ���ô�����Ϣ�����󷵻���                            *
 *�����: pStrErr   ������Ϣ��                  ��            *
 *        iErr      ��������ֵ  ����                          *
 *������: ��                                                  *
 *������: ��                                                  *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
void CMisSocket::SetSocketError( char* pStrErr, int iErrID )
{
	memset( m_cLastError, 0, ERR_MAXLENGTH ); 
	memcpy( m_cLastError, pStrErr, strlen( pStrErr ) );
	m_cLastError[strlen(pStrErr)+1] = '\0';

	m_iErrorNumber = iErrID ;
}
/**************************************************************
 *������: GetSocketError                                      *
 *������: void                                                *
 *������: ���ô�����Ϣ�����󷵻���                            *
 *�����: ��                    ����                          *
 *������: pStrErr   ������Ϣ������                            *
 *        piErrID   ������Ϣֵ                                *
 *������: ��                                                  *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
void CMisSocket::GetSocketError( char* pStrErr, int* piErrID )
{
	// ȡ�ô�����Ϣ����
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
 *������: Long2DottedQuad                                     *
 *������: void                                                *
 *������: ��32λLONGֵת��IP��ַΪ�ַ�����ʽ(255.255.255.255) *
 *�����: uLong   IP��ַ32λֵ                  ��            *
 *������: pCBuf   ���ص��ַ���                                *
 *������: ��                                                  *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
		//�Ƿ�㲥ģʽ
		if ( !IsBroadcast() )
		{
			SOCKET sock = (SOCKET) m_hCommSocket;
			sock = WaitForConnection( sock );

			// �ȴ��µ�����
			if (sock != INVALID_SOCKET)
			{
				//�ر�����
				ShutdownConnection( (SOCKET) m_hCommSocket);
				m_hCommSocket = (HANDLE) sock;
				OnEvent( EVT_CONSUCCESS ); // connect
			}
			else
			{
				// ����Ѿ��ر��򲻷����¼���������
				if (IsOpen())
					OnEvent( EVT_CONFAILURE ); // �ȴ�ʧ��
				return;
			}
		}
	}
	//���socket�Ѿ�����
	while( IsOpen() )
	{
/*
		// ��������ʽsocket���ȴ��¼�֪ͨ
		dwBytes = ReadComm(buffer, sizeof(buffer), dwTimeout);

		// ����д�����
		if (dwBytes == (DWORD)-1)
		{
			// ���Ҫ�رգ��򲻷����¼�
			if ( IsOpen() )
				OnEvent( EVT_CONDROP ); // ʧȥ����
			break;
		}

		// �Ƿ��������յ�
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
		// ��λ�����ź��¼�
		WSAEnumNetworkEvents( (SOCKET)m_hCommSocket,m_sCommEvent.EventArray[dwIndex - WSA_WAIT_EVENT_0], &networkEvents );
		// ����ǳ�ʱ��
		if(  dwIndex-WSA_WAIT_TIMEOUT ==0 )
		{
			OnEvent( EVT_CONDROP );
			return;
		}
		if( networkEvents.lNetworkEvents & FD_READ )			//��������ݵ���
		{
			if(networkEvents.iErrorCode[FD_READ_BIT] != 0)
			{ 
				break;
			}
			memset( buffer,0, sizeof(buffer) );
			int iSend =0;
			// �ȶ�ȡ����
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
			// �ڶ�ȡ���� ��ȡָ������
			dwBytes = ReadComm(buffer, iSend, dwTimeout);
			if( dwBytes > 0 )
			{ 				
				buffer[dwBytes]=0;
				OnDataReceived( buffer, dwBytes);

			}
		}
		else if( networkEvents.lNetworkEvents & FD_CLOSE )	//����������·
		{
			WSAResetEvent(m_sCommEvent.EventArray[dwIndex - WSA_WAIT_EVENT_0]);
			m_gentool.WriteLog( LOG_LEVEL1,"ǰ�û��ر���������!");
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
	// reinterpret_cast���ڸ���ָ���ת��
	CMisSocket* pThis = reinterpret_cast<CMisSocket*>( pParam );
	_ASSERTE( pThis != NULL );

	pThis->RunThread();

	return 0L;
} 
SOCKET CMisSocket::WaitForConnection(SOCKET sock)
{
	// ����һ������
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
	// �ǻ�˿�ʵ��
	if ( !IsStart() )
		m_bServer = bServer;
}
//�ر�һ�����Ӳ��ر�һ��socket���⽫ǿ�����еĴ���ͽ���ʧ��
bool CMisSocket::ShutdownConnection(SOCKET sock)
{
	//
	shutdown(sock, SD_BOTH);
	return ( 0 == closesocket( sock ));
}

/**************************************************************
 *������: ReadComm                                            *
 *������: DWORD                                               *
 *������: ��������ͨѶ����                                    *
 *�����: dwSize    ָ����ȡ�ĳ���              ��            *
 *        dwTimeout �ȴ��˿�״̬�仯��ʱʱ��                  *
 *������: lpBuffer  �������ݻ�����                            *
 *������: ʵ�ʽ������ݳ���                                    *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 *  2008/04/27    ����Receive��������ָ�����ȵ����ݣ�������� *
 *                ����[-1]                                  *
**************************************************************/
DWORD CMisSocket::ReadComm(LPBYTE lpBuffer, DWORD dwSize, DWORD dwTimeout)
{
	_ASSERTE( IsOpen() );
	_ASSERTE( lpBuffer != NULL );
	if (lpBuffer == NULL || dwSize < 1L)
		return 0L;
	// ȡ�˿�״̬�仯�ĳ�ʱʱ��
	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;
	if ( INFINITE != dwTimeout ) 
	{
		stTime.tv_sec = 0;
		stTime.tv_usec = dwTimeout*1000;
		pstTime = &stTime;
	}
	SOCKET sLocal = (SOCKET) m_hCommSocket;
	// �趨������
	fd_set	fdRead  = { 0 };
	if ( !FD_ISSET( sLocal, &fdRead ) )
		FD_SET( sLocal, &fdRead );
	// ��ȡ�����ֽ���
	DWORD dwBytesRead = 0L;
	// ִ�гɹ��򷵻��ļ�������״̬�Ѹı�ĸ������������0������������״̬�ı�ǰ�ѳ���timeoutʱ�䣬
	// ���д�����ʱ�򷵻�-1
	int iResult = select( sLocal+1, &fdRead, NULL, NULL, pstTime );

	if ( iResult >= 0 )
	{
		// ������Ϣ�㲥���ߵ�Ե㷢��
		if (IsBroadcast() || IsSmartAddressing())
		{
			SOCKADDR_IN sockAddr = { 0 }; 
			int nOffset = IsSmartAddressing() ? sizeof(sockAddr) : 0;
			// ��Ե㴫��ʱҪ�ڽ��ջ���ȡ��ŷ��ͷ���ַ��Ϣ�ṹ
			int nLen = sizeof(sockAddr);
			if ( dwSize < (DWORD) nLen)
			{
				SetLastError( ERROR_INVALID_USER_BUFFER );
				return -1L;
			}
			// ��������Զ��������ָ����socket ���������ݣ��������ݴ浽�ɲ���buf ָ����ڴ�ռ䣬����len Ϊ�ɽ������ݵ���󳤶ȡ�
			// ����flags һ����0������sockAddr����ָ�������͵������ַ
			iResult = recvfrom( sLocal, (LPSTR)&lpBuffer[nOffset], dwSize, 0, (LPSOCKADDR)&sockAddr, &nLen);
			// clear 'sin_zero', we will ignore them with 'SockAddrIn' anyway!
			memset(&sockAddr.sin_zero, 0, sizeof(sockAddr.sin_zero));
			if ( iResult >= 0)
			{	
				//������ַ�б�
				LockList();
				// �����͵�ַת�����б�ĩβ
				SockAddrIn sockin;
				sockin.SetAddr( &sockAddr );
				m_AddrList.remove( sockin );
				m_AddrList.insert( m_AddrList.end(), sockin );
				// ��Ե㷢�ͽ��ճ����޸�
				if ( IsSmartAddressing() )
				{
					memcpy(lpBuffer, &sockAddr, sizeof(sockAddr));
					iResult += sizeof(sockAddr);
				}
				// �⿪��ַ�б� 
				UnlockList();
			}
		}
		else
		{
			// TCP��ʽֱ�ӽ�����Ϣ
			// ��������Զ��������ָ����socket���������ݣ��������ݴ浽�ɲ���buf ָ����ڴ�ռ䣬
			// ����lenΪ�ɽ������ݵ���󳤶�
			iResult = recv( sLocal, (LPSTR)lpBuffer, dwSize, 0);
			//iResult = Receive( (LPSTR)lpBuffer, dwSize, dwTimeout );
		}
		//dwBytesRead = (DWORD)((iResult > 0)?(iResult) : (-1));
		dwBytesRead = (DWORD)((iResult == dwSize)?(iResult) : (iResult));
	}

	return dwBytesRead;
}
/**************************************************************
 *������: WriteComm                                           *
 *������: DWORD                                               *
 *������: ��������ͨѶ����                                    *
 *�����: lpBuffer  �������ݻ�����                            *
 *        dwSize    �������ݳ���                ��            *
 *        dwTimeout �ȴ��˿�״̬�仯��ʱʱ��(��λ��)          *
 *������: ��                                                  *
 *������: �ɹ� ʵ�ʷ������ݳ���                               *
 *        ʧ�� ���� -1                                        *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 *  2008/04/27    �޸ķ���ֵ�ĳ�ʼ�������û�з���ָ�����ȷ���*
 *                [-1]                                      *
 **************************************************************/
DWORD CMisSocket::WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout)
{
	_ASSERTE( IsOpen() );
	_ASSERTE( NULL != lpBuffer );
	// ���û�н������ӻ��߻�����Ϊ�գ��򷵻�
	if( !IsOpen() || NULL == lpBuffer)
		return 0L;
	// ȡ�˿�״̬�仯�ĳ�ʱʱ��
	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;
	if ( INFINITE != dwTimeout )
	{
		stTime.tv_sec = 0;
		stTime.tv_usec = dwTimeout*1000*1000;
		pstTime = &stTime;
	}
	SOCKET s = (SOCKET) m_hCommSocket;
	// �趨������
	fd_set	fdWrite  = { 0 };
	if ( !FD_ISSET( s, &fdWrite ) )
		FD_SET( s, &fdWrite );
	// ���͵��ֽ���
	DWORD dwBytesWritten = 0L;
	// ѡ�����趨��ʱʱ��
	int iResult = select( s+1, NULL, &fdWrite, NULL, pstTime );
	if ( iResult >= 0)
	{
		// ������Ϣ�㲥���ߵ�Ե㷢��
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
				// �ӻ������л�õ�ַ
				SockAddrIn sockAddr;
				sockAddr.SetAddr((SOCKADDR_IN*) lpBuffer);

				// ��õ�ַȻ����
				if (sockAddr.sockAddrIn.sin_addr.s_addr != htonl(INADDR_BROADCAST) )
				{
					iResult = sendto( s, (LPCSTR)&lpBuffer[nOffset], dwCount-nOffset, 0,
						(LPSOCKADDR)sockAddr, sockAddr.Size());
					dwBytesWritten = (DWORD)((iResult >= 0)?(iResult) : (-1));
					return dwBytesWritten;
				}
			}
			// �������û��㲥
			LockList();
			//ѭ��������Ϣ
			CSockAddrList::iterator iter = m_AddrList.begin();
			for( ; iter != m_AddrList.end();  )
			{
				iResult = sendto( s, (LPCSTR)&lpBuffer[nOffset], dwCount-nOffset, 0, (LPSOCKADDR)(*iter), iter->Size());
				if (iResult < 0)
				{
					CSockAddrList::iterator deladdr = iter;
					++iter;	// ��һ��
					m_AddrList.erase( deladdr );
				}
				else
					++iter;	// ��һ��
			}
			UnlockList(); 
			// UDP���Ƿ���true
			iResult = (int) dwCount - nOffset;
		}
		else
		{
			// ���͵������ͻ���
			iResult = send( s, (LPCSTR)lpBuffer, dwCount, 0);
//			WriteLog( LOG_LEVEL2,"������[%d]ʵ�ʷ���[%d]",dwCount, iResult);

		}
		// �޸ķ���ֵ�ĳ�ʼ��
		//dwBytesWritten = (DWORD)((iResult >= 0)?(iResult) : (-1));
		dwBytesWritten = (DWORD)((iResult == dwCount)?(iResult) : (-1));
	}
	return dwBytesWritten;
}
/**************************************************************
 *������: GetIPAddress                                        *
 *������: ULONG                                               *
 *������: ͨ����IP��ַ������������ȡ��32λ�ֽ���IP��ַ        *
 *�����: strHostName   ��IP��ַ������������    ��            *
 *������: ��                                                  *
 *������: INADDR_NONE  IP��ַ����                             *
		  ULONG        ���������ͱ�ʾ�ĵ�ַ                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
		// ��IP��ַ�ַ���ת���������ֽ�˳���IP��ַ��ʾ����һ��32λ���޷��ų����ͱ�ʾ,˳�������,
		uAddr = inet_addr( strHostName );

		if ( (INADDR_NONE == uAddr) && ( strcmp( strHost, "255.255.255.255" ) ) )
		{
			// ͨ����������ȡ��IP��ַ
			if ( lphostent = gethostbyname( strHost ) )
				uAddr = *((ULONG *) lphostent->h_addr_list[0]);
		}
	}
	// ����ת�������������ͱ�ʾ�ĵ�ַ Intel���������ֽ��Ǵ����������е�
	return ntohl( uAddr );
}
/**************************************************************
 *������: GetPortNumber                                       *
 *������: USHORT                                              *
 *������: ͨ�����������߶˿ڴ�ֵȡ��16λ�ֽ���˿�            *
 *�����: strServiceName   ���������߶˿ڴ�ֵ   ��            *
 *������: ��                                                  *
 *������: nPortNumber  ����˿�ֵ��Ϊ0����                    *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
USHORT CMisSocket::GetPortNumber( LPCTSTR strServiceName )
{
	LPSERVENT	lpservent;
	USHORT		nPortNumber = 0;
	// �жϷ������Ƿ�Ϊ�˿ڴ�
	if ( _istdigit( strServiceName[0] ) )
	{
		nPortNumber = (USHORT) _ttoi( strServiceName );
	}
	else 
	{
		LPCTSTR pstrDevice = strServiceName;
		// ͨ��������ȡ�ö˿�ֵ
		if ( (lpservent = getservbyname( pstrDevice, NULL )) != NULL )
			nPortNumber = ntohs( lpservent->s_port );
	}

	return nPortNumber;
}
/**************************************************************
 *������: GetLocalName                                        *
 *������: BOOL                                                *
 *������: ȡ�����ӵ�Զ����������                              *
 *�����: nSize   ���ջ���������                ��            *
 *������: pName   ���ջ�����ָ��                              *
 *������: FALSE     ʧ��                                      *
 *        TRUE      �ɹ�                                      *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
BOOL CMisSocket::GetLocalName( LPTSTR pName, UINT nSize )
{
	if ( pName != NULL && nSize > 0 )
	{
		char strHost[HOSTNAME_SIZE] = { 0 };
		// ��û�����
		if (SOCKET_ERROR != gethostname( strHost, sizeof(strHost)) )
		{
			struct hostent* hp;
			hp = gethostbyname(strHost);
			if (hp != NULL)
			{
				// ��黺������С
				if (strlen(hp->h_name) > nSize)
				{
					SetLastError(ERROR_INSUFFICIENT_BUFFER);
					return FALSE;
				}
				strcpy(strHost, hp->h_name);
			}
			// Unicodeת��
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
 *������: GetLocalNameHost                                    *
 *������: int                                                 *
 *������: ȡ�����ӵ�Զ����������                              *
 *�����: iBufLen   Զ����������󳤶�          ��            *
 *������: pStrBuf   Զ��������������                          *
 *������: ERR_BADPARAM ��������                               *
 *        ERR_WSAERROR UPON ����                              *
 *        ERR_SUCCESS  �ɹ�                                   *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
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
 *������: GetLocalAddress                                     *
 *������: BOOL                                                *
 *������: ȡ�ñ�������IP��ַ                                  *
 *�����: nSize      ���ջ���������             ��            *
 *������: pAddress   ���ջ�����ָ��                           *
 *������: FALSE     ʧ��                                      *
 *        TRUE      �ɹ�                                      *
 *���޸ļ�¼      ����ʱ��       ������      ԭ��       ����  *
 *����������������----------    --------    ------����   ���� *
 *������������    -08/03/28-    --FSW---     �İ�             *
 **************************************************************/
BOOL CMisSocket::GetLocalAddress(LPTSTR pAddress, UINT nSize)
{
	// ��ü�������ص�ַ
	if( pAddress != NULL && nSize > 0 )
	{
		char strHost[HOSTNAME_SIZE] = { 0 };
		// ��û�����
		if (SOCKET_ERROR != gethostname( strHost, sizeof(strHost)) )
		{
			// ͨ����������ñ��ص�ַ��Ϣ
			struct hostent* hp;
			hp = gethostbyname(strHost);
			if ( hp != NULL && hp->h_addr_list[0] != NULL )
			{
				// �鿴��ַ�Ƿ���4�ֽڴ�С
				if ( hp->h_length < 4)
					return FALSE;
				// ת����ַ����
				strHost[0] = 0;
				// ������ַ�ַ���
				sprintf(strHost, "%u.%u.%u.%u",
					(UINT)(((PBYTE) hp->h_addr_list[0])[0]),
					(UINT)(((PBYTE) hp->h_addr_list[0])[1]),
					(UINT)(((PBYTE) hp->h_addr_list[0])[2]),
					(UINT)(((PBYTE) hp->h_addr_list[0])[3]));
				// ��黺�����Ƿ��㹻
				if (strlen(strHost) > nSize)
				{
					SetLastError(ERROR_INSUFFICIENT_BUFFER);
					return FALSE;
				}
				// Unicodeת��
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

//���socket����
bool CMisSocket::GetSockName(SockAddrIn& saddr_in)
{
	if (IsOpen())
	{
		int namelen = saddr_in.Size();
		return (SOCKET_ERROR != getsockname(GetSocket(), (LPSOCKADDR)saddr_in, &namelen));
	}

	return false;
}
//�ر�socket
void CMisSocket::CloseComm()
{
	if (IsOpen())
	{
		//����ShutdownConnection�ر�
		ShutdownConnection((SOCKET)m_hCommSocket);
		m_hCommSocket = INVALID_HANDLE_VALUE;
		m_bBroadcast = FALSE;
	}
}
//����socketͨ���߳�
bool CMisSocket::WatchComm()
{
	// �����ж��Ƿ�����
	if ( !IsStart() )
	{
		// �ж��Ƿ��ͨ�ţ���socket�Ƿ�ɹ�����
		if (IsOpen())
		{
			HANDLE hThread=NULL;
			UINT uiThreadId = 0;
			// �����߳�ʹ��_beginthreadex
			// ��ȫ����// ��ջ// �̳߳���// �̲߳���//����ģʽ// �߳�ID
			hThread = (HANDLE)_beginthreadex(NULL,0,SocketThreadProc,this,CREATE_SUSPENDED,&uiThreadId);			
			if ( NULL != hThread)
			{
				// �����߳�
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
//	WriteLog( LOG_LEVEL2,"�ر������ն�����" );

}

void CMisSocket::SetOutTime(int iTime)
{
	m_OutTime.tv_sec	 = iTime;
	m_OutTime.tv_usec	 = 0;

}

int CMisSocket::GetLocalIP_More(char *cStrIP)
{
	char strHost[HOSTNAME_SIZE] = { 0 };
	// ��û�����
	if( cStrIP == NULL )
		return ERR_BADPARAM;
	
	gethostname( strHost, sizeof(strHost));
	hostent *pHost=::gethostbyname(strHost);
	if( pHost == NULL )
		return ERR_WSAERROR;
	char buf[20]={0};
	for (int i = 0; pHost != NULL && pHost->h_addr_list[i] != NULL; i++) 
	{   
		//���������ַ������б���Ӧ��
		strcpy(buf,inet_ntoa(*(struct in_addr *)pHost->h_addr_list[i]));
		//inet_ntoa(*(struct in_addr *)pHost->h_addr_list[i]); //IP��ַ
		sprintf(cStrIP,"%s",buf);
		
	} 
	if (strlen(cStrIP)>0)
		return ERR_SUCCESS;
	else
		return ERR_WSAERROR;
}
