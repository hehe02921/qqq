// IngPosCom.cpp: implementation of the CIngPosCom class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Bank_Ist.h"
#include "IngPosCom.h"
#include "VirPos.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

extern CGenTool m_gentool;

extern ListStru    liststru[3000];


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CIngPosCom::CIngPosCom()
{
	m_hComDev = INVALID_HANDLE_VALUE;
	m_hMainDlg = NULL;
	
	m_bConneted = FALSE;
	m_pThread = NULL;
	m_iBufLen = 0;
	
	memset( m_ReadBuf, 0, sizeof(m_ReadBuf) );
	srand( (unsigned)time( NULL ) ); 
	m_dwStart = 0;
	
	memset( &m_TranRetInfo, 0, sizeof(TranRetInfo) );
	
	
	m_bKeyIgnore = FALSE;
	
	iExitPro = 0;
	m_bQueryList = FALSE;
	m_bPackEnd = FALSE;
	m_bLogin=FALSE;
}

CIngPosCom::~CIngPosCom()
{
	CommClose();
}


void CIngPosCom::SetTradeInfo( TradeInfo *pTradeInfo )
{
	memset(&m_TradeInfo,0,sizeof(TradeInfo));
	memcpy(&m_TradeInfo,pTradeInfo,sizeof(TradeInfo));
}

void CIngPosCom::GetTranResultInfo(TranRetInfo * pResp)
{
	memset(pResp,0,sizeof(TranRetInfo));
	memcpy(pResp,&m_TranRetInfo,sizeof(TranRetInfo));
}

UINT CIngPosCom::PinCommReadProc( LPVOID pParam )
{
	DWORD		dwLength = 1;
	COMSTAT		ComStat;
	CIngPosCom	*pComm;
	int			iReturn =0;
	
	int			iOldRecevie = 0;
	DWORD		 dwWaitObject;
	DWORD		 dwMask = EV_RXCHAR;
	char cTemp[2048]={0};
	int         ideflen = 0;

	memset(&ComStat, 0, sizeof(COMSTAT));
	pComm = reinterpret_cast<CIngPosCom*>(pParam);
	

	while( pComm->m_bConneted )
	{
		dwWaitObject = WaitForSingleObject( pComm->m_hRecvDataEvent,   INFINITE );
		int ii = GetTickCount()-pComm->m_dwStart;
		//WriteLog( LOG_LEVEL2,"[�����豸][����߳�]ʣ��ʱ��[%d]", -ii/1000);
		if( ii > 0  ) //�ѳ�ʱ
		{
			//add by liuwd 20091218
			pComm->m_bKeyIgnore = FALSE; //���˳����ڵȴ�״̬
			//end add

			ResetEvent( pComm->m_hRecvDataEvent );
			PostMessage( pComm->m_hMainDlg,WM_COMMNOTIFY,PINPAD_TIME_OUT,NULL);
			iOldRecevie = 0;
			m_gentool.WriteLog( LOG_LEVEL2,"[�����豸][����߳�]:��ȡ�������ݳ�ʱ");
			continue;
		}
		if( WAIT_OBJECT_0  == dwWaitObject )  
		{
			//Sleep(1000);
			ResetEvent( pComm->m_hRecvDataEvent );
			//WriteLog( LOG_LEVEL2,"[�����豸][����߳�]:������ʱ���ڼ��1���ȡ����");
			if ( iOldRecevie == 0 )
			{
				//WriteLog( LOG_LEVEL2,"[�����豸][����߳�]:��ջ���");
				memset( pComm->m_ReadBuf, 0, sizeof(pComm->m_ReadBuf));
			}
			dwLength = pComm->CommRead( pComm->m_ReadBuf+iOldRecevie, MAX_CFG_BUF  );
			if(dwLength == 0) //û�н��յ��ַ�
			{
				//WriteLog( LOG_LEVEL2,"[�����豸][����߳�]:������������");
				Sleep(500);
				SetEvent( pComm->m_hRecvDataEvent ); //����ȥ��
				continue;
			}
			iOldRecevie += dwLength;
			if ( 1 == iOldRecevie && pComm->m_ReadBuf[0]=='\x06' ) //������Ӧ��
			{
//				WriteLog( LOG_LEVEL2,"[�����豸][����߳�]�����豸ȷ�ϱ�ʶ�������ȴ�����ָ��");
				PostMessage( pComm->m_hMainDlg,WM_COMMNOTIFY,PINPAD_ACQ_SND,NULL);
				SetEvent( pComm->m_hRecvDataEvent );
				pComm->m_dwStart=GetTickCount()+POSCMDOUT; //����Ӧ��ʱʱ��
				iOldRecevie = 0;
				pComm->m_iBufLen =0;
				continue;
			}
			//add by liuwd 20091223
			else if(1 == iOldRecevie && pComm->m_ReadBuf[0]=='\x00' )
			{
				SetEvent( pComm->m_hRecvDataEvent );
				iOldRecevie = 0;
				pComm->m_iBufLen =0;
				continue;
			}
			//end add
			else if ( iOldRecevie < 4) //��û���չ�,������
			{
				SetEvent( pComm->m_hRecvDataEvent );
				continue;
			}
			else if ( iOldRecevie >= 3 )
			{
				char cLenHex[5]={0};
				if ( pComm->m_ReadBuf[0] == '\x06'  ) //�ȼ���Ƿ���ͷ����
					m_gentool.FunBin2Hex(pComm->m_ReadBuf+2, cLenHex, 2 );
				else
					m_gentool.FunBin2Hex(pComm->m_ReadBuf+1, cLenHex, 2 );
				// ����STX+XX+XX+[]+ETX+LRC�е���������ֽ� 
				int iLen = atol( cLenHex)+5;
				//WriteLog( LOG_LEVEL2,"[�����豸]�Ѿ���ȡ[%d]��Ҫ[%d]",iOldRecevie,iLen);
				if ( iLen > iOldRecevie )
				{
					// ������ȡ������������
					SetEvent( pComm->m_hRecvDataEvent );
					continue;
				}
			}

			
		//	char cTemp[1024]={0};
		//	sprintf(cTemp,"020262DF010102DF020146DF04024313DF0681F0DF020146DF460A30303139202020202020DF470A38313136313520202020DF1106313330393131DF12083135323231313535DF130F313034313532323533333131303231DF441957444C20202020202020202020202020202020202020202020DF4518CEDAC0BCBAC6CCD8CAD0CEACB6E0C0FBB3ACCAD0D3D0CFDEDF0309524D42202D302E3230DF0A03000066DF1003000006DF1803000005DF1A0C393235343938333334373738DF1B06202020202020DF1C0430393131DF1D06313534333532DF1E0E2A2A2A2A2A2A2A2A2A2A2A2A3834DF1F052A2A2A2A2ADF210111DF2C0A20202020D2F8C1AABFA8DF2F020000DF07023030035D");
		//	sprintf(cTemp,"020280DF010102DF020145DF04022954DF06820101DF020145DF460A30303139202020202020DF470A38313136313520202020DF1106313330393131DF12083135323231313535DF130F313034313532323533333131303231DF441957444C20202020202020202020202020202020202020202020DF4518CEDAC0BCBAC6CCD8CAD0CEACB6E0C0FBB3ACCAD0D3D0CFDEDF0309524D422020302E3230DF0A03000065DF1003000005DF1A0C393235343938333334373738DF1B06202020202020DF1C0430393131DF1D06313534323133DF1E0E2A2A2A2A2A2A2A2A2A2A2A2A3834DF1F052A2A2A2A2ADF210111DF2C0A20202020D2F8C1AABFA8DF2F020040DF69143235313930393131353635333439333538313831DF070230300343");
		//	iOldRecevie=strlen(cTemp)/2;
		//	m_gentool.FunHex2Bin(cTemp,pComm->m_ReadBuf,iOldRecevie);
	 


			m_gentool.WriteLog( LOG_LEVEL1,"[�����豸]���յ�POS���ذ�����[%d]!", iOldRecevie);
#ifdef  TEST_VER
			m_gentool.ShowBin2HexStr(  "[�����豸]���յ�POS�������ݰ�" ,pComm->m_ReadBuf, iOldRecevie );

#else
			if(iOldRecevie<30)
				m_gentool.ShowBin2HexStr(  "[�����豸]���յ�POS�������ݰ�" ,pComm->m_ReadBuf, iOldRecevie );
#endif
			memset(pComm->m_MoniBuf, 0, sizeof(pComm->m_MoniBuf));
			pComm->m_MoniLen = iOldRecevie;
			memcpy(pComm->m_MoniBuf, pComm->m_ReadBuf, pComm->m_MoniLen);


			// ��ȡ�������ĺ��������
			//add by liuwd 20091218
			pComm->m_bKeyIgnore = FALSE; //�ѳɹ��յ���,�����ٵȴ���
			//end add

			int iCheckRet = 0;
			char cretinvoice[10];
			memset(cretinvoice, 0, sizeof(cretinvoice));
			iCheckRet = pComm->CheckSucRet(iOldRecevie, cretinvoice);
			
			if(iCheckRet > 0 )
			{
				memset(pComm->cRetInvoice, 0, sizeof(pComm->cRetInvoice));
				if( iCheckRet == 1 )
				{
					memcpy(pComm->cRetInvoice, cretinvoice, 6);
					pComm->iRetType = 1;
					PostMessage( pComm->m_hMainDlg,WM_COMMNOTIFY,PINPAD_REVEIVE_SUCTRAN,NULL);
				}
				else if( iCheckRet == 2)
				{
					pComm->iRetType = 2;
					PostMessage( pComm->m_hMainDlg,WM_COMMNOTIFY,PINPAD_REVEIVE_SUCTRAN,NULL);
				}
				
				SetEvent(pComm->m_hRecvDataEvent);
				iOldRecevie = 0;	
				ideflen = 0;
				Sleep(30);
				continue;	
			}
			else
			{
				int iRet = pComm->CheckPosMsg( iOldRecevie ); //�����Ƿ�ϸ�,ֻ��鳤�Ⱥ�LRC�Ƿ���ȷ			
				if ( iRet == 0  )				
				{		
					PostMessage( pComm->m_hMainDlg,WM_COMMNOTIFY,PINPAD_REVEIVE_SUC,NULL);
				}
				else if ( iRet > 1 )
				{
					m_gentool.WriteLog( LOG_LEVEL2,"[�����豸]POS���ذ����ʧ��!");
					PostMessage( pComm->m_hMainDlg,WM_COMMNOTIFY,PINPAD_ERROR_COMM,NULL);
				}
			}
			//pComm->CmdSendRetCode(0);
			
			// �����ȴ��´�����
			ResetEvent( pComm->m_hRecvDataEvent );
			iOldRecevie = 0;		
		}
	}
//	WriteLog( LOG_LEVEL2,"[�����豸]�˳����ڶ�ȡ�߳�[%d]", pComm->m_bConneted );
	return iReturn;
}


BOOL CIngPosCom::SetReadTimeOut( int iTime )
{
	COMMTIMEOUTS    ct;
	memset ( &ct, 0, sizeof(COMMTIMEOUTS) );
	
	if ( m_hComDev == INVALID_HANDLE_VALUE )
		return FALSE;
	
	if ( !GetCommTimeouts ( m_hComDev, &ct ) )
		return FALSE;

	if ( iTime > 0 ) 
	{
		ct.ReadIntervalTimeout = MAXDWORD;
		ct.ReadTotalTimeoutMultiplier = 0;
		ct.ReadTotalTimeoutConstant = iTime*1000;
		ct.WriteTotalTimeoutMultiplier = 0;
		ct.WriteTotalTimeoutConstant = 0;
	}

   return SetCommTimeouts( m_hComDev, &ct );
}

DWORD CIngPosCom::CommRead( char *pData, DWORD dwLength)
{
	if( !m_bConneted || m_hComDev == NULL )
	{
//		WriteLog( LOG_LEVEL2,"[��������豸]���ڶϿ�");
		return 0;
	}
	
	BOOL		fReadState;
	DWORD		dwErrorFlags,dwBytesRead;
	COMSTAT		ComStat;
	DWORD       dwError;
	
	ClearCommError( m_hComDev, &dwErrorFlags, &ComStat );
	if( ComStat.cbInQue == 0  )
	{
//		WriteLog( LOG_LEVEL2,"[��������豸]������");
		return 0;
	}
	dwBytesRead = min( dwLength, (DWORD) ComStat.cbInQue );
//	WriteLog( LOG_LEVEL2,"[��������豸]Ԥ�ƶ�ȡ���ݳ���[%d]", dwBytesRead);
	
	fReadState = ReadFile( m_hComDev, pData, dwLength, &dwBytesRead, &m_osRead );

	if ( !fReadState )   
	{   
		if (GetLastError() ==  ERROR_IO_PENDING )   
		{
			while( !GetOverlappedResult( m_hComDev, &m_osRead, &dwBytesRead, TRUE ) )   
			{
				dwError=GetLastError();   
				if( dwError == ERROR_IO_INCOMPLETE )
					continue;
			}
		}
		else
		{
			ClearCommError( m_hComDev,&dwErrorFlags,&ComStat);  
			dwLength = 0;
			return 0;
		}
	} 
// 	WriteLog( LOG_LEVEL2,"[��������豸]ʵ�ʶ�ȡ���ݳ���[%d]", dwBytesRead);

	return dwBytesRead;
	
}


DWORD CIngPosCom::CommWrite(char *pData, DWORD dwLength)
{
	BOOL	fWriteStat;   
	DWORD	dwBytesWritten;  
	
	DWORD	length = dwLength;
	COMSTAT ComStat;
	DWORD	dwErrorFlags;
	DWORD   dwError;  
	
	m_iBufLen = 0;	

 
	m_bKeyIgnore = TRUE; //�ȴ�Ӧ�������
 

	PurgeComm(m_hComDev, PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR);
	ClearCommError( m_hComDev, &dwErrorFlags, &ComStat );
	fWriteStat = WriteFile ( m_hComDev, pData, length, &dwBytesWritten, &m_osWrite );
	int it = GetLastError();
	if ( !fWriteStat )
	{		
		if ( it == ERROR_IO_PENDING )
		{
			// �ж�һ���ص�������ǰ��״̬
			while( !GetOverlappedResult(m_hComDev, &m_osWrite, &dwBytesWritten, TRUE ) )   
			{
				dwError=GetLastError();   
				if( dwError == ERROR_IO_INCOMPLETE )
					continue;   
				else   
				{
					ClearCommError(m_hComDev, &dwErrorFlags, &ComStat );   
					break;   
				}   
			}   
		}

		else
		{
			ClearCommError(m_hComDev, &dwErrorFlags, &ComStat );  
			m_gentool.WriteLog( LOG_LEVEL2,"[��������豸]%s ERROR CODE[%d]", "������������豸ʧ��!", it);
 
			m_bKeyIgnore = FALSE;
 
			return  0;
		}
		
	}
	m_gentool.WriteLog( LOG_LEVEL2,"[��������豸]��POS�������ݳ���[%d]�ѷ���[%d]", length, dwBytesWritten);
#ifdef TEST_VER 
	m_gentool.ShowBin2HexStr("[��������豸]������POS�������ݰ�" ,pData, length );
#endif
	
	return length;
}

/************************************************************************
����:	����Ĭ�ϲ���,�˿���ֵ��ʽ����,ת�����ַ�����ʽ�򿪴���
����:	Ĭ�ϲ���
************************************************************************/
BOOL CIngPosCom::CommOpen(int iPort, int iBaud , int DataBits, int StopBits, int Parity)
{
	// 
	srand( (unsigned)time( NULL ) ); 

	char cDevName[6];
	sprintf( cDevName,"COM%1d", iPort );
	if ( (m_hRecvDataEvent=CreateEvent(NULL,TRUE,FALSE,NULL)) == NULL )
	{
		return FALSE;
	}

	if ( (m_hIdleEvent=CreateEvent(NULL,TRUE,FALSE,NULL)) == NULL )
	{
		return FALSE;
	}
	
	// �ر��豸
	CommClose( );

	m_hComDev = CreateFile ( cDevName,GENERIC_WRITE|GENERIC_READ,0,NULL,OPEN_EXISTING, FILE_FLAG_OVERLAPPED,NULL);
	if ( m_hComDev == INVALID_HANDLE_VALUE )
		return FALSE;
	
	memset( &m_osRead,  0, sizeof( OVERLAPPED ) );
	memset( &m_osWrite, 0, sizeof( OVERLAPPED ) );
	m_osRead.hEvent  = CreateEvent( NULL, TRUE, FALSE, NULL );
	m_osWrite.hEvent = CreateEvent( NULL, TRUE, FALSE, NULL );
	
	DCB	 PinpadDCB;
	memset(&PinpadDCB,0,sizeof(DCB));
	if ( !GetCommState( m_hComDev, &PinpadDCB ) ) 
	{
		CloseHandle ( m_hComDev );
		return FALSE;
	}
	//m_gentool.WriteLog( LOG_LEVEL3,"[��������豸]��ʼ������[%s][%d][%d][%d][%d]",cDevName,iBaud,DataBits,StopBits,Parity);
	PinpadDCB.BaudRate = iBaud;
	PinpadDCB.ByteSize = DataBits;
    PinpadDCB.StopBits = StopBits;
	PinpadDCB.Parity   = Parity;
	PinpadDCB.fOutX = FALSE;
	PinpadDCB.fInX = FALSE;
	PinpadDCB.fErrorChar = FALSE;
	PinpadDCB.fParity = TRUE;
	PinpadDCB.fNull = FALSE;
	PinpadDCB.fAbortOnError = TRUE;

	PinpadDCB.fOutxDsrFlow=FALSE;   
	PinpadDCB.fDtrControl=DTR_CONTROL_ENABLE;   
	PinpadDCB.fOutxCtsFlow=FALSE;   
	PinpadDCB.fRtsControl=RTS_CONTROL_ENABLE;
	PinpadDCB.fBinary=TRUE;   
 
	PurgeComm(m_hComDev, PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR);
	if ( !SetCommState( m_hComDev, &PinpadDCB ) )
	{
		CloseHandle ( m_hComDev );
		return FALSE;
	}
	
// 	if ( !SetupComm( m_hComDev, 1000, 1000 )  )
// 	{
// 		ShowErrMsg();
// 	}

	if( m_osRead.hEvent == NULL ||	m_osWrite.hEvent == NULL )
	{
		if( m_osRead.hEvent != NULL ) 
			CloseHandle( m_osRead.hEvent );
		if( m_osWrite.hEvent != NULL )
			CloseHandle( m_osWrite.hEvent );
		CloseHandle( m_hComDev );
		return FALSE;
	}

	SetCommMask(m_hComDev, EV_RXCHAR);
//	ShowErrMsg();
	COMMTIMEOUTS TimeOuts;
	TimeOuts.ReadIntervalTimeout = MAXDWORD;
	TimeOuts.ReadTotalTimeoutMultiplier=0;
	TimeOuts.ReadTotalTimeoutConstant=1000;
	TimeOuts.WriteTotalTimeoutMultiplier=0;
	TimeOuts.WriteTotalTimeoutConstant=1000;
	SetCommTimeouts( m_hComDev, &TimeOuts );

	m_pThread = AfxBeginThread( PinCommReadProc, this, THREAD_PRIORITY_NORMAL,0,CREATE_SUSPENDED,NULL);
	if ( m_pThread == NULL )
	{
		// Ϊ�رվ������
		m_bConneted = TRUE;
		CommClose();
		return FALSE;
	}
	else
	{
		m_bConneted = TRUE;
		EscapeCommFunction(m_hComDev, SETDTR ); 
		//WriteLog( LOG_LEVEL2,"[��������豸][����߳�]:ID[0x%02xH]��ַ[0x%02xH]�߳̾��[0x%02xH]",m_pThread->GetThreadPriority(),	m_pThread,m_pThread->m_nThreadID);
		m_pThread->ResumeThread();
	}
	

	return TRUE;
}

void CIngPosCom::CommClose(  )
{
	if( !m_bConneted || m_hComDev == NULL )
		return;
	
	SetCommMask( m_hComDev, 0 );

	//add �ӳٴ��ڹر� by wangw 2021.12.7
	Sleep(200);
	//end add
	
	if( m_pThread != NULL )
	{
		//add �ӳٴ��ڹر� by wangw 2021.12.7
		Sleep(200);
		//end add
		m_bConneted = FALSE;
		SetEvent( m_hRecvDataEvent );
		WaitForSingleObject( m_pThread->m_hThread, INFINITE );
		m_gentool.WriteLog( LOG_LEVEL2,"[�����豸]�رմ��������¼�");
		m_pThread = NULL;
		
	}
	if ( m_hComDev != INVALID_HANDLE_VALUE )
	{
		EscapeCommFunction(m_hComDev,CLRDTR);   
		// ����ָ���źŵ����ź�
		PurgeComm(m_hComDev, PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR);
		CloseHandle(m_osRead.hEvent);   
		CloseHandle(m_osWrite.hEvent);   
		CloseHandle ( m_hComDev );
		m_hComDev = INVALID_HANDLE_VALUE;
		m_bConneted = FALSE;
	}
	m_gentool.WriteLog( LOG_LEVEL2,"[�����豸]�رմ����豸");
}

void CIngPosCom::SetMainDlgHWnd(HWND hWnd)
{
	m_hMainDlg = hWnd;
}


int CIngPosCom::CheckPosMsg(  int iLen )
{
	// ��ȷ����0 ���󷵻ش���0
	char	cMsgLength[5];
	char	cCmdLRC = 0;
	
	m_iCmdPackLen = 0;
	memset( cMsgLength, 0, sizeof(cMsgLength) );
	if ( m_ReadBuf[0]=='\x06' && iLen>1 )
	{
		memcpy(m_ReadBuf, m_ReadBuf+1, iLen-1 );
		m_ReadBuf[iLen]=0;
		iLen -= 1;
	}
	m_iBufLen = iLen;
	// ת�����ӽ�BCD��ĳ���
	m_gentool.FunBin2Hex( m_ReadBuf+1, cMsgLength, 2 );
	if ( strlen(cMsgLength) > 0 )
		m_iCmdPackLen = atoi( cMsgLength );
	// �ж�MSG����
	if ( m_iCmdPackLen <= 0 || m_iCmdPackLen > 1024 )
	{
		m_gentool.WriteLog( LOG_LEVEL2,"[�����豸]���ȳ���" );
		return 2;
	}
	// ���������[�����ֽ�+MSG+ETX]�������ӽ�
	for (int i = 1; i< m_iBufLen-1; i++ )
		cCmdLRC ^= m_ReadBuf[i];
	
 
 	if( cCmdLRC != m_ReadBuf[m_iBufLen-1] )
 	{
 		m_gentool.WriteLog( LOG_LEVEL2,"[�����豸]У��λ����[%02.02x]?[����][%02.02x]",cCmdLRC,m_ReadBuf[m_iBufLen-1]);
 		return 2;
 	}
	
	return 0;
}


//��鷵�صİ��Ƿ���ȡ�����
// ���: iOldRecevie -- ������
// ����: cretinvoice -- �ɹ�У��Ʊ�ݺ�
// ����: < 0 -- ʧ��
//       = 1  -- �ɹ�,�ɹ��ҵ�Ʊ�ݺ�
//       = 2  --�ɹ�,����Ʊ�ݺ�   
//       = 3  --��־��,�����κδ���
int CIngPosCom::CheckSucRet(int iOldRecevie, char *cretinvoice)
{
	// ��ȷ����0 ���󷵻ش���0
	
	unsigned char packbuf[2048];
	
	int i;
	
	memset(packbuf, 0, sizeof(packbuf));
	memcpy(packbuf, m_ReadBuf, iOldRecevie);
	
	// �ж�MSG����
	if ( iOldRecevie <= 0 || iOldRecevie > 1024 )
	{
		m_gentool.WriteLog( LOG_LEVEL2,"[CheckSucRet]���ȳ���[%ld]",iOldRecevie );
		return -1;
	}
	
	
	for (i = 0; i< 10; i++ )
	{
		if( (memcmp(packbuf + i, "LOGLOG", 6) == 0 ) && (iOldRecevie < 30) )
		{
			m_gentool.ShowBin2HexStr(  "���յ���־��",(char *)packbuf, iOldRecevie );
			return 3;
		}
	}
	
	
	//	ShowBin2HexStr("��鷵�ذ�",(char *)packbuf, iOldRecevie );
	
	if(memcmp(packbuf + 2, "ACKACK", 6) == 0 ) //�ɹ�������ذ�
	{
		m_gentool.WriteLog(LOG_LEVEL2,"����ɹ����֪ͨ��1,Ʊ�ݺ�[%6.6s]" ,packbuf+8 );
		memcpy(cretinvoice, packbuf + 8, 6);
		return 1;
	}
	
	if(memcmp(packbuf + 3, "ACKACK", 6) == 0 ) //�ɹ�������ذ�
	{
		m_gentool.WriteLog(LOG_LEVEL2,"����ɹ����֪ͨ��2,Ʊ�ݺ�[%6.6s]" ,packbuf+9 );
		memcpy(cretinvoice, packbuf + 9, 6);
		return 1;
	}
	
	if(memcmp(packbuf + 4, "ACKACK", 6) == 0 ) //�ɹ�������ذ�
	{
		m_gentool.WriteLog(LOG_LEVEL2,"����ɹ����֪ͨ��3,Ʊ�ݺ�[%6.6s]" ,packbuf+10 );
		memcpy(cretinvoice, packbuf + 10, 6);
		return 1;
	}
	
	if(memcmp(packbuf + 5, "ACKACK", 6) == 0 ) //�ɹ�������ذ�
	{
		m_gentool.WriteLog(LOG_LEVEL2,"����ɹ����֪ͨ��4,Ʊ�ݺ�[%6.6s]" ,packbuf+11 );
		memcpy(cretinvoice, packbuf + 11, 6);
		return 1;
	}

	// ���������[�����ֽ�+MSG+ETX]�������ӽ�
	for (i = 0; i< 10; i++ )
	{
		if( ( memcmp(packbuf+i, "ACK", 3) == 0) && (iOldRecevie < 25) )
		{
			m_gentool.WriteLog(LOG_LEVEL2,"����������ɹ����֪ͨ��[%d]" ,i );
			return 2;
		}			
	}
	
	return -1;
}

// ���ڿ��ź���Ч�ڣ�POS���ڷ��صĽ��׽����
// ��Դ�ַ����еĿ��ź���Ч������
// ���: pSrcStr -- Դ�ַ���
//       bAll -- �Ƿ����ڶ��DF1E��DF1F
// ����: TRUE -- ת���ɹ�
//       FALSE -- ת��ʧ��
BOOL CIngPosCom::HiddenRetInfo( char *pSrcStr, BOOL bAll )
{
    int nSrcLen = 0;
    nSrcLen = strlen(pSrcStr);
	if( nSrcLen <= 0 )
		return FALSE;
	char sCardnoField[5];
	char sExpireField[5];
	memset(sCardnoField, 0, sizeof(sCardnoField));
	memset(sExpireField, 0, sizeof(sExpireField));
	sprintf(sCardnoField, "DF1E");
	sprintf(sExpireField, "DF1F");
    //WriteLog(LOG_LEVEL2,"CardnoField=[%s] ExpireField=[%s]" ,sCardnoField, sExpireField );
	
    //�����ַ����еĿ�����DF1E
	int i,j,k;
	char cCardnoLenHex[2];
	char cExpireLenHex[2];
	
	for( i = 0; pSrcStr[i] != '\0'; i++ )
	{
        j = 0;
		k = 0;
		while( pSrcStr[i+j] != '\0' && sCardnoField[j] != '\0' ) //����������
		{
            if( pSrcStr[i+j] != sCardnoField[j] )
				break;
			j++;
		}
		while( pSrcStr[i+k] != '\0' && sExpireField[k] != '\0' ) //������Ч����
		{
            if( pSrcStr[i+k] != sExpireField[k] )
				break;
			k++;
		}
		if( sCardnoField[j] == '\0' ) //�ҵ�������
		{
			//���ڿ��ţ�ֻ����4λ
            //ȡ�����򳤶�
			int iCardnoLen = 0; 
			memset(cCardnoLenHex, 0, sizeof(cCardnoLenHex));
			sprintf(cCardnoLenHex, "%-2.2s", pSrcStr + i + j);
            iCardnoLen = strtol( cCardnoLenHex, NULL, 16);
			//WriteLog(LOG_LEVEL2,"���׽�� CardnoLenHex=[%s] ilen=[%d]" ,cCardnoLenHex, iCardnoLen );
            //�����ȿ�������Ϊ*
			int y = 0; 
			int iMaskLen = 0;
			y = i+j+2;
			iMaskLen = (iCardnoLen-4)*2;
			//WriteLog(LOG_LEVEL2,"iMaskLen=[%d]" , iMaskLen );
			for( y; y< i + j + 2 + iMaskLen; y+=2)
			{
                pSrcStr[y] = '2';
                pSrcStr[y+1] = 'A';
			}
		}
		
		if( sExpireField[k] == '\0' ) //�ҵ���Ч����
		{
			//������Ч��
			//ȡ��Ч���򳤶�
			int iExpireLen = 0; 
			memset(cExpireLenHex, 0, sizeof(cExpireLenHex));
			sprintf(cExpireLenHex, "%-2.2s", pSrcStr + i + k);
            iExpireLen = strtol( cExpireLenHex, NULL, 16);
			//WriteLog(LOG_LEVEL2,"���׽�� ExpireLenHex=[%s] ilen=[%d]" ,cExpireLenHex, iExpireLen );
            //�����ȿ�������Ϊ*
			int y = 0; 
			int iMaskLen = iExpireLen*2;
			y = i+k+2;
			//WriteLog(LOG_LEVEL2,"iMaskLen=[%d]" , iMaskLen );
			for( y; y< i + k + 2 + iMaskLen; y+=2)
			{
                pSrcStr[y] = '2';
                pSrcStr[y+1] = 'A';
			}
		}
	}
	//WriteLog( LOG_LEVEL2, "[�����豸]Mask hidden ���յ�POS�������ݰ�Hex=[%s]", pSrcStr ) ;
    
	return TRUE;
}


void CIngPosCom::CmdSendRetCode(int iCode)
{
	char 	cCMDBuf[2];
	memset( cCMDBuf, 0, sizeof(cCMDBuf) );
	
	if ( iCode == 0 )
		sprintf(cCMDBuf,"%c",ACK);
	else if ( iCode == 1 )
		sprintf(cCMDBuf,"%c",NAK);
	else if ( iCode == 2 )
		sprintf(cCMDBuf,"%c",EOT);
	
	CommWrite( cCMDBuf, 1 );
	m_dwStart = GetTickCount()+ POSCMDOUT;
 
}

//����ַ����Ƿ�ȫ�� cChar ���
// ���: pStr -- Դ�ַ���
//       strLen -- Դ�ַ�������
//       cChar -- ƥ����ַ�
// ����: TRUE  -- �ǣ��ַ����� cChar���
//       FALSE -- ����
BOOL CIngPosCom::CmpStr( char *pStr, int strLen, char cChar )
{
	BOOL bEqual = TRUE;
    for( int i = 0; i < strLen; i++ )
	{
        if( *(pStr+i) != cChar )
            bEqual = FALSE;
	}
	return bEqual;
}

int CIngPosCom::StrAmt2DigAmount( char *pStrAmt, char *pDigAmount )
{
    CString tmpStr;
	CString tmpDigStr;
	tmpStr.Empty();
    tmpStr.Format("%s", pStrAmt );
    m_gentool.WriteLog(LOG_LEVEL2,"str2dig-tmpStr=[%s]" , tmpStr.GetBuffer(0));
	
    for( int i=0; i< tmpStr.GetLength(); i++ )
	{
		if(tmpStr[i] >='0' && tmpStr[i] <='9')
		{
            tmpDigStr += tmpStr[i];
		}
	}
    m_gentool.WriteLog(LOG_LEVEL2,"str2dig-DigAmount=[%s]" , tmpDigStr.GetBuffer(0));
	CString temp2;
    temp2.Format("%012s", tmpDigStr);
	m_gentool.WriteLog(LOG_LEVEL2,"str2dig-temp2=[%s]" , temp2.GetBuffer(0));
	sprintf( pDigAmount, "%s", temp2.GetBuffer(0));
	
	return 0;
}

int CIngPosCom::CommRebuildDataSync( char *pData, int iLen )
{
	char cLRC = 0;
	char cDataBuf[2048];
	
	char	cMsgLen[5];
	char	cMsgLenBin[3];
	
	memset(cDataBuf, 0, sizeof(cDataBuf) );
	memset(cMsgLen, 0, sizeof(cMsgLen) );
	memset(cMsgLenBin, 0, sizeof(cMsgLenBin) );
	cDataBuf[0] = STX;
	
	sprintf( cMsgLen, "%04d", iLen );
	
	m_gentool.FunHex2Bin(  cMsgLen, cMsgLenBin, 2);
	for (int i = 0; i< 2; i++ )
		cLRC ^= cMsgLenBin[i];
	
	memcpy( cDataBuf+1, cMsgLenBin, 2 );
	memcpy( cDataBuf+1+2, pData, iLen );
	for (  i = 0; i< iLen; i++ )
		cLRC ^= pData[i];
	cLRC ^= ETX;
	
	cDataBuf[iLen+1+2] = ETX;
	cDataBuf[iLen+2+2] = cLRC;
	
//	char cDataBufHex[1024]={0};
//	m_gentool.FunBin2Hex( (char*)cDataBuf, cDataBufHex, iLen+5 );
//	WriteLog(LOG_LEVEL2,"[POS�豸][�豸д��][%s]", cDataBufHex);
	
	memcpy( pData, cDataBuf, iLen+5 );
	
// 	if (iLen>0)
// 	{
// 		char sbuf[MAXBLOCK]={0};
// 		m_gentool->FunBin2Hex(pData,sbuf,iLen+5);
// 		m_pMainDlg->GetDlgItem(IDC_EDIT_DATA_REQ)->SetWindowText( sbuf );
// 	}
	
	return iLen+5;
}


int CIngPosCom::UserLogin(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_LOGIN, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranPurchase(  )
{
	char 	cCMDBuf[1024];
	int		iCmdLen = 0;
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_PURCHASE, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
 	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
 	if ( iAddCmdLen > 0 )
 	{
 		iCmdLen += iAddCmdLen;
 		iAddCmdLen = 0;
 	}

	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF20", (LPSTR)(LPCSTR)"000000000000", 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}

//	m_gentool.WriteLog(LOG_LEVEL1,"m_TradeInfo.szBarCode=[%s]",m_TradeInfo.szBarCode);
//	if( strlen(m_TradeInfo.szBarCode)>0 ) //���ɨ����
	if(memcmp(m_TradeInfo.szBarCode,"##",2)==0)
	{


	}
	else 
	{
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
 		}

        iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF6A", m_TradeInfo.szBarCode, strlen(m_TradeInfo.szBarCode), TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
	}
 
	
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranVoid(  )
{
 	char 	cCMDBuf[1024];

	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
// 	if(atoi(m_TradeInfo.szPayCh)==4)
// 		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_QRVOID, 2, TLV_DATA_BCD);
// 	else
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_VOID, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
//  	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "0", 1, TLV_DATA_ASC);
//  	if ( iAddCmdLen > 0 )
//  	{
//  		iCmdLen += iAddCmdLen;
//  		iAddCmdLen = 0;
//  	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF18", m_TradeInfo.szInvoiceID, 6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranRefund(   )
{
	char 	cCMDBuf[1024];

	int		iCmdLen = 0;

	memset(cCMDBuf, 0, sizeof(cCMDBuf));

	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add

	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	if(atoi(m_TradeInfo.szPayCh)==4)
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_QRREFUND_M, 2, TLV_DATA_BCD);
	else
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_REFUND, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
// 	if(memcmp(m_TradeInfo.szPayCh,"##",2)==0)
// 	{
// 
// 	}
// 	else
    if(atoi(m_TradeInfo.szPayCh)==4)
	{
        if(strlen(m_TradeInfo.szPayNo)>0)
		{
			iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF69", m_TradeInfo.szPayNo, strlen(m_TradeInfo.szPayNo), TLV_DATA_ASC);
			if ( iAddCmdLen > 0 ) 
			{
				iCmdLen += iAddCmdLen;
				iAddCmdLen = 0;
			}

			iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF90", m_TradeInfo.szPayNo, strlen(m_TradeInfo.szPayNo), TLV_DATA_ASC);
			if ( iAddCmdLen > 0 ) 
			{
				iCmdLen += iAddCmdLen;
				iAddCmdLen = 0;
			}
  		}
	}
	else
	{
        iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF19",  m_TradeInfo.szTraceID, 6, TLV_DATA_BCD);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
		if(strlen(m_TradeInfo.szAuthNO)==0)
			sprintf(m_TradeInfo.szAuthNO,"      ");
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF16", m_TradeInfo.szAuthNO, 6, TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
		
		
		if( strlen(m_TradeInfo.szTranDate) > 0 )
		{
			iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF17", m_TradeInfo.szTranDate+4, 4, TLV_DATA_BCD);
			if ( iAddCmdLen > 0 )
			{
				iCmdLen += iAddCmdLen;
				iAddCmdLen = 0;
			}
			iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0B", m_TradeInfo.szTranTime, 6, TLV_DATA_BCD);
			if ( iAddCmdLen > 0 )
			{
				iCmdLen += iAddCmdLen;
				iAddCmdLen = 0;
			}
		}
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}

	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );

	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );

	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}


int CIngPosCom::TranQuery(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_INQUIRY, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
    iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}


int CIngPosCom::Reprint(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_REPRINT, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF18", m_TradeInfo.szInvoiceID,  6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}


int CIngPosCom::Totle(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_STATICS, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
 
	{
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF05", "01", 2, TLV_DATA_BCD);
	}
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	/*�Ƿ�ȫ��ͳ��ȫ����Ϣ	*/
	char cOperSta[3];
	memset(cOperSta, 0, sizeof(cOperSta));
	m_gentool.CFG_Get_Key(CONFIG_FILE,  "DEVICE", "OPERSTATIC", cOperSta);
	if(cOperSta[0] == '1') //��Ҫ��Ա����
	{
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
	}
	/*�Ƿ�ȫ��ͳ��ȫ����Ϣ	����*/
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::DownParam(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_DOWNPARAM, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr("[POS�豸]���ڷ��Ͳ������ص�����" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}
int CIngPosCom::Settle(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_SETTLE, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF05", "01", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}


int CIngPosCom::TlvCmdPack(char *pCmd, char *pFlag, char *pVal, int iValLen, int iType)
{
	int		iPost = 0;
	BYTE	cLenBuf[4];
	int		iLenBufLen = 0;
	int		iFlagLen = 0;
	char	cValBin[2048];

	memset( cLenBuf, 0, sizeof(cLenBuf) );
	memset( cValBin, 0, sizeof(cValBin) );
	iFlagLen = strlen( pFlag );

	switch ( iType )
	{
	case TLV_DATA_ASC:
		{
			// �������ȴ���ʱ������ʧ��
			if( !TlvGetLenBuf(cLenBuf, iValLen, iLenBufLen ) )
				return -1;
			// TAG
			m_gentool.FunHex2Bin(pFlag,  pCmd, iFlagLen );
			iPost += iFlagLen>>1;
			// LENGTH
			memcpy( pCmd+iPost, cLenBuf, iLenBufLen );
			iPost += iLenBufLen;
			// VALUES
			memcpy( pCmd+iPost, pVal, iValLen);
			iPost += iValLen;
		}
		break;
	case TLV_DATA_BIN:
		{
			// �������ȴ���ʱ������ʧ��
			if( !TlvGetLenBuf(cLenBuf, iValLen, iLenBufLen ) )
				return -1;
			// TAG
			m_gentool.FunHex2Bin(pFlag,  pCmd, iFlagLen );
			iPost += iFlagLen>>1;
			// LENGTH
			memcpy( pCmd+iPost, cLenBuf, iLenBufLen );
			iPost += iLenBufLen;
			// VALUES
			memcpy( pCmd+iPost, pVal, iValLen);
			iPost += iValLen;
		}
		break;
	case TLV_DATA_BCD:
		{
			iValLen >>= 1;
			m_gentool.FunHex2Bin(pVal, cValBin, iValLen);
			// �������ȴ���ʱ������ʧ��
			if( !TlvGetLenBuf(cLenBuf, iValLen, iLenBufLen ) )
				return -1;
			// TAG
			m_gentool.FunHex2Bin(pFlag,  pCmd, iFlagLen );
			iPost += iFlagLen>>1;
			// LENGTH
			memcpy( pCmd+iPost, cLenBuf, iLenBufLen );
			iPost += iLenBufLen;
			// VALUES
			memcpy( pCmd+iPost, cValBin, iValLen);
			iPost += iValLen;
		}
		break;
	case TLV_DATA_HEX:
		{
			iValLen >>= 1;
			m_gentool.FunHex2Bin(pVal, cValBin, iValLen);
			// �������ȴ���ʱ������ʧ��
			if( !TlvGetLenBuf(cLenBuf, iValLen, iLenBufLen ) )
				return -1;
			// TAG
			m_gentool.FunHex2Bin(pFlag,  pCmd, iFlagLen );
			iPost += iFlagLen>>1;
			// LENGTH
			memcpy( pCmd+iPost, cLenBuf, iLenBufLen );
			iPost += iLenBufLen;
			// VALUES
			memcpy( pCmd+iPost, pVal, iValLen);
			iPost += iValLen;
		}
		break;
	default:
		return -1;
		break;
	}

	return iPost;
}

BOOL CIngPosCom::TlvGetLenBuf(BYTE *pLenBuf, int& iValLen, int &iLen, BOOL bGet/*=FALSE*/)
{
	if (  !bGet  )
	{
		if ( iValLen == 0 || pLenBuf == NULL )
			return FALSE;
		
		WORD wSubLen = 0;
		memset( pLenBuf, 0, 4 );
		
		if( iValLen < 128 )
		{
			pLenBuf[0] = iValLen;
			iLen = 1;
		}
		else if ( iValLen < 255)
		{
			pLenBuf[0]  = 1;
			pLenBuf[0] |= BYTE(0x80);
			pLenBuf[1] = iValLen;
			iLen = 2;
		}
		else if ( iValLen < 65535 )
		{
			pLenBuf[0] = 2;
			pLenBuf[0] |= BYTE(0x80);
			wSubLen = iValLen;
			//memcpy(pLenBuf+1, &wSubLen, sizeof(WORD));
			char cBufTempHex[5]={0};
			char cBufTempBin[3]={0};
		//	
			m_gentool.FunBin2Hex( (char*)&wSubLen+1, cBufTempHex, 1);
			m_gentool.FunBin2Hex( (char*)&wSubLen, cBufTempHex+2, 1);
			m_gentool.FunHex2Bin( cBufTempHex, cBufTempBin, 2);
			memcpy(pLenBuf+1, cBufTempBin, 2 );
			//WriteLog( )
			//wSubLen = strtol( pLenBuf+1, NULL, 16 )
			iLen = 3; 
		}
		else
			return FALSE ;
	}
	else
	{
		WORD wSubLen = 0;
		iLen = 0;
		if ( pLenBuf == NULL )
			return FALSE;
		if( BYTE(pLenBuf[0] & BYTE(0x80)) == BYTE(0x80) )
		{
			if ( BYTE(pLenBuf[0] & BYTE(0x01)) == BYTE(0x01) )
			{
				iLen = 2;
				iValLen = int( pLenBuf[1]);
			}
			else if ( BYTE(pLenBuf[0] & BYTE(0x02)) == BYTE(0x02) )
			{
				//memcpy(&wSubLen, pLenBuf+1, sizeof(WORD) );
				char cBufTemp[5]={0};
				
				m_gentool.FunBin2Hex( (char*)pLenBuf+1, cBufTemp, 2);
				wSubLen = WORD(strtol( cBufTemp, NULL, 16 ));
				iLen = 3;
				iValLen = wSubLen;
			}
			else
				return FALSE;

		}
		else if ( BYTE(pLenBuf[0] & BYTE(0x80)) == BYTE(0x00) )
		{
			iLen = 1;
			iValLen = int( pLenBuf[0] & BYTE(0x7F) );
		}
		else
			return FALSE;		
	}
	return TRUE;
}
int CIngPosCom::TlvUnPack(char *pCmdMsg, int& iTagLen, CmdTlv *pCmdTlv )
{
	char	*pCur = NULL;
	int		iLen = 0;
	int		iSubLenLen=0;
	int		iSubLen=0;
	
	char	cTagFlag[5];
	memset( cTagFlag, 0, sizeof(cTagFlag) );
	
	// �����жϱ���
	if ( pCmdMsg[0] != '\xDF' || pCmdMsg == NULL )
	{
		m_gentool.WriteLog(LOG_LEVEL2,"[�����豸]���������ķǷ�!") ;
		return FALSE;
	}
	
	pCur = pCmdMsg;
	// ��ʱ�����Զ����ʶ��������λ
	m_gentool.FunBin2Hex( pCur, cTagFlag, 2 );
	sprintf(pCmdTlv->tagID, "%4.4s", cTagFlag );
	//WriteLog( LOG_LEVEL2, "[�����豸]��ǩ��ʶ[%s]", pCmdTlv->tagID ) ;
	
	
	pCur += 2;
	iLen += 2;
	
	TlvGetLenBuf( (BYTE*)pCur, iSubLen, iSubLenLen, TRUE );
//	WriteLog( LOG_LEVEL2, "[�����豸]��ǩ���ȵĳ���[%d]", iSubLenLen ) ;
//	WriteLog( LOG_LEVEL2, "[�����豸]��ǩ���ݵĳ���[%d]", iSubLen ) ;

	if ( iSubLen > 0  )
	{
		GetTlvTagType(pCmdTlv->tagID, pCmdTlv );
		if( pCmdTlv->tagLen != 0  )
		{
			if( pCmdTlv->tagLen != iSubLen )
			{
				m_gentool.WriteLog( LOG_LEVEL2, "[�����豸]��ǩ[%s]���ȷǷ�",pCmdTlv->tagID ) ;
				return FALSE;
			}
		}
		if ( strncmp( pCmdTlv->tagID, "DF07", 4 ) == 0 )
		{
			if ( iSubLen == 2 )
			{
				// 
				pCmdTlv->tagType = TLV_DATA_ASC;
				pCmdTlv->pPkg = (char*)malloc((iSubLen+1)*sizeof(char) );
				memset(pCmdTlv->pPkg, 0, (iSubLen+1)*sizeof(char) );
				memcpy(pCmdTlv->pPkg, pCur+iSubLenLen, iSubLen );
				pCmdTlv->tagLen = iSubLen;
			}
			else
			{
				pCmdTlv->tagType = TLV_DATA_BCD;
				pCmdTlv->pPkg = (char*)malloc((iSubLen*2+1)*sizeof(char));
				memset(pCmdTlv->pPkg, 0, (iSubLen*2+1)*sizeof(char) );
				m_gentool.FunBin2Hex( pCur+iSubLenLen, pCmdTlv->pPkg, iSubLen);
				pCmdTlv->tagLen = iSubLen;
			}
		}
		else
		{
		if ( pCmdTlv->tagType == TLV_DATA_ASC  )
		{
			pCmdTlv->pPkg = (char*)malloc((iSubLen+1)*sizeof(char) );
			memset(pCmdTlv->pPkg, 0, (iSubLen+1)*sizeof(char) );
			memcpy(pCmdTlv->pPkg, pCur+iSubLenLen, iSubLen );
			pCmdTlv->tagLen = iSubLen;

		}
		else if ( pCmdTlv->tagType == TLV_DATA_BCD || pCmdTlv->tagType == TLV_DATA_HEX || pCmdTlv->tagType == TLV_DATA_BIN )
		{
			pCmdTlv->pPkg = (char*)malloc((iSubLen*2+1)*sizeof(char));
			memset(pCmdTlv->pPkg, 0, (iSubLen*2+1)*sizeof(char) );
			m_gentool.FunBin2Hex( pCur+iSubLenLen, pCmdTlv->pPkg, iSubLen);
			pCmdTlv->tagLen = iSubLen;
		}
		}

		// ���ֽڳ���
		int i = strlen(pCmdTlv->pPkg);
//		m_gentool.WriteLog( LOG_LEVEL2, "[�����豸][%s][%s][%s]", pCmdTlv->tagName, pCmdTlv->tagID, pCmdTlv->pPkg ) ;
	}
	else if( iSubLen == 0 )
	{
		iTagLen = 2+ 1 + iSubLen;
		// ���ӽڳ���
		//WriteLog( LOG_LEVEL2, "[�����豸]��ǩ���ȷǷ�" ) ;
//		m_gentool.WriteLog( LOG_LEVEL2, "[�����豸][%s][%s][%s]", pCmdTlv->tagName, pCmdTlv->tagID, pCmdTlv->pPkg ) ;
		return TRUE;
	}
	else
	{
		// ���ӽڳ���
		m_gentool.WriteLog( LOG_LEVEL2, "[�����豸]��ǩ���ȷǷ�" ) ;
		return FALSE;

	}
	iTagLen = 2+ iSubLenLen + iSubLen;
	return TRUE;
}

 


void CIngPosCom::FreeTlvPkgArray()
{
	CmdTlv* pCmdTlv = NULL;
	for(int i = 0; i < m_TlvPtrArray.GetSize(); i++)
	{
		pCmdTlv = m_TlvPtrArray.GetAt(i);
		if( pCmdTlv->pPkg != NULL )
			free(pCmdTlv->pPkg );
		delete pCmdTlv;
	}
	m_TlvPtrArray.RemoveAll();
	m_b8583Pkg = FALSE; 
}
void CIngPosCom::FreeTlvSubPkgArray()
{
	CmdTlv* pCmdTlv = NULL;
	for(int i = 0; i < m_TlvPtrSubArray.GetSize(); i++)
	{
		pCmdTlv = m_TlvPtrSubArray.GetAt(i);
		if( pCmdTlv->pPkg != NULL )
			free(pCmdTlv->pPkg );
		delete pCmdTlv;
	}
	m_TlvPtrSubArray.RemoveAll();
}


int CIngPosCom::UnPackPosRetData( BOOL &bContinue )
{
	// �������
	m_bPackEnd = FALSE;
	m_b8583Pkg = FALSE;
	bContinue = FALSE;
	
	char *pCurRet = NULL;
	pCurRet = m_ReadBuf+3;
	int iRetLen = m_iBufLen -5 ;
	int iAddLen = 0 ;
	int iRet = 0;


 

	return 1;
}


int CIngPosCom::Pack8583Package(char* pPkg, int iPkg )
{
	char 	cCMDBuf[4096];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );

	memcpy(m_cRandom, cRandom, sizeof(cRandom));

	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "01", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
#ifdef USE_CUP_LEN
	char cPkgAdd[4096]={0};
	memcpy( cPkgAdd, pPkg, 5 );
	memcpy( cPkgAdd+5, "\x01\x00", 2 );
	memcpy( cPkgAdd+5+2, pPkg+5, iPkg-5 );
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF06", cPkgAdd , iPkg+2, TLV_DATA_BIN);
#else
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF06", pPkg , iPkg, TLV_DATA_BIN);
#endif
	
	//	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF06", pPkg , iPkg, TLV_DATA_BIN);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	m_gentool.WriteLog( LOG_LEVEL2,"[�����豸]׼���򴮿ڷ���8583����!");
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	//	ShowBin2HexStr( LOG_LEVEL3, "[�����豸]���ڷ��͵�8583��������" ,cCMDBuf, iCmdLen );
	
	
	
	CommWrite(cCMDBuf, iCmdLen);
	m_gentool.WriteLog( LOG_LEVEL1,"[�����豸]�򴮿ڷ���8583�������!");	
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
 
}

BOOL CIngPosCom::Get8583Package(CmdTlv* &p8583CmdTlv)
{
	CmdTlv* pCmdTlv = NULL;
	int		iDF06_ID = -1;
	
	strcpy(sDesHost, "01"); //ȱʡ��IST����
	if( m_b8583Pkg )
	{
		for(int i = 0; i < m_TlvPtrArray.GetSize(); i++)
		{
			//ȷ����8583����,��8583������
			pCmdTlv = m_TlvPtrArray.GetAt(i);
			if ( strncmp(pCmdTlv->tagID,"DF02", 4 )==0 )
			{
				if ( strncmp(pCmdTlv->tagID,"01", 4 ) )
					return FALSE;
			}
			if ( strncmp(pCmdTlv->tagID,"DF06", 4 )==0 )
				iDF06_ID = i;
			
			//���Ӷ�������־�Ĵ���
			if ( strncmp(pCmdTlv->tagID,"DF05", 4 )==0 )
			{
				if( pCmdTlv->pPkg != NULL)
				{
					if ( !strncmp(pCmdTlv->pPkg,"01", 4 ) //IST
						||!strncmp(pCmdTlv->pPkg,"02", 4 ) //DCC
						||!strncmp(pCmdTlv->pPkg,"03", 4 ) //TAS
						||!strncmp(pCmdTlv->pPkg,"04", 4 ) ) //ZYWZ
					{
						memset(sDesHost, 0, sizeof(sDesHost));
						strncpy(sDesHost, pCmdTlv->pPkg, 2);
						m_gentool.WriteLog( LOG_LEVEL2,"8583����Ŀ����������[%s]", sDesHost );
					}
				}
			}
			//������־�������
		}
		if ( iDF06_ID == -1 )
			return FALSE;
		pCmdTlv = m_TlvPtrArray.GetAt(iDF06_ID);
		if( pCmdTlv->pPkg != NULL && strncmp(pCmdTlv->tagID,"DF06", 4 )==0 )
		{
			p8583CmdTlv = pCmdTlv ;
			return TRUE;
		}
	}
	return FALSE;
}


int CIngPosCom::TlvUnPackRet( BOOL &bContinue )
{
	// �������
	m_bPackEnd = FALSE;

//	m_bRetSuccess = FALSE;
	FreeTlvPkgArray();
	bContinue = FALSE;
	
	CmdTlv	*pNewCmdTlv = NULL;
	
	char *pCurRet = NULL;
	pCurRet = m_ReadBuf+3;
	int iRetLen = m_iBufLen -5 ;
	int iTagLen = 0;
	int iFlag =0;
	m_b8583Pkg=FALSE;

	while( iRetLen > 0 )
	{
//		WriteLog( LOG_LEVEL2,"[�����豸]��ʼ�ⱨTAG!");

		pNewCmdTlv = new CmdTlv;
		if ( pNewCmdTlv != NULL )
		{
			memset( pNewCmdTlv, 0, sizeof(CmdTlv) );
		}
		TlvUnPack(pCurRet, iTagLen, pNewCmdTlv);//���һ����ǩ
		//
		if( strncmp( pNewCmdTlv->tagID, "DF01", 4 ) == 0 )
		{
			if( strncmp(pNewCmdTlv->pPkg, "01", 2 ) == 0 )
			{
				m_b8583Pkg = TRUE; //8583��
			}
		}

		if( strncmp( pNewCmdTlv->tagID, "DF89", 4) ==0) 
		{
			iFlag=1;
		}
		else if ( strncmp(pNewCmdTlv->tagID,"DF8F", 4 )==0)  // ֧����ʽ
		{
			sprintf(m_TranRetInfo.cSurplusNum,"%s", pNewCmdTlv->pPkg);
			m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF8F ����ʣ������=[%s]", m_TranRetInfo.cSurplusNum );
		}
		else if ( strncmp(pNewCmdTlv->tagID,"DF74", 4 )==0)
		{
			m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF74 =[%s]", pNewCmdTlv->pPkg );
		}

		if( strncmp( pNewCmdTlv->tagID, "DF0C", 4 ) == 0 )
		{
			if( strncmp(pNewCmdTlv->pPkg, "01", 2 ) == 0 )
			{
				m_gentool.CFG_Set_Key(CONFIG_FILE,  "PROGRAM", "SIGNIN", "1");
			}
		}

		if( strncmp( pNewCmdTlv->tagID, "DF07", 4 ) == 0 )
		{
			if ( strlen(pNewCmdTlv->pPkg) == 2 ) //Ӧ��
			{
				if( strncmp(pNewCmdTlv->pPkg, "00", 2 ) == 0 || strncmp(pNewCmdTlv->pPkg, "Y1", 2 ) == 0  || 
					 strncmp(pNewCmdTlv->pPkg, "Y2", 2 ) == 0 || strncmp(pNewCmdTlv->pPkg, "Y3", 2 ) == 0)
				{
					//m_bRetSuccess = TRUE;
					bContinue = FALSE;
				}
				else
				{
					iExitPro = 99;//add by liuwd 20091225, ����ʧ��Ӧ��ʱ����
				}
				
			}
			else
			{
				//m_bRetSuccess = FALSE;
				bContinue = FALSE;

				iExitPro = 100;//add by liuwd 20091225, POS��ֹ�˽���,��ʹPOS�ٷ��ڶ���
			}
			if( strncmp(pNewCmdTlv->pPkg, "00000002", 8 ) == 0 )//���������
			{
				bContinue = TRUE;
			}
			if( strncmp(pNewCmdTlv->pPkg, "00000004", 8 ) == 0 )//δ֪AID
			{
				bContinue = TRUE;
			}
			if( strncmp(pNewCmdTlv->pPkg, "00010014", 8 ) == 0 )//��Կδ��װ,��Ҫ����ǩ��
			{
				m_gentool.CFG_Set_Key(CONFIG_FILE,  "PROGRAM", "SIGNIN", "1");
			}
		}
		// 		if( !m_b8583Pkg && strncmp( pNewCmdTlv->tagID, "DF06", 4 ) == 0 )
// 		{
// 			if ( !TlvUnPackSubRet(pNewCmdTlv->pPkg, pNewCmdTlv->tagLen))
// 				return FALSE;
// 		}
		
		m_TlvPtrArray.Add( pNewCmdTlv );
		
		pCurRet = pCurRet+ iTagLen;
		iRetLen -= iTagLen;
		
	}
	
	for(int i = 0; i < m_TlvPtrArray.GetSize(); i++)
	{
		pNewCmdTlv = m_TlvPtrArray.GetAt(i);
		// ǩ���ɹ����Ʊ�ݴ�ӡ����
		if( strncmp( pNewCmdTlv->tagID, "DF02", 4 ) == 0 ) //��������
		{
			if( strncmp(pNewCmdTlv->pPkg, POS_LOGIN, 2 ) == 0 )
			{
				//m_bRetSuccess = FALSE; //��ֹǩ����ӡСƱ
			}

			//״̬��ѯ������
			if( strncmp(pNewCmdTlv->pPkg, "13", 2 ) == 0 )
			{
			//	m_bRetSuccess = FALSE; //��Ҫ��СƱ

			}

		}

 
		//add by liuwd 20091218
		if( strncmp( pNewCmdTlv->tagID, "DF04", 4 ) == 0 ) //�����
		{
			if (iFlag ==1)
			{
				iFlag =0;
			}
			else if( strncmp(pNewCmdTlv->pPkg, m_cRandom, 4 ) != 0 )
			{
				m_gentool.WriteLog( LOG_LEVEL2, "[�����豸]��������[%s]-[%s]", pNewCmdTlv->pPkg, m_cRandom ) ;
// 				m_bRetSuccess = FALSE;
//  
// 				m_DllRadom = FALSE;
//  
				return -1;
			}
		}
 
		//end add

		if( strncmp( pNewCmdTlv->tagID, "DF24", 4 ) == 0 ) //�Ƿ��н�����
		{
			m_gentool.WriteLog( LOG_LEVEL2, "[�����豸] DF24:[%02x]", pNewCmdTlv->pPkg[0]);
			if( pNewCmdTlv->pPkg[0] == 0x01 )
			{
				m_bPackEnd = TRUE;
			}
		}
		
		if( !m_b8583Pkg && strncmp( pNewCmdTlv->tagID, "DF06", 4 ) == 0 ) //�Ǵ�ӡСƱ����
		{
				//����������Ϣ
				char strMaskRetInfoHex[MAX_CFG_BUF]={0};
				
				m_gentool.FunBin2Hex( m_MoniBuf, strMaskRetInfoHex, m_MoniLen );
				 HiddenRetInfo( strMaskRetInfoHex, FALSE );
				 m_gentool.WriteLog( LOG_LEVEL3, "[�����豸]���յ�POS�������ݰ���ϸ=[%s]", strMaskRetInfoHex ) ;
				//
	 

			if(!m_bQueryList) //�ǲ���ˮģʽ
			{
//				WriteLog( LOG_LEVEL2,"[�����豸]��ʼ���ӡTAG!");

				if ( !TlvUnPackSubRet(pNewCmdTlv->pPkg, pNewCmdTlv->tagLen))
					return 0;
				else
					break;
			}
			else
			{
				if ( !TlvUnPackSubRetList(pNewCmdTlv->pPkg, pNewCmdTlv->tagLen))
					return 0;
				else
					break;
			}
		}
	}
	return 1;
}
BOOL CIngPosCom::TlvUnPackSubRet( char* pPtrSub, int iSubLen )
{
	// �������
	FreeTlvSubPkgArray();
	
	char cPackageBin[1024];
	memset( cPackageBin, 0, sizeof(cPackageBin) );

	CmdTlv	*pNewCmdTlv = NULL;
	char *pCurRet = NULL;
	
	m_gentool.FunHex2Bin( pPtrSub, cPackageBin, iSubLen );
	pCurRet = cPackageBin;
	int iRetLen = iSubLen ;
	int iTagLen = 0;
	while( iRetLen > 0 )
	{
		pNewCmdTlv = new CmdTlv;
		if ( pNewCmdTlv != NULL )
		{
			memset( pNewCmdTlv, 0, sizeof(CmdTlv) );
		}
		TlvUnPack(pCurRet, iTagLen, pNewCmdTlv);
		//
		if( strncmp( pNewCmdTlv->tagID, "DF07", 4 ) == 0 )
		{
		//	if( strncmp(pNewCmdTlv->pPkg, "01", 2 ) == 0 )
		//	{
		//		m_b8583Pkg = TRUE;
		//	}
			;
		}
		// 		if( strncmp( pNewCmdTlv->tagID, "DF06", 4 ) == 0 )
		// 		{
		// 			TlvUnPack(pNewCmdTlv->pPkg, pNewCmdTlv->, pNewCmdTlv);
		// 		}
		
		m_TlvPtrSubArray.Add( pNewCmdTlv );
		
		pCurRet = pCurRet+ iTagLen;
		iRetLen -= iTagLen;
		
	}
	return TRUE;
}


BOOL CIngPosCom::TlvUnPackSubRetList( char* pPtrSub, int iSubLen )
{
	// �������
//	FreeTlvSubPkgArray();
	BOOL bCurOper;


	CmdTlv tmpcmdtlv[3];
	
	char cPackageBin[1024];
	memset( cPackageBin, 0, sizeof(cPackageBin) );

	CmdTlv	*pNewCmdTlv = NULL;
	char *pCurRet = NULL;
	
	m_gentool.FunHex2Bin( pPtrSub, cPackageBin, iSubLen );
	pCurRet = cPackageBin;
	int iRetLen = iSubLen ;
	int iTagLen = 0;
	while( iRetLen > 0 )
	{
		pNewCmdTlv = tmpcmdtlv;
		if ( pNewCmdTlv != NULL )
		{
			memset( pNewCmdTlv, 0, sizeof(CmdTlv) );
		}
		
		TlvUnPack(pCurRet, iTagLen, pNewCmdTlv);
	//	m_gentool.WriteLog( LOG_LEVEL2, "��ˮ��ȡTAG[%s], LEN[%d], VALUE[%s], NAME[%s], TYPE[%02x]", pNewCmdTlv->tagID, pNewCmdTlv->tagLen, pNewCmdTlv->pPkg, pNewCmdTlv->tagName, pNewCmdTlv->tagType ) ;
		//һ�ʽ�����ˮ��ȡ
		
		//��Ա������ǰ,�������Ҫ���ݹ�Ա�Ų���ˮ��ֱ�Ӱ�bCurOper��Ϊ�漴��
		char cOperList[3];
		memset(cOperList, 0, sizeof(cOperList));
		m_gentool.CFG_Get_Key(CONFIG_FILE,  "DEVICE", "OPERLIST", cOperList);
		if(cOperList[0] == '1')
		{
			if( strncmp( pNewCmdTlv->tagID, "DF47", 4 ) == 0 ) //��Ա��
			{
				if(pNewCmdTlv->pPkg == NULL)
				{
					bCurOper = FALSE;	
				}
				else if(!strcmp(pNewCmdTlv->pPkg,  m_TradeInfo.szOperNo)) //��ǰ��Ա
					bCurOper = TRUE;
				else
					bCurOper = FALSE;
			}
		}
		else
		{
			bCurOper = TRUE;
		}

		if( strncmp( pNewCmdTlv->tagID, "DF03", 4 ) == 0 ) //���
		{
			sprintf( liststru[ilistsum].cAmt, "%-19.19s", pNewCmdTlv->pPkg );
		}
		
		if( strncmp( pNewCmdTlv->tagID, "DF02", 4 ) == 0 ) //��������
		{
			sprintf( liststru[ilistsum].cTranType, "%2.2s", pNewCmdTlv->pPkg );
		}
		
		if( strncmp( pNewCmdTlv->tagID, "DF10", 4 ) == 0 ) //��������
		{
			sprintf( liststru[ilistsum].cInvoice, "%-6.6s", pNewCmdTlv->pPkg );
		}
		
        if ( strncmp(pNewCmdTlv->tagID,"DF1E", 4 )==0 ) //����
		{
			sprintf( liststru[ilistsum].cCardNo, "%s", pNewCmdTlv->pPkg );
			
			//WriteLog( LOG_LEVEL2, "ilistsum[%d]" ,ilistsum ) ;
		}
		
		if ( strncmp(pNewCmdTlv->tagID,"DF1C", 4 )==0 ) //��������
		{
			sprintf( liststru[ilistsum].cTranDate, "%s", pNewCmdTlv->pPkg );
			
			//WriteLog( LOG_LEVEL2, "ilistsum[%d]" ,ilistsum ) ;
		}
		
		if ( strncmp(pNewCmdTlv->tagID,"DF1D", 4 )==0 ) //����ʱ��
		{
			sprintf( liststru[ilistsum].cTranTime, "%s", pNewCmdTlv->pPkg );
			
			//WriteLog( LOG_LEVEL2, "ilistsum[%d]" ,ilistsum ) ;
		}
		
		if( strncmp( pNewCmdTlv->tagID, "DF1B", 4 ) == 0 ) //��Ȩ��
		{
			sprintf( liststru[ilistsum].cAuthNo, "%s", pNewCmdTlv->pPkg );
		}
		
		if( strncmp( pNewCmdTlv->tagID, "DFBE", 4 ) == 0 ) //�̻�������
		{
			//sprintf(liststru[ilistsum].cMerchantOrder, "%s", m_gentool.atrimstr(pNewCmdTlv->pPkg));
			if(bCurOper)
			{
				ilistsum++; //��������һ�ֳ�ȡ���
			}
			else
			{		
				//memset(liststru[ilistsum].cMerchantOrder, 0, sizeof(liststru[ilistsum].cMerchantOrder));
				memset(liststru[ilistsum].cCardNo, 0, sizeof(liststru[ilistsum].cCardNo));
				memset(liststru[ilistsum].cInvoice, 0, sizeof(liststru[ilistsum].cInvoice));
				memset(liststru[ilistsum].cTranType, 0, sizeof(liststru[ilistsum].cTranType));
				memset(liststru[ilistsum].cAmt, 0, sizeof(liststru[ilistsum].cAmt));
				memset(liststru[ilistsum].cTranFlag, 0, sizeof(liststru[ilistsum].cTranFlag));
				memset(liststru[ilistsum].cAuthNo, 0, sizeof(liststru[ilistsum].cAuthNo));
				memset(liststru[ilistsum].cTranDate, 0, sizeof(liststru[ilistsum].cTranDate));
				memset(liststru[ilistsum].cTranTime, 0, sizeof(liststru[ilistsum].cTranTime));
			}
		}

		//��ȡ����			
		pCurRet = pCurRet+ iTagLen;
		iRetLen -= iTagLen;
		
	}
	return TRUE;
}


BOOL CIngPosCom::GetTlvTagType(char *pTagID, CmdTlv* pCmdTlv)
{
	for (int i = 0;  g_CmdTlv[i].tagID[0] != '\0'; i++ )
	{
		if ( !memcmp(pTagID, g_CmdTlv[i].tagID, 4) )
		{
			memcpy( pCmdTlv, &g_CmdTlv[i], sizeof(CmdTlv) );
			return TRUE;
		}
	}
	return FALSE;
}



BOOL CIngPosCom::InitTranRetInfo(TranRetInfo* pRetInfo, BOOL bTimeOut)
{
//	m_gentool.WriteLog(LOG_LEVEL2,"[�����豸]��ʼ��ʼ��������Ϣ!") ;

	if ( !bTimeOut )
	{
		sprintf( pRetInfo->cRetCode, "%s", "99" );
		sprintf( pRetInfo->cRetMsg, "%s", "����ȡ��" );	
	}
	else
	{
		sprintf( pRetInfo->cRetCode, "%s", "99" );
		sprintf( pRetInfo->cRetMsg, "%s", "�豸��ʱ" );			
		return TRUE;
	}

//	m_gentool.WriteLog(LOG_LEVEL2,"[�����豸]��ʼ��ʼ��������Ϣ,����TAG!") ;

	CmdTlv* pCmdTlv = NULL;
	for(int i = 0; i < m_TlvPtrSubArray.GetSize(); i++)
	{
		pCmdTlv = m_TlvPtrSubArray.GetAt(i);
		if( pCmdTlv->pPkg != NULL )
		{

//			WriteLog( LOG_LEVEL2, "[�����豸][%s][%s][%s]", pCmdTlv->tagName, pCmdTlv->tagID, pCmdTlv->pPkg ) ;

			//�ն˺�
			if ( strncmp(pCmdTlv->tagID,"DF12", 4 )==0 )
				sprintf( pRetInfo->cTerminalID, "%s", pCmdTlv->pPkg );
			//�̻��� 
			else if ( strncmp(pCmdTlv->tagID,"DF13", 4 )==0 )
				sprintf( pRetInfo->cMerchantID, "%s", pCmdTlv->pPkg );
			//���׽�� 
			else if ( strncmp(pCmdTlv->tagID,"DF03", 4 )==0 )
				sprintf( pRetInfo->cAmount, "%-19.19s", pCmdTlv->pPkg );
			//��������
			else if ( strncmp(pCmdTlv->tagID,"DF02", 4 )==0 )
			{
				sprintf( pRetInfo->cTranCode, "%s", pCmdTlv->pPkg );
				if ( strlen(pRetInfo->cTranCode)>0 && strcmp(pRetInfo->cTranCode, POS_LOGIN) )
				{
					sprintf( pRetInfo->cRetCode, "%s", "00" );
					sprintf( pRetInfo->cRetMsg, "���׳ɹ�" );
//					WriteLog(LOG_LEVEL2,"[�����豸]��ȱʡ���׷�����[%s]!", pRetInfo->cRetCode);
				}
			}
			else if ( strncmp(pCmdTlv->tagID,"DF05", 4 )==0 )
			{
				sprintf( pRetInfo->cHostId, "%s", pCmdTlv->pPkg );
			}
			//������
			else if ( strncmp(pCmdTlv->tagID,"DF07", 4 )==0 )
			{
				sprintf( pRetInfo->cRetCode, "%s", pCmdTlv->pPkg );

//				WriteLog(LOG_LEVEL2,"[�����豸]���׷�����[%s]!", pRetInfo->cRetCode);
			}
				//��ˮ��
			else if ( strncmp(pCmdTlv->tagID,"DF0A", 4 )==0 )
				sprintf( pRetInfo->cTraceNo, "%s", pCmdTlv->pPkg );

			//����ʱ��
			else if ( strncmp(pCmdTlv->tagID,"DF0B", 4 )==0 )
			{
// 				CTime CurTime;
// 				CurTime = CTime::GetCurrentTime();
// 				sprintf( pRetInfo->cTranDate_Old, "%s%4.4s", CurTime.Format("%Y"), pCmdTlv->pPkg );
// 				sprintf( pRetInfo->cTranTime_Old, "%s", pCmdTlv->pPkg+4 );
			}
			//Ʊ�ݺ�
			else if ( strncmp(pCmdTlv->tagID,"DF10", 4 )==0 )
				sprintf( pRetInfo->cInvoiceNo, "%s", pCmdTlv->pPkg );
			
			//���κ�
			else if ( strncmp(pCmdTlv->tagID,"DF11", 4 )==0 )
				sprintf( pRetInfo->cBatchID, "%s", pCmdTlv->pPkg );
	
			// �˻�ʱԭ������ˮ�š�����ʱΪԭ������ˮ��
			else if ( strncmp(pCmdTlv->tagID,"DF19", 4 )==0 )
				sprintf( pRetInfo->vInvoiceID, "%s", pCmdTlv->pPkg );
			//ϵͳ�ο���
			else if ( strncmp(pCmdTlv->tagID,"DF1A", 4 )==0 )
				sprintf( pRetInfo->cSysRRN, "%s", pCmdTlv->pPkg );
			
			//��Ȩ��
			else if ( strncmp(pCmdTlv->tagID,"DF1B", 4 )==0 )
				sprintf( pRetInfo->cAuthNo, "%s", pCmdTlv->pPkg ); //add 20100315
			//����
			else if ( strncmp(pCmdTlv->tagID,"DF1C", 4 )==0 )
			{
				CTime CurTime;
				CurTime = CTime::GetCurrentTime(); 
				sprintf( pRetInfo->cTranDate, "%4.4s%s", CurTime.Format("%Y"), pCmdTlv->pPkg );
			}
			//ʱ�� 
			else if ( strncmp(pCmdTlv->tagID,"DF1D", 4 )==0 )
				sprintf( pRetInfo->cTranTime, pCmdTlv->pPkg );

			//����
			else if ( strncmp(pCmdTlv->tagID,"DF1E", 4 )==0 )
				sprintf( pRetInfo->cCardNo, "%s", pCmdTlv->pPkg );

			//��Ч�� 
			else if ( strncmp(pCmdTlv->tagID,"DF1F", 4 )==0 )
			{
				sprintf( pRetInfo->cExpire, "%2.2s%2.2s", pCmdTlv->pPkg, pCmdTlv->pPkg+3 );
			}
		
			//������
			else if ( strncmp(pCmdTlv->tagID,"DF21", 4 )==0 )
				sprintf( pRetInfo->cCardType, "%s", pCmdTlv->pPkg );
			
			//������ID
			else if ( strncmp(pCmdTlv->tagID,"DF22", 4 )==0 )
			{
				sprintf( pRetInfo->cIssuerID, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2,"[����]DF22 ������ID[%s]!", pRetInfo->cIssuerID);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF25", 4 )==0 )
				sprintf( pRetInfo->cSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF26", 4 )==0 )
				sprintf( pRetInfo->cSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF27", 4 )==0 )
				sprintf( pRetInfo->cSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF28", 4 )==0 )
				sprintf( pRetInfo->cSettleCreSum, "%s", pCmdTlv->pPkg );
			//������
			else if ( strncmp(pCmdTlv->tagID,"DF2C", 4 )==0 )
				sprintf( pRetInfo->cCardName, "%s", pCmdTlv->pPkg );
			//�ն����뷽ʽ
			else if ( strncmp(pCmdTlv->tagID,"DF2F", 4 )==0 )
				sprintf( pRetInfo->cInputMode, "%s", pCmdTlv->pPkg );

			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF3E", 4 )==0 )
				sprintf( pRetInfo->cCardHolder, "%s", pCmdTlv->pPkg );
			// 
			else if ( strncmp(pCmdTlv->tagID,"DF30", 4 )==0 )
				sprintf( pRetInfo->cIcAID, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF31", 4 )==0 )
				sprintf( pRetInfo->cIcAPPPRE, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF32", 4 )==0 )
				sprintf( pRetInfo->cIcAPPLABEL, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF33", 4 )==0 )
				sprintf( pRetInfo->cIcTC, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF34", 4 )==0 )
				sprintf( pRetInfo->cIcTVR, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF35", 4 )==0 )
				sprintf( pRetInfo->cIcTSI, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF36", 4 )==0 )
				sprintf( pRetInfo->cIcCVMR, "%s", pCmdTlv->pPkg );
			//
			else if ( strncmp(pCmdTlv->tagID,"DF3D", 4 )==0 )
				sprintf( pRetInfo->cIcATC, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF37", 4 )==0 )
				sprintf( pRetInfo->cIcTACDEF, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF38", 4 )==0 )
				sprintf( pRetInfo->cIcTACDEN, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF39", 4 )==0 )
				sprintf( pRetInfo->cIcTACONL, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF3A", 4 )==0 )
				sprintf( pRetInfo->cIcIACDEF, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF3B", 4 )==0 )
				sprintf( pRetInfo->cIcIACDEN, "%s", pCmdTlv->pPkg );
			//��Ա��
			else if ( strncmp(pCmdTlv->tagID,"DF3C", 4 )==0 )
				sprintf( pRetInfo->cIcIACONL, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF3F", 4 )==0 )
				sprintf(pRetInfo->cFeeAmount, "%s", pCmdTlv->pPkg); //�����ѽ��
			else if ( strncmp(pCmdTlv->tagID,"DF40", 4 )==0 ) //20100315
				sprintf(pRetInfo->cFirstAmount, "%s", pCmdTlv->pPkg); //�����׸���
			else if ( strncmp(pCmdTlv->tagID,"DF41", 4 )==0 )
				sprintf(pRetInfo->cMonAmount, "%s", pCmdTlv->pPkg); //���»���
			else if ( strncmp(pCmdTlv->tagID,"DF42", 4 )==0 )
				sprintf(pRetInfo->cTenor, "%s", pCmdTlv->pPkg); //����
			else if ( strncmp(pCmdTlv->tagID,"DF43", 4 )==0 )
				sprintf(pRetInfo->cPlanId, "%s", pCmdTlv->pPkg); //�ƻ���
			else if ( strncmp(pCmdTlv->tagID,"DF44", 4 )==0 )
				sprintf(pRetInfo->cMerchantEName, "%s", pCmdTlv->pPkg); //�̻�Ӣ������
			else if ( strncmp(pCmdTlv->tagID,"DF45", 4 )==0 )
			{
				sprintf(pRetInfo->cMerchantCName, "%s", pCmdTlv->pPkg); //�̻���������
				m_gentool.atrimstr(pRetInfo->cMerchantCName,' ');
			}
			else if ( strncmp(pCmdTlv->tagID,"DF48", 4 )==0 )	//���ڿ�����ͳ�Ʋ���
			{
				sprintf( pRetInfo->cCupSettleDebAmt, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2,"��������ǽ��=[%s]", pRetInfo->cCupSettleDebAmt);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF49", 4 )==0 )
			{
				sprintf( pRetInfo->cCupSettleDebSum, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2,"��������Ǳ���=[%s]", pRetInfo->cCupSettleDebSum);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF4A", 4 )==0 )	//���п�����ͳ�Ʋ���
				sprintf( pRetInfo->cBocSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF4B", 4 )==0 )
				sprintf( pRetInfo->cBocSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF4C", 4 )==0 )
				sprintf( pRetInfo->cBocSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF4D", 4 )==0 )
				sprintf( pRetInfo->cBocSettleCreSum, "%s", pCmdTlv->pPkg );


			else if ( strncmp(pCmdTlv->tagID,"DF50", 4 )==0 )
			{
				sprintf( pRetInfo->cCupSettleCreAmt, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2,"���������ǽ��=[%s]", pRetInfo->cCupSettleCreAmt);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF51", 4 )==0 )
			{
				sprintf( pRetInfo->cCupSettleCreSum, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2,"���������Ǳ���=[%s]", pRetInfo->cCupSettleCreSum);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF52", 4 )==0 )	//VISA������ͳ�Ʋ���
				sprintf( pRetInfo->cVisaSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF53", 4 )==0 )
				sprintf( pRetInfo->cVisaSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF54", 4 )==0 )
				sprintf( pRetInfo->cVisaSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF55", 4 )==0 )
				sprintf( pRetInfo->cVisaSettleCreSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF56", 4 )==0 )	//MASTER������ͳ�Ʋ���
				sprintf( pRetInfo->cMastSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF57", 4 )==0 )
				sprintf( pRetInfo->cMastSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF58", 4 )==0 )
				sprintf( pRetInfo->cMastSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF59", 4 )==0 )
				sprintf( pRetInfo->cMastSettleCreSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF5A", 4 )==0 )	//��ͨAEX������ͳ�Ʋ���
				sprintf( pRetInfo->cAexSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF5B", 4 )==0 )
				sprintf( pRetInfo->cAexSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF5C", 4 )==0 )
				sprintf( pRetInfo->cAexSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF5D", 4 )==0 )
				sprintf( pRetInfo->cAexSettleCreSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF5E", 4 )==0 )	//DEC����������ͳ�Ʋ���
				sprintf( pRetInfo->cDecSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF5F", 4 )==0 )
				sprintf( pRetInfo->cDecSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF60", 4 )==0 )
				sprintf( pRetInfo->cDecSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF61", 4 )==0 )
				sprintf( pRetInfo->cDecSettleCreSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF62", 4 )==0 )	//JCB������ͳ�Ʋ���
				sprintf( pRetInfo->cJcbSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF63", 4 )==0 )
				sprintf( pRetInfo->cJcbSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF64", 4 )==0 )
				sprintf( pRetInfo->cJcbSettleCreAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF65", 4 )==0 )
				sprintf( pRetInfo->cJcbSettleCreSum, "%s", pCmdTlv->pPkg );

		
			else if ( strncmp(pCmdTlv->tagID,"DF66", 4 )==0 )
			{
				//	ShowBin2HexStr("[�������]���׳ɹ�ʱ���ص�56������" ,pCmdTlv->pPkg, pCmdTlv->tagLen );
				memcpy(pRetInfo->c56tag, pCmdTlv->pPkg,  2*pCmdTlv->tagLen);
				pRetInfo->i56taglen = pCmdTlv->tagLen;
				//	FunBin2Hex(pCmdTlv->pPkg,  pRetInfo->c56tag, pCmdTlv->tagLen);
				//		WriteLog(LOG_LEVEL2,"[�������]���׳ɹ�ʱ�����56������[%s][%d]", pRetInfo->c56tag, pRetInfo->i56taglen);
				
				//	memcpy(pRetInfo->c56tag, pCmdTlv->pPkg, pCmdTlv->tagLen);
				//	pRetInfo->i56taglen = pCmdTlv->tagLen;
			}
			else if (	strncmp(pCmdTlv->tagID,"DF69", 4 )==0) // ϵͳ�����ţ�΢��֧�����˻��ã�������ƾ֤�ţ�������ά�룩
			{
				sprintf(pRetInfo->cPayNo,"%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF69 ����ƾ֤��/ϵͳ������=[%s]", pRetInfo->cPayNo );
			}

			else if ( strncmp(pCmdTlv->tagID,"DF6C", 4 )==0 )	//��ά�����ͳ�Ʋ���
				sprintf( pRetInfo->cSettleDebQRAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF6D", 4 )==0 )
				sprintf( pRetInfo->cSettleDebQRSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF6E", 4 )==0 )
				sprintf( pRetInfo->cSettleCreQRAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF6F", 4 )==0 )
				sprintf( pRetInfo->cSettleCreQRSum, "%s", pCmdTlv->pPkg );
 

			else if ( strncmp(pCmdTlv->tagID,"DF70", 4 )==0 )
				sprintf(pRetInfo->cAddData, "%s", pCmdTlv->pPkg); //44�򸽼���Ϣ
			else if ( strncmp(pCmdTlv->tagID,"DF71", 4 )==0 )
				sprintf(pRetInfo->cDccRate, "%s", pCmdTlv->pPkg); //��һ�����Ϣ
			else if ( strncmp(pCmdTlv->tagID,"DF72", 4 )==0 )
				sprintf(pRetInfo->cDccBaseAmt, "%s", pCmdTlv->pPkg); //DCC��ҽ��

			else if (	strncmp(pCmdTlv->tagID,"DF7A", 4 )==0)
			{
				//sprintf(pRetInfo->ce,"%s", pCmdTlv->pPkg);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF7B", 4 )==0)
			{
				sprintf(pRetInfo->NQCCardNo,"%s", pCmdTlv->pPkg);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF74", 4 )==0)
			{

				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF74 =[%s]", pCmdTlv->pPkg );
			}
			else if ( strncmp(pCmdTlv->tagID,"DF76", 4 )==0)
			{
				sprintf(pRetInfo->cIcUnpNumber,"%s", pCmdTlv->pPkg);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF77", 4 )==0)
			{
				sprintf(pRetInfo->cIcAIP,"%s", pCmdTlv->pPkg);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF78", 4 )==0)
			{
				sprintf(pRetInfo->cIcTVR,"%s", pCmdTlv->pPkg);
			}
			else if ( strncmp(pCmdTlv->tagID,"DF80", 4 )==0 )
				sprintf(pRetInfo->cDccmarkup, "%s", pCmdTlv->pPkg); //markup����
			else if ( strncmp(pCmdTlv->tagID,"DF82", 4 )==0)
			{
				if( strlen(pRetInfo->cDctAmount) > 0 )
				    sprintf(pRetInfo->cDctAmount,"%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "POS�����Żݽ��=[%s]", pCmdTlv->pPkg );
			}
			/*
			else if ( strncmp(pCmdTlv->tagID,"DF83", 4 )==0 )
				sprintf( pRetInfo->cEWMYouhuiFlag, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF84", 4 )==0 )	//������ά���Ż�ͳ�Ʋ���
				sprintf( pRetInfo->cEWMYouhuiSettleDebAmt, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF85", 4 )==0 )
				sprintf( pRetInfo->cEWMYouhuiSettleDebSum, "%s", pCmdTlv->pPkg );
			else if ( strncmp(pCmdTlv->tagID,"DF86", 4 )==0 )
				sprintf( pRetInfo->cEWMYouhuiSettleCreAmt, "%s", pCmdTlv->pPkg );
			*/
			else if ( strncmp(pCmdTlv->tagID, "DF83", 4 )==0)  //΢֧����ʱ�Ľ�ǽ��
			{
				sprintf( pRetInfo->cSettleDebWzAmt, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF83 ΢֧��ǽ��=[%s]", pRetInfo->cSettleDebWzAmt );
			}
			else if ( strncmp(pCmdTlv->tagID, "DF84", 4 )==0)  //΢֧����ʱ�Ľ�Ǳ���
			{
				sprintf( pRetInfo->cSettleDebWzSum, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF84 ΢֧��Ǳ���=[%s]", pRetInfo->cSettleDebWzSum );
			}
			else if ( strncmp(pCmdTlv->tagID, "DF85", 4 )==0)   //΢֧����ʱ�Ĵ��ǽ��
			{
				sprintf( pRetInfo->cSettleCreWzAmt, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF85 ΢֧���ǽ��=[%s]", pRetInfo->cSettleCreWzAmt );
			}
			else if ( strncmp(pCmdTlv->tagID, "DF86", 4 )==0)  //΢֧����ʱ�Ĵ��Ǳ���
			{
				sprintf( pRetInfo->cSettleCreWzSum, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF86 ΢֧���Ǳ���=[%s]", pRetInfo->cSettleCreWzSum );
			}
			
			else if ( strncmp(pCmdTlv->tagID,"DF87", 4 )==0)  // ֧����ʽ
			{
				sprintf(pRetInfo->cTranFlag,"%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF87 ֧����ʽ=[%s]", pRetInfo->cTranFlag );
			}
			else if ( strncmp(pCmdTlv->tagID, "DF88", 4 )== 0)  // ΢֧���׵�����ϵͳ������
			{
				sprintf( pRetInfo->cPayNo, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL3, "[����] ���DF88 ������ϵͳ������=[%s]", pRetInfo->cPayNo );
			}
			else if ( strncmp(pCmdTlv->tagID,"DF8F", 4 )==0)  // ֧����ʽ
			{
				sprintf(pRetInfo->cSurplusNum,"%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF8F ����ʣ������=[%s]", pRetInfo->cSurplusNum );
			}
			
			else if ( strncmp(pCmdTlv->tagID, "DF90", 4 )== 0)  //΢��֧����
			{
				sprintf( pRetInfo->cVoidPayNo, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] ���DF90 ԭ΢֧����ƾ֤��=[%s]", pRetInfo->cVoidPayNo );
			}
			else if ( strncmp(pCmdTlv->tagID,"DFA1", 4 ) == 0 )  //��ǩ��־
			{
				if(strncmp(pCmdTlv->pPkg,"1", 1) == 0 )
				{
					m_iSIGN = 1;
				}
			}
			else if (strncmp(pCmdTlv->tagID,"DFA2", 4 ) == 0)   //��ǩ�޶�
			{
				sprintf(pRetInfo->cSIGNAMT, "%s", pCmdTlv->pPkg);
			}
			else if (strncmp(pCmdTlv->tagID,"DFA8", 4 ) == 0)
			{
				sprintf(pRetInfo->cEWMdiscount, "%s", pCmdTlv->pPkg);
				m_gentool.WriteLog( LOG_LEVEL2, "[����] DFA8 ��ά���Ż���Ϣ=[%s]", pRetInfo->cEWMdiscount );
				CString strEWMdiscountAmt, strEWMdiscount, strtmp;
				char stmp[15];
				memset(stmp, 0, sizeof(stmp)/sizeof(char));
				strEWMdiscount.Format("%s", pRetInfo->cEWMdiscount);
				for (int i=0 ; i<=5; i++ )
				{
					strtmp = m_gentool.GetFirstParam(strEWMdiscount, "|");
					if(strtmp.IsEmpty() == TRUE)
					{
						break;
					}
					else
					{
						strEWMdiscountAmt.Format("%s", strtmp.Mid(25,12));
						m_gentool.WriteLog( LOG_LEVEL2, "[����]EWMdiscountAmt=[%s]", strEWMdiscountAmt );
						sprintf( stmp,"%12.12s",strEWMdiscountAmt);
						m_gentool.WriteLog( LOG_LEVEL2, "[����]stmp=[%s]", stmp );
						fEWMAmt += atoi(m_gentool.ltrimstr(stmp, '0'));
					}
				}
				m_gentool.WriteLog( LOG_LEVEL2, "[����]fEWMAmt=[%d]", fEWMAmt );
				sprintf(pRetInfo->cDctAmount, "%012d", fEWMAmt);
				m_gentool.WriteLog( LOG_LEVEL2, "[����]������ά���Żݽ��=[%s]", pRetInfo->cDctAmount );
			}
			else if ( strncmp(pCmdTlv->tagID,"DFA9", 4 )==0 ) //������ά���Ż�ͳ�Ʋ���
			{
				sprintf( pRetInfo->cEWMYouhuiSettleDebSum, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2, "[����] DFA9 ��ά�븶���Żݱ���=[%s]", pRetInfo->cEWMYouhuiSettleDebSum );
			}
			else if ( strncmp(pCmdTlv->tagID,"DFAA", 4 )==0 )
			{
				sprintf( pRetInfo->cEWMYouhuiSettleDebAmt, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2, "[����] DFAA ��ά�븶���Żݽ��=[%s]", pRetInfo->cEWMYouhuiSettleDebAmt );
			}
			else if ( strncmp(pCmdTlv->tagID,"DFAC", 4 )==0 )
			{
				sprintf( pRetInfo->cEWMYouhuiSettleCreSum, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2, "[����] DFAC ��ά���˿��Żݱ���=[%s]", pRetInfo->cEWMYouhuiSettleCreSum );
			}
			else if ( strncmp(pCmdTlv->tagID,"DFAD", 4 )==0 )
			{
				sprintf( pRetInfo->cEWMYouhuiSettleCreAmt, "%s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2, "[����] DFAD ��ά���˿��Żݽ��=[%s]", pRetInfo->cEWMYouhuiSettleCreAmt );
			}
			//Ӧ����� 
			else if ( strncmp(pCmdTlv->tagID,"DFBA", 4 )==0 )  //Ӧ�����
			{
				sprintf( pRetInfo->cOrgAmount, "%-19.19s", pCmdTlv->pPkg );
				m_gentool.WriteLog( LOG_LEVEL2, "[����]Ӧ�����=[%s]", pRetInfo->cOrgAmount );
			}
		 
		}
	}
	
	if ( m_TlvPtrSubArray.GetSize() == 0 )
	{
		for(int i = 0; i < m_TlvPtrArray.GetSize(); i++)
		{
			pCmdTlv = m_TlvPtrArray.GetAt(i);
			if ( strncmp(pCmdTlv->tagID,"DF07", 4 )==0 )
			{
				if ( strlen(pCmdTlv->pPkg) == 2 )
				{
					sprintf( pRetInfo->cRetCode, "%s", pCmdTlv->pPkg );

					    m_gentool.GetRetCodeMsg(pRetInfo->cRetCode, pRetInfo->cRetMsg);
					 
					if ( strcmp(pRetInfo->cRetCode,"63") == 0 ||
						strcmp(pRetInfo->cRetCode,"88") == 0 ||
						strcmp(pRetInfo->cRetCode,"87") == 0 ||
						strcmp(pRetInfo->cRetCode,"Z1") == 0 
						) 
						m_gentool.CFG_Set_Key(CONFIG_FILE,  "PROGRAM", "SIGNIN", "1");
					//m_gentool.WriteLog(LOG_LEVEL2,"[����]���׷���RetCode=[%s] bOffLine=[%d]", pRetInfo->cRetCode, m_pMainDlg->bOffLine );
				}
				else
				{
					// ��ʱ��English��EMV������
					sprintf( pRetInfo->cRetMsg, "%s", pCmdTlv->pPkg );
					sprintf( pRetInfo->cRetCode, "%s", "99" );
					m_gentool.GetEmvRetCodeMsg(pRetInfo->cRetMsg, pRetInfo->cRetMsg);
				}
				//sprintf( pRetInfo->Chinese, "����ʧ��" );
				break;
			}
			else if ( strncmp(pCmdTlv->tagID,"DF02", 4 )==0 )
			{
				sprintf( pRetInfo->cTranCode, "%s", pCmdTlv->pPkg );
			}
			else if( strncmp(pCmdTlv->tagID,"DF74", 4 )==0 )
			{

			}
		}
	}
	char tmp[100]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "TERMINAL", "MERCHANTCNAME", tmp );//ȱʡʹ�ñ�������
	m_gentool.CFG_Get_Key(CONFIG_FILE, "TERMINAL", "VER", pRetInfo->cVersion );
	if ( strlen(tmp) != 0 )
		sprintf(pRetInfo->cMerchantCName, "%s", tmp);
 

// 	char strFormat[50];
// 	char sMarkCard[30];
// 	memset(sMarkCard, 0, sizeof(sMarkCard));
// 	memset(strFormat, 0, sizeof(strFormat));
// 
// 	if( strncmp(m_TranRetInfo.cHostId, "02", 2) == 0 ||strncmp(m_TranRetInfo.cHostId, "03", 2) == 0  )
// 	{
// 		if( pRetInfo->cCardNo[0] == '5'	)//�����з���ͳһ
// 		{
// 			sprintf(pRetInfo->cCardType,"%2.2s", "32");
// 		}
// 		else
// 		{
// 			sprintf(pRetInfo->cCardType,"%2.2s", "22");
// 		}
// 	}
// 
// 	sprintf(strFormat, "%%6.6s%%%d.%ds%%-4.4s", strlen(pRetInfo->cCardNo)-4-6,strlen(pRetInfo->cCardNo)-4-6 );
// 	sprintf(sMarkCard , strFormat, pRetInfo->cCardNo, "********************", pRetInfo->cCardNo + strlen(pRetInfo->cCardNo)-4);

	return TRUE;
}
 
int CIngPosCom::TranAuthor()
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_PREAUTH, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr( "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranAuthorVoid()
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_VOIDAUTH, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF19", m_TradeInfo.szTraceID, 6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF16", m_TradeInfo.szAuthNO, 6, TLV_DATA_ASC); //��Ȩ��
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF17", m_TradeInfo.szTranDate+4, 4, TLV_DATA_BCD);//����
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0B", m_TradeInfo.szTranTime, 6, TLV_DATA_BCD);//ʱ��
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}


//�ǽӽ���
int CIngPosCom::TranECPurchase(  )
{
	char 	cCMDBuf[1024]={0};
	int		iCmdLen = 0;
	char cRandom[5]={0};
	
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
 	memcpy(m_cRandom, cRandom, sizeof(cRandom));
 
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_PURCHASE, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
 	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "0", 1, TLV_DATA_ASC);
 	if ( iAddCmdLen > 0 )
 	{
 		iCmdLen += iAddCmdLen;
 		iAddCmdLen = 0;
 	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF20", (LPSTR)(LPCSTR)"000000000000", 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranECQuery(  )
{
	char 	cCMDBuf[1024]={0};
	
	int		iCmdLen = 0;
	char cRandom[5]={0};
	
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
 
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_ECINQUIRY, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr( "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranECRefund()
{
    char 	cCMDBuf[1024]={0};

	int		iCmdLen = 0;
	char cRandom[5]={0};
	
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) ); 
	memcpy(	m_cRandom, cRandom, sizeof(cRandom));
 

	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_ECREFUND, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
 
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF19",  m_TradeInfo.szTraceID, 6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}

	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF17", m_TradeInfo.szTranDate+4, 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0B", m_TradeInfo.szTranTime, 6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}

	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}

	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );

	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );

	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::OffLine(  )
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
    sprintf( m_TranRetInfo.cTranCode,POS_OFFLINE);
	m_gentool.WriteLog(LOG_LEVEL3,"[�����豸]TranType=[%s]", m_TranRetInfo.cTranCode );
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_OFFLINE, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	
	Sleep(300);
	
	return TRUE;
}
//

int CIngPosCom::TranAuthorConfirm()
{	
	char 	cCMDBuf[1024];

	int		iCmdLen = 0;


	memset(cCMDBuf, 0, sizeof(cCMDBuf));

	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add

	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_CONFIRM, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", (LPSTR)(LPCSTR)m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF16", (LPSTR)(LPCSTR)m_TradeInfo.szAuthNO, 6, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0D", "1", 1, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}

	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
	iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );

	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );

	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );

	return TRUE;
}

int CIngPosCom::TranFenqiPurchase()
{
	char 	cCMDBuf[1024];
	int		iCmdLen = 0;
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_FQSALE, 2, TLV_DATA_BCD);//���ڸ���
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF20", (LPSTR)(LPCSTR)"000000000000", 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::TranFenqiRefund()
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02",POS_FQREFUND, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF03", m_TradeInfo.szAmount, 12, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF19",  m_TradeInfo.szTraceID, 6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF16", m_TradeInfo.szAuthNO, 6, TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF17", m_TradeInfo.szTranDate+4, 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF0B", m_TradeInfo.szTranTime, 6, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	return TRUE;
}

int CIngPosCom::QueryList()
{
	char 	cCMDBuf[1024];
	
	int		iCmdLen = 0;
	
	
	memset(cCMDBuf, 0, sizeof(cCMDBuf));
	
	char cRandom[5];
	memset(cRandom, 0, sizeof(cRandom));
	sprintf( cRandom, "%4.4d", m_gentool.GetRandom(1000,9999) );
	//add by liuwd 
	memcpy(m_cRandom, cRandom, sizeof(cRandom));
	//end add
	
	int iAddCmdLen = 0;
	iAddCmdLen = TlvCmdPack( cCMDBuf, "DF01", "00", 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF04", cRandom, strlen(cRandom), TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF02", POS_QURYLIST, 2, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF08", "5555", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF09", "3004", 4, TLV_DATA_BCD);
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
// 	if(m_pMainDlg->m_iDCCSel == 4 ) //==4,��Ϊ΢֧
// 	{
// 		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF05", "04", 2, TLV_DATA_BCD);
// 	}
// 	else if(m_pMainDlg->m_iDCCSel == 3 ) //==3,��ΪDCC
// 	{
// 		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF05", "02", 2, TLV_DATA_BCD);
// 	}
// 	else
	{
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF05", "01", 2, TLV_DATA_BCD);
	}
	if ( iAddCmdLen > 0 )
	{
		iCmdLen += iAddCmdLen;
		iAddCmdLen = 0;
	}
	
	/*�Ƿ�ȫ������ˮ��Ϣ	*/
	char cOperSta[3];
	memset(cOperSta, 0, sizeof(cOperSta));
	m_gentool.CFG_Get_Key(CONFIG_FILE,  "DEVICE", "OPERLIST", cOperSta);
	if(cOperSta[0] == '1') //��Ҫ��Ա����
	{
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF46", m_TradeInfo.szDeskNo, strlen(m_TradeInfo.szDeskNo), TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
		iAddCmdLen = TlvCmdPack( cCMDBuf+iCmdLen, "DF47", m_TradeInfo.szOperNo, strlen(m_TradeInfo.szOperNo), TLV_DATA_ASC);
		if ( iAddCmdLen > 0 )
		{
			iCmdLen += iAddCmdLen;
			iAddCmdLen = 0;
		}
	}
	/*�Ƿ�ȫ������ˮ��Ϣ	����*/
	
	// ���ֽ�ָ���У��
	if ( iCmdLen > 1 )
		iCmdLen = CommRebuildDataSync(cCMDBuf, iCmdLen  );
	
	m_gentool.ShowBin2HexStr(  "[�����豸]��POS���͵����ݰ�" ,cCMDBuf, iCmdLen );
	
	CommWrite(cCMDBuf, iCmdLen);
	//
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
	m_bQueryList = TRUE;
	return TRUE;
}

void CIngPosCom::SetReciveSign()
{
	m_dwStart = GetTickCount()+ POSCMDOUT;
	SetEvent( m_hRecvDataEvent );
}


BOOL CIngPosCom::CheckPinPort(int iPort, int iBaud, int DataBits, int StopBits, int Parity)
{
	char cDevName[10]={0};
	sprintf( cDevName,"COM%1d", iPort );
 
	// �ر��豸
	CommClose( );
	
	m_hComDev = CreateFile ( cDevName,GENERIC_WRITE|GENERIC_READ,0,NULL,OPEN_EXISTING, FILE_FLAG_OVERLAPPED,NULL);
	if ( m_hComDev == INVALID_HANDLE_VALUE )
		return FALSE;
	else
	{
		m_bConneted = TRUE;
		CommClose();
		return TRUE;
	}
}


void CIngPosCom::UnPackTranResult()
{
	InitTranRetInfo(&m_TranRetInfo);
}

int CIngPosCom::SaveTranList()
{
	if(ilistsum==0)
	{
		m_gentool.WriteLog(LOG_LEVEL1,"�޽�����ˮ����");
		return 0;
	}

	FILE * fPrintOut=NULL;
	char cPath[512]={0};
	m_gentool.GetCurrPath( cPath );

	char strPrtName[512]={0};
	sprintf(strPrtName,"%s\\%s",cPath,TRAN_LIST_FILE);
	fPrintOut = fopen(strPrtName, "w");
	if(fPrintOut==NULL)
	{
		m_gentool.WriteLog(LOG_LEVEL1,"����������ˮ�����ļ��쳣");
		return -1;	
	}
	for(int i = 0; i < ilistsum; i++)
	{
		char strFormat[30]={0};
		m_gentool.FormatCardMask(strFormat,liststru[i].cCardNo);
		char cPayCh[5]={0};
		if(atoi(liststru[i].cTranFlag)==3)
			sprintf(cPayCh,"4");
		else 
			sprintf(cPayCh,"0");

		char cTemp[200]={0};

		m_gentool.atrimstr(liststru[i].cAmt);
		sprintf(cTemp,"%s|%s|%s|%s|%s|%s|%s|%s|%s",strFormat,liststru[i].cAmt,liststru[i].cTranType,liststru[i].cTranFlag,liststru[i].cAuthNo,liststru[i].cInvoice,liststru[i].cTranDate,liststru[i].cTranTime,cPayCh);
		fprintf(fPrintOut,"%s\n",cTemp);
	}
	fclose(fPrintOut);
	return ilistsum;
}
