// DevMisPos.cpp : implementation file
//

#include "stdafx.h"
#include "Bank_Ist.h"
#include "DevMisPos.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


ListStru    liststru[3000];

/////////////////////////////////////////////////////////////////////////////
// CDevMisPos dialog

extern CGenTool m_gentool;

CDevMisPos::CDevMisPos(CWnd* pParent /*=NULL*/)
	: CDialog(CDevMisPos::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDevMisPos)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	m_bLogin=FALSE;
	m_bContinue=FALSE;
}


void CDevMisPos::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDevMisPos)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	DDX_Control(pDX, IDC_STATIC_TIP, m_ctlStaticInfo);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CDevMisPos, CDialog)
	//{{AFX_MSG_MAP(CDevMisPos)
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
	ON_MESSAGE(WM_COMMNOTIFY, OnCommNotify)
	ON_MESSAGE(WM_UPDATE_CONNECTION, OnUpdateConnection)
	ON_MESSAGE(WM_ANALYSE_PACKET, OnAnalysePacket)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDevMisPos message handlers


LRESULT CDevMisPos::OnUpdateConnection(WPARAM wParam, LPARAM lParam)
{
	UINT uEvent = (UINT) wParam;
	CSocketManager* pManager = reinterpret_cast<CSocketManager*>( lParam );
	
	if ( pManager != NULL)
	{
		if (uEvent == EVT_CONFAILURE || uEvent == EVT_CONDROP)
		{
			m_DevIngPos.m_bKeyIgnore =FALSE;
			m_gentool.WriteLog( LOG_LEVEL1,"���ܷ��������ķ��س�ʱ");
			m_SocketManager.StopComm();
		}
	}
	return 1L;
}
/**************************************************************
*������: OnAnalysePacket                                     *
*������: LRESULT                                             *
*������: �Է��������ص���Ϣ���и�ʽ���������Ƴ���            *
*�����: wParam    �ַ��������ַ             ��             *
*        lParam    CSocketManager ָ��         ��            *
*������: ��                                                  *
*������: 1                                                   *
**************************************************************/
LRESULT CDevMisPos::OnAnalysePacket( WPARAM wParam, LPARAM lParam )
{
	// ���緵����Ϣ����
	char* pRecive = NULL;
	pRecive = (char*)wParam;
	
	int iRevecive = m_SocketManager.GetReveciveLen();
 
 #ifdef TEST_VER
 	m_gentool.ShowBin2HexStr("���񷵻�����",pRecive, iRevecive);
 #endif
	
	
	m_DevIngPos.m_bKeyIgnore = FALSE;
	m_gentool.WriteLog( LOG_LEVEL2,"����������[%d]�ֽ�",iRevecive);

	m_DevIngPos.Pack8583Package(pRecive, iRevecive);
 

	
	return 1;
}

LRESULT CDevMisPos::OnCommNotify(WPARAM wParam, LPARAM lParam )
{
	int		iCommFrom;
	LONG	lResult = 0L;
	int		iRet=-1;
	
	iCommFrom = int(wParam);

	switch ( iCommFrom )
	{
		case PINPAD_TIME_OUT:
		{
			m_SocketManager.StopComm();//�������ݳ�ʱ
			Sleep(20);
			m_DevIngPos.CommClose();
			sprintf(m_TranResp.cRetCode,"%s","99");
			sprintf(m_TranResp.cRetMsg,"%s","������̽������ݳ�ʱ");
			m_gentool.WriteLog(LOG_LEVEL1,"������̽������ݳ�ʱ");			
			EndDialog(1);
		}
		break;
	case PINPAD_ACQ_SND:
		break;
	case PINPAD_REVEIVE_SUC:
		{
			m_DevIngPos.FreeTlvPkgArray();
			m_DevIngPos.FreeTlvSubPkgArray();
			m_gentool.WriteLog(LOG_LEVEL3,"������������");
			iRet = m_DevIngPos.TlvUnPackRet( m_bContinue);
			m_gentool.WriteLog(LOG_LEVEL2,"���������������[%d]",iRet);
			if( iRet == -1 )
			{
				m_DevIngPos.CommClose();
				m_SocketManager.StopComm();
				if(strlen(m_TranResp.cRetCode)==0)
				{
					sprintf(m_TranResp.cRetCode,"%s","99");
					sprintf(m_TranResp.cRetMsg,"%s","������̷������ݽ������");
					m_gentool.WriteLog(LOG_LEVEL1,"������̷������ݽ������");
				}

				EndDialog(1);		
				break;
			}
			else if (iRet == 2)
			{
				return TRUE;
			}
			else if(iRet==3)
			{
				m_gentool.WriteLog(LOG_LEVEL1,"��Ϣ���������ȴ����׽��");
				return TRUE;	
			}

			if(m_DevIngPos.m_bPackEnd==TRUE) //���к�����Ҫ����
			{
				if(m_DevIngPos.m_bQueryList)
				{
					m_DevIngPos.QueryList();
				}
				break; //ʲôҲ������
			}

			CmdTlv * p8538CmdTlv = NULL;
			if ( !m_bContinue ) //���׽�����ذ�
			{
				m_gentool.WriteLog( LOG_LEVEL2,"�ж�8583���׹���!");
				if( m_DevIngPos.Get8583Package(p8538CmdTlv) )
				{
					if(!Send8583Package(p8538CmdTlv->pPkg, p8538CmdTlv->tagLen))
					{
						m_DevIngPos.CommClose();						
						m_SocketManager.StopComm();	
						sprintf(m_TranResp.cRetCode,"%s","99");
						sprintf(m_TranResp.cRetMsg,"%s","����ǰ�û�ʧ�ܻ�������ʧ��");
						m_gentool.WriteLog(LOG_LEVEL1,"����ǰ�û�ʧ�ܻ�������ʧ��");
					
						EndDialog(1);
					}
					else
					{
						m_gentool.WriteLog( LOG_LEVEL3,"����8583��ǰ�óɹ�!");
					}
				}
				else
				{
					m_DevIngPos.UnPackTranResult();
					m_gentool.WriteLog( LOG_LEVEL2,"׼����������!");

 					if ( stricmp(m_TranReq.szTranCode, MIS_REPRINT ) == 0 )
					{	
						m_DevIngPos.GetTranResultInfo(&m_TranResp);
					}
					else
					{
						m_DevIngPos.GetTranResultInfo(&m_TranResp);
					}
					if ( !m_bLogin)
					{
						m_SocketManager.StopComm();
						m_DevIngPos.CommClose();
						//Sleep(10);
						m_gentool.WriteLog(LOG_LEVEL1,"���׽���0[%s][%s]",m_TranResp.cRetCode,m_TranResp.cRetMsg);
						EndDialog(0);
						break;
					}
					else
					{
						if((m_DevIngPos.iExitPro == 100) || (m_DevIngPos.iExitPro == 99))
						{
							m_DevIngPos.iExitPro = 0;
							m_SocketManager.StopComm();
 
							m_DevIngPos.CommClose();
							//Sleep(10);
							m_gentool.WriteLog(LOG_LEVEL1,"���׽���[%s][%s]",m_TranResp.cRetCode,m_TranResp.cRetMsg);
							EndDialog(0);
							break;
						}
	
						{
							m_DevIngPos.GetTranResultInfo(&m_TranResp);
							m_bLogin = FALSE;
							m_SocketManager.StopComm();
							
							m_DevIngPos.CommClose();
							//Sleep(10);
							m_gentool.WriteLog(LOG_LEVEL1,"ǩ�����[%s][%s]",m_TranResp.cRetCode,m_TranResp.cRetMsg);
							EndDialog(0);
							break;
						}
						//��ʼ��������
					}
				}
			}
			else
			{
				m_DevIngPos.SetReciveSign();
			}
		}
		break;
	case PINPAD_ERROR_COMM:
		EndDialog(1);
		break;
	}
	
	return lResult;
}



void CDevMisPos::SetTranReqInfo(TradeInfo * pReq)
{
	memset(&m_TranReq,0,sizeof(TradeInfo));
	memcpy(&m_TranReq,pReq,sizeof(TradeInfo));
}
void CDevMisPos::GetTranResultInfo(TranRetInfo * pResp)
{
	memset(pResp,0,sizeof(TranRetInfo));
	memcpy(pResp,&m_TranResp,sizeof(TranRetInfo));
}

BOOL CDevMisPos::PreTranslateMessage(MSG* pMsg) 
{
	// TODO: Add your specialized code here and/or call the base class
	if ( pMsg->message == WM_KEYDOWN )
	{
		if ( pMsg->wParam == VK_ESCAPE )
		{
			return TRUE;
		}
		if (pMsg->wParam==VK_RETURN)//ʹ�ûس�����
		{
			return TRUE;
		}
	}	
	return CDialog::PreTranslateMessage(pMsg);
 
}

BOOL CDevMisPos::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	ModifyStyleEx(WS_EX_APPWINDOW,WS_EX_TOOLWINDOW,0);
	ShowWindow(SW_HIDE);
	SetTimer(99,200,NULL);
	
	ModifyStyleEx(WS_EX_APPWINDOW,WS_EX_TOOLWINDOW, SWP_DRAWFRAME);	
	
	ModifyStyleEx(WS_EX_APPWINDOW,WS_EX_TOOLWINDOW); 
    WINDOWPLACEMENT  wp; //��ʾ����
    wp.length=sizeof(WINDOWPLACEMENT); 
    wp.flags=WPF_RESTORETOMAXIMIZED; 
    wp.showCmd=SW_HIDE; 
    SetWindowPlacement(&wp);
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CDevMisPos::OnTimer(UINT nIDEvent) 
{
	// TODO: Add your message handler code here and/or call default
	if (nIDEvent==99)
	{
		KillTimer(99);
		//StartTran();
		DWORD Dword;
		HANDLE handle = CreateThread( NULL, 0, & StartTran, this, 0, &Dword );
		if( handle != NULL )
		{
			//CloseHandle( handle );
			SetTimer( 199, 100, NULL );
			m_gentool.WriteLog(LOG_LEVEL2,"����StartTran�����̲߳���");
		}
		else
			EndDialog( -1 ); ///temp
	}
	if ( nIDEvent == 199 )
	{
		if ( 0 != m_nSTTOver )
		{
			KillTimer( 199 );
			EndDialog( m_nSTTRet );
		}
	}
	CDialog::OnTimer(nIDEvent);
}

DWORD WINAPI CDevMisPos::StartTran( LPVOID lpParameter )
{
	CDevMisPos * p = ( CDevMisPos * )lpParameter;
	int iRet=p->STTranMis();
	if (iRet==9)
	{
		; 
	}
	else
	{
		p->m_nSTTRet = iRet;
		p->m_nSTTOver = 1;
	}
	
 
	return 0;
}

int CDevMisPos::STTranMis()
{
	int iRet=-1;
	memset(&m_TranResp,0,sizeof(TranRetInfo));
	m_gentool.WriteLog( LOG_LEVEL3, "����startmis����");

	m_DevIngPos.SetTradeInfo(&m_TranReq);

	
	char cKeyVal[100]={0};
	int	iPort;

	
	m_gentool.WriteLog( LOG_LEVEL3, "��ȡ�����������");
	m_gentool.CFG_Get_Key(CONFIG_FILE, "DEVICE", "PINPAD", cKeyVal );
	
	CString strTmp, strPort;
	strPort.Format( "%s", cKeyVal );
	
	if ( strPort.GetLength() > 0 )
		iPort = atoi(strPort);
	else
		iPort = 1;
	m_DevIngPos.SetMainDlgHWnd(m_hWnd);

	if ( !m_DevIngPos.CommOpen( iPort ) )
	{	
		m_gentool.WriteLog(LOG_LEVEL1,"�򿪴���ʧ��");
		sprintf(m_TranResp.cRetCode,"%s","99");
		sprintf(m_TranResp.cRetMsg,"%s","�򿪴���ʧ��");
		return -1;
	}
	
	m_SocketManager.SetMessageWindow( &m_ctlStaticInfo );
	m_SocketManager.SetServerState( FALSE );
	m_SocketManager.SetSmartAddressing( FALSE );


	
	m_gentool.WriteLog( LOG_LEVEL3, "��ʼ���ף���������=��%s��",m_TranReq.szTranCode);

	m_gentool.WriteLog( LOG_LEVEL3, "֧������=��%s��",m_TranReq.szPayCh);

	
	if ( stricmp(m_TranReq.szTranCode, MIS_PURCHASE ) == 0 )
		m_DevIngPos.TranPurchase();
	else if ( stricmp(m_TranReq.szTranCode, MIS_VOID ) == 0 )
		m_DevIngPos.TranVoid( );
	else if ( stricmp(m_TranReq.szTranCode, MIS_REPRINT ) == 0 )
		m_DevIngPos.Reprint( );
	else if ( stricmp(m_TranReq.szTranCode, MIS_INQUIRY ) == 0 )
		m_DevIngPos.TranQuery();
	else if ( stricmp(m_TranReq.szTranCode, MIS_REFUND ) == 0 )
		m_DevIngPos.TranRefund( );	
	else if ( stricmp(m_TranReq.szTranCode, MIS_PREAUTH ) == 0 )
		m_DevIngPos.TranAuthor();
	else if ( stricmp(m_TranReq.szTranCode, MIS_VOIDAUTH ) == 0 )
		m_DevIngPos.TranAuthorVoid();
	else if ( stricmp(m_TranReq.szTranCode, MIS_CONFIRM ) == 0 )
		m_DevIngPos.TranAuthorConfirm();
	else if ( stricmp(m_TranReq.szTranCode, MIS_FQSALE ) == 0 ) //���ڸ���
		m_DevIngPos.TranFenqiPurchase(  );	
	else if ( stricmp(m_TranReq.szTranCode, MIS_FQREFUND ) == 0 ) //�����˻�
		m_DevIngPos.TranFenqiRefund( );	
	else if ( stricmp(m_TranReq.szTranCode, MIS_STATICS ) == 0) //ͳ��
	{
		m_DevIngPos.Totle();
	}
	else if ( stricmp(m_TranReq.szTranCode, MIS_DOWNPARAM)==0) //��������
	{
		m_DevIngPos.DownParam();
		m_DevIngPos.m_bLogin = TRUE;
	}
	else if ( stricmp(m_TranReq.szTranCode, MIS_LOGIN )==0) //ǩ��
	{
		m_DevIngPos.UserLogin();
		m_DevIngPos.m_bLogin = TRUE;
	}
	else if (stricmp(m_TranReq.szTranCode, MIS_QURYLIST ) == 0) //����ˮ
	{
		m_DevIngPos.ilistsum = 0;
		memset(&liststru,0,sizeof(liststru));
		m_DevIngPos.QueryList();	
	}
	else if (stricmp(m_TranReq.szTranCode, MIS_SETTLE ) == 0 ) //����
	{
		m_DevIngPos.Settle();	
	}
	return 9;
}


BOOL CDevMisPos::Send8583Package(char *pPkg, int iPkgLen)
{	
	m_SocketManager.StopComm();
	m_gentool.WriteLog(LOG_LEVEL3,"׼������8583����������ǰ��");
	

	//Sleep(10);
	m_SocketManager.CloseComm();

	m_SocketManager.SetMessageWindow( &m_ctlStaticInfo );
	m_SocketManager.SetServerState( FALSE );
	m_SocketManager.SetSmartAddressing( FALSE );

//	m_gentool.WriteLog(LOG_LEVEL2,"�˿ڼ���Ƿ��");
	
	if ( !m_SocketManager.IsHostOpen(m_DevIngPos.sDesHost)&& FALSE == ConnectServer(m_DevIngPos.sDesHost) )
	{
		
		m_gentool.WriteLog(LOG_LEVEL2,"����ǰ�û�ʧ��");
		m_DevIngPos.m_bKeyIgnore = TRUE;
		m_DevIngPos.m_dwStart = GetTickCount()+ POSCMDOUT;
		Sleep(30); //�ȴ��ڽ��̽���ȴ�״̬
		SetEvent(m_DevIngPos.m_hRecvDataEvent);
		return FALSE;
	}
 

	char cSendBuf[1024*4]={0};
	
	WORD wLen = iPkgLen;
	
	char cDataLen[5]={0};
	char cDataLenHex[5]={0};

	
	if (memcmp(cSocketMode,"ASC",3)==0) //ASC
	{
		sprintf(cDataLen,"%04d",wLen);
		m_SocketManager.WriteComm( (LPBYTE)cDataLen, 4*sizeof(char), INFINITE);
		//memcpy(cSendBuf,pPkg,wLen);
		m_gentool.FunHex2Bin(pPkg,cSendBuf,wLen);
	}
	else if (memcmp(cSocketMode,"HEX",3)==0)//HEX
	{
		cSendBuf[0] = HIBYTE(wLen);
		cSendBuf[1] = LOBYTE(wLen);
		m_gentool.FunHex2Bin(pPkg,cSendBuf+2,wLen);
 #ifdef TEST_VER
 		m_gentool.ShowBin2HexStr("���ͷ���", cSendBuf,wLen+2);
 #endif
		m_gentool.WriteLog( LOG_LEVEL2,"����ǰ�����ݸ�ʽ[%02X][%02X]",cSendBuf[0], cSendBuf[1]);
		wLen=wLen+2;
	}
	if ( m_SocketManager.WriteComm( (LPBYTE)cSendBuf, wLen, INFINITE) == wLen )
	{
		
		m_gentool.WriteLog( LOG_LEVEL3,"����������[%d]�ֽڳɹ�",wLen+2);
		m_DevIngPos.m_bKeyIgnore = TRUE;
		m_DevIngPos.m_dwStart = GetTickCount()+ POSCMDOUT;
		Sleep(30); //�ȴ��ڽ��̽���ȴ�״̬
		SetEvent(m_DevIngPos.m_hRecvDataEvent);
		
		return TRUE;
	}
	
	m_gentool.WriteLog( LOG_LEVEL1,"������������[%d]�ֽ�ʧ��",wLen+2);
	m_DevIngPos.m_bKeyIgnore = TRUE;
	m_DevIngPos.m_dwStart = GetTickCount()+ POSCMDOUT;
	Sleep(30); //�ȴ��ڽ��̽���ȴ�״̬
	SetEvent(m_DevIngPos.m_hRecvDataEvent);
	
	return FALSE;
	
}


BOOL CDevMisPos::ConnectServer(char *sDesHost)
{

	char cSerIp[50]={0};
	
	//��÷�������ַ
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
	
	char c_strPortTime[200]={0};
	if ( strncmp(sDesHost, "01", 2 ) == 0 ) //IST
	{
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	}
	else if( strncmp(sDesHost, "02", 2 ) == 0) //DCC
	{
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "DCC", c_strPortTime );
	}
	else if( strncmp(sDesHost, "03", 2 ) == 0) //TAS
	{
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "TAS", c_strPortTime );
	}
	else if( strlen(sDesHost) > 0) //TAS
	{
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST",sDesHost, c_strPortTime );
	}
	
	else //δָ�����ӵ�����
	{
		m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );	
	}
	char strPort[20]={0};
	char strTime[20]={0};
	char sTrMode[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	m_gentool.GetFirstString(c_strPortTime,strTime,'!');
	m_gentool.GetFirstString(c_strPortTime,sTrMode,'!');
	
	char cTempBuf[10]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "NETMODE", cTempBuf );

	if(memcmp(cTempBuf,"ASC",3)==0)
		sprintf(cSocketMode,"ASC");
	else
		sprintf(cSocketMode,"HEX");

	if (memcmp(cSocketMode,"ASC",3)==0)//ASC
	{
		m_gentool.WriteLog( LOG_LEVEL2,"����ǰ��ģʽ[ASC]");	
	}
	else if (memcmp(cSocketMode,"HEX",3)==0)//HEX
	{
		m_gentool.WriteLog( LOG_LEVEL2,"����ǰ��ģʽ[HEX]");				
	}

	
	m_gentool.WriteLog( LOG_LEVEL3,"[����ͨ��]����Ŀ�������%s�˿�%s��ʱʱ��%s", cSerIp, strPort, strTime );
	
	BOOL bSuccess;
	//�����TCP����
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	m_SocketManager.SetOutTime( atoi(strTime));

	sprintf(m_SocketManager.cSocketMode,cSocketMode);
	//�����߳�
	if (bSuccess && m_SocketManager.WatchComm() )
	{
		//�����TCPЭ��
		m_gentool.WriteLog( LOG_LEVEL3,"[����ͨ��]%s", "��������ѽӽ��� ");
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "���ӷ�����ʧ��!");
		return FALSE;
	}
}


BOOL CDevMisPos::CheckNetSataes()
{
	char cSerIp[50]={0};
	
	//��÷�������ַ
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
	if(strlen(cSerIp)<7)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "Ĭ�Ϸ����IP�����쳣[%s]!",cSerIp);
		return FALSE;
	}
	char c_strPortTime[200]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	
	char strPort[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	
	
	BOOL bSuccess=FALSE;
	//�����TCP����
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	
	//�����߳�
	if (bSuccess )
	{
		m_SocketManager.CloseComm();
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "���ӷ�����[%s,%s]ʧ��!",cSerIp, strPort);
		return FALSE;
	}
}

BOOL CDevMisPos::CheckNetSataes_DevA()
{
	char cDefIP[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cDefIP);

	
	
	//��÷�������ַ
	char cSerIp[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "DEVIPA", cSerIp);
	if(strlen(cSerIp)<7)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "������A IP�����쳣[%s]!",cSerIp);
		return FALSE;
	}


	if(memcmp(cDefIP,cSerIp,strlen(cSerIp))==0)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "������A���ú�Ĭ��IP������ͬ[%s],����ʧ��!",cSerIp);
		return FALSE;
	}

	
	char c_strPortTime[200]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	
	char strPort[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	
	
	BOOL bSuccess=FALSE;
	//�����TCP����
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	
	//�����߳�
	if (bSuccess )
	{
		m_gentool.CFG_Set_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
		m_SocketManager.CloseComm();
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "���ӷ�����[%s,%s]ʧ��!",cSerIp, strPort);
		return FALSE;
	}
}

BOOL CDevMisPos::CheckNetSataes_DevB()
{
	char cDefIP[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cDefIP);

	//��÷�������ַ
	char cSerIp[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "DEVIPB", cSerIp);
	if(strlen(cSerIp)<7)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "������B IP�����쳣[%s]!",cSerIp);
		return FALSE;
	}
	
	
	if(memcmp(cDefIP,cSerIp,strlen(cSerIp))==0)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "������B���ú�Ĭ��IP������ͬ[%s],����ʧ��!",cSerIp);
		return FALSE;
	}
	
	char c_strPortTime[200]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	
	char strPort[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	
	
	BOOL bSuccess=FALSE;
	//�����TCP����
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	
	//�����߳�
	if (bSuccess )
	{
			m_gentool.CFG_Set_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
		m_SocketManager.CloseComm();
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[����ͨ��]%s", "���ӷ�����[%s,%s]ʧ��!",cSerIp, strPort);
		return FALSE;
	}
}

BOOL CDevMisPos::CheckPinPadStates()
{
	char cKeyVal[10]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "DEVICE", "PINPAD", cKeyVal );
	
	int iPort=1;
	if ( strlen(cKeyVal) > 0 )
		iPort = atoi(cKeyVal);
	
	if ( FALSE==m_DevIngPos.CheckPinPort( iPort ) )
	{	
		
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

int CDevMisPos::SaveTranList()
{
	return m_DevIngPos.SaveTranList();
}
