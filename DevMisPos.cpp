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
			m_gentool.WriteLog( LOG_LEVEL1,"接受服务器报文返回超时");
			m_SocketManager.StopComm();
		}
	}
	return 1L;
}
/**************************************************************
*　名称: OnAnalysePacket                                     *
*　类型: LRESULT                                             *
*　功能: 对服务器返回的信息进行格式化反给控制程序            *
*　入参: wParam    字符串缓冲地址             　             *
*        lParam    CSocketManager 指针         　            *
*　出参: 无                                                  *
*　返回: 1                                                   *
**************************************************************/
LRESULT CDevMisPos::OnAnalysePacket( WPARAM wParam, LPARAM lParam )
{
	// 网络返回信息报文
	char* pRecive = NULL;
	pRecive = (char*)wParam;
	
	int iRevecive = m_SocketManager.GetReveciveLen();
 
 #ifdef TEST_VER
 	m_gentool.ShowBin2HexStr("服务返回数据",pRecive, iRevecive);
 #endif
	
	
	m_DevIngPos.m_bKeyIgnore = FALSE;
	m_gentool.WriteLog( LOG_LEVEL2,"服务器返回[%d]字节",iRevecive);

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
			m_SocketManager.StopComm();//接收数据超时
			Sleep(20);
			m_DevIngPos.CommClose();
			sprintf(m_TranResp.cRetCode,"%s","99");
			sprintf(m_TranResp.cRetMsg,"%s","密码键盘接收数据超时");
			m_gentool.WriteLog(LOG_LEVEL1,"密码键盘接收数据超时");			
			EndDialog(1);
		}
		break;
	case PINPAD_ACQ_SND:
		break;
	case PINPAD_REVEIVE_SUC:
		{
			m_DevIngPos.FreeTlvPkgArray();
			m_DevIngPos.FreeTlvSubPkgArray();
			m_gentool.WriteLog(LOG_LEVEL3,"解析串口数据");
			iRet = m_DevIngPos.TlvUnPackRet( m_bContinue);
			m_gentool.WriteLog(LOG_LEVEL2,"解析串口数据完成[%d]",iRet);
			if( iRet == -1 )
			{
				m_DevIngPos.CommClose();
				m_SocketManager.StopComm();
				if(strlen(m_TranResp.cRetCode)==0)
				{
					sprintf(m_TranResp.cRetCode,"%s","99");
					sprintf(m_TranResp.cRetMsg,"%s","密码键盘返回数据解包错误");
					m_gentool.WriteLog(LOG_LEVEL1,"密码键盘返回数据解包错误");
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
				m_gentool.WriteLog(LOG_LEVEL1,"信息包，继续等待交易结果");
				return TRUE;	
			}

			if(m_DevIngPos.m_bPackEnd==TRUE) //还有后续包要处理
			{
				if(m_DevIngPos.m_bQueryList)
				{
					m_DevIngPos.QueryList();
				}
				break; //什么也不用做
			}

			CmdTlv * p8538CmdTlv = NULL;
			if ( !m_bContinue ) //交易结果返回包
			{
				m_gentool.WriteLog( LOG_LEVEL2,"判断8583交易过程!");
				if( m_DevIngPos.Get8583Package(p8538CmdTlv) )
				{
					if(!Send8583Package(p8538CmdTlv->pPkg, p8538CmdTlv->tagLen))
					{
						m_DevIngPos.CommClose();						
						m_SocketManager.StopComm();	
						sprintf(m_TranResp.cRetCode,"%s","99");
						sprintf(m_TranResp.cRetMsg,"%s","连接前置机失败或发送数据失败");
						m_gentool.WriteLog(LOG_LEVEL1,"连接前置机失败或发送数据失败");
					
						EndDialog(1);
					}
					else
					{
						m_gentool.WriteLog( LOG_LEVEL3,"发送8583到前置成功!");
					}
				}
				else
				{
					m_DevIngPos.UnPackTranResult();
					m_gentool.WriteLog( LOG_LEVEL2,"准备结束交易!");

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
						m_gentool.WriteLog(LOG_LEVEL1,"交易结束0[%s][%s]",m_TranResp.cRetCode,m_TranResp.cRetMsg);
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
							m_gentool.WriteLog(LOG_LEVEL1,"交易结束[%s][%s]",m_TranResp.cRetCode,m_TranResp.cRetMsg);
							EndDialog(0);
							break;
						}
	
						{
							m_DevIngPos.GetTranResultInfo(&m_TranResp);
							m_bLogin = FALSE;
							m_SocketManager.StopComm();
							
							m_DevIngPos.CommClose();
							//Sleep(10);
							m_gentool.WriteLog(LOG_LEVEL1,"签到完成[%s][%s]",m_TranResp.cRetCode,m_TranResp.cRetMsg);
							EndDialog(0);
							break;
						}
						//开始后续交易
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
		if (pMsg->wParam==VK_RETURN)//使用回车按键
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
    WINDOWPLACEMENT  wp; //显示隐藏
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
			m_gentool.WriteLog(LOG_LEVEL2,"启动StartTran交易线程操作");
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
	m_gentool.WriteLog( LOG_LEVEL3, "进入startmis交易");

	m_DevIngPos.SetTradeInfo(&m_TranReq);

	
	char cKeyVal[100]={0};
	int	iPort;

	
	m_gentool.WriteLog( LOG_LEVEL3, "读取密码键盘配置");
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
		m_gentool.WriteLog(LOG_LEVEL1,"打开串口失败");
		sprintf(m_TranResp.cRetCode,"%s","99");
		sprintf(m_TranResp.cRetMsg,"%s","打开串口失败");
		return -1;
	}
	
	m_SocketManager.SetMessageWindow( &m_ctlStaticInfo );
	m_SocketManager.SetServerState( FALSE );
	m_SocketManager.SetSmartAddressing( FALSE );


	
	m_gentool.WriteLog( LOG_LEVEL3, "开始交易，交易类型=【%s】",m_TranReq.szTranCode);

	m_gentool.WriteLog( LOG_LEVEL3, "支付类型=【%s】",m_TranReq.szPayCh);

	
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
	else if ( stricmp(m_TranReq.szTranCode, MIS_FQSALE ) == 0 ) //分期付款
		m_DevIngPos.TranFenqiPurchase(  );	
	else if ( stricmp(m_TranReq.szTranCode, MIS_FQREFUND ) == 0 ) //分期退货
		m_DevIngPos.TranFenqiRefund( );	
	else if ( stricmp(m_TranReq.szTranCode, MIS_STATICS ) == 0) //统计
	{
		m_DevIngPos.Totle();
	}
	else if ( stricmp(m_TranReq.szTranCode, MIS_DOWNPARAM)==0) //参数下载
	{
		m_DevIngPos.DownParam();
		m_DevIngPos.m_bLogin = TRUE;
	}
	else if ( stricmp(m_TranReq.szTranCode, MIS_LOGIN )==0) //签到
	{
		m_DevIngPos.UserLogin();
		m_DevIngPos.m_bLogin = TRUE;
	}
	else if (stricmp(m_TranReq.szTranCode, MIS_QURYLIST ) == 0) //查流水
	{
		m_DevIngPos.ilistsum = 0;
		memset(&liststru,0,sizeof(liststru));
		m_DevIngPos.QueryList();	
	}
	else if (stricmp(m_TranReq.szTranCode, MIS_SETTLE ) == 0 ) //结算
	{
		m_DevIngPos.Settle();	
	}
	return 9;
}


BOOL CDevMisPos::Send8583Package(char *pPkg, int iPkgLen)
{	
	m_SocketManager.StopComm();
	m_gentool.WriteLog(LOG_LEVEL3,"准备发送8583数据至银行前置");
	

	//Sleep(10);
	m_SocketManager.CloseComm();

	m_SocketManager.SetMessageWindow( &m_ctlStaticInfo );
	m_SocketManager.SetServerState( FALSE );
	m_SocketManager.SetSmartAddressing( FALSE );

//	m_gentool.WriteLog(LOG_LEVEL2,"端口检测是否打开");
	
	if ( !m_SocketManager.IsHostOpen(m_DevIngPos.sDesHost)&& FALSE == ConnectServer(m_DevIngPos.sDesHost) )
	{
		
		m_gentool.WriteLog(LOG_LEVEL2,"连接前置机失败");
		m_DevIngPos.m_bKeyIgnore = TRUE;
		m_DevIngPos.m_dwStart = GetTickCount()+ POSCMDOUT;
		Sleep(30); //等串口进程进入等待状态
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
 		m_gentool.ShowBin2HexStr("上送发送", cSendBuf,wLen+2);
 #endif
		m_gentool.WriteLog( LOG_LEVEL2,"发送前置数据格式[%02X][%02X]",cSendBuf[0], cSendBuf[1]);
		wLen=wLen+2;
	}
	if ( m_SocketManager.WriteComm( (LPBYTE)cSendBuf, wLen, INFINITE) == wLen )
	{
		
		m_gentool.WriteLog( LOG_LEVEL3,"向主机发送[%d]字节成功",wLen+2);
		m_DevIngPos.m_bKeyIgnore = TRUE;
		m_DevIngPos.m_dwStart = GetTickCount()+ POSCMDOUT;
		Sleep(30); //等串口进程进入等待状态
		SetEvent(m_DevIngPos.m_hRecvDataEvent);
		
		return TRUE;
	}
	
	m_gentool.WriteLog( LOG_LEVEL1,"已向主机发送[%d]字节失败",wLen+2);
	m_DevIngPos.m_bKeyIgnore = TRUE;
	m_DevIngPos.m_dwStart = GetTickCount()+ POSCMDOUT;
	Sleep(30); //等串口进程进入等待状态
	SetEvent(m_DevIngPos.m_hRecvDataEvent);
	
	return FALSE;
	
}


BOOL CDevMisPos::ConnectServer(char *sDesHost)
{

	char cSerIp[50]={0};
	
	//获得服务器地址
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
	
	else //未指定连接的主机
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
		m_gentool.WriteLog( LOG_LEVEL2,"连接前置模式[ASC]");	
	}
	else if (memcmp(cSocketMode,"HEX",3)==0)//HEX
	{
		m_gentool.WriteLog( LOG_LEVEL2,"连接前置模式[HEX]");				
	}

	
	m_gentool.WriteLog( LOG_LEVEL3,"[网络通信]连接目标服务器%s端口%s超时时间%s", cSerIp, strPort, strTime );
	
	BOOL bSuccess;
	//如果是TCP连接
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	m_SocketManager.SetOutTime( atoi(strTime));

	sprintf(m_SocketManager.cSocketMode,cSocketMode);
	//建立线程
	if (bSuccess && m_SocketManager.WatchComm() )
	{
		//如果是TCP协议
		m_gentool.WriteLog( LOG_LEVEL3,"[网络通信]%s", "与服务器已接建立 ");
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "连接服务器失败!");
		return FALSE;
	}
}


BOOL CDevMisPos::CheckNetSataes()
{
	char cSerIp[50]={0};
	
	//获得服务器地址
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
	if(strlen(cSerIp)<7)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "默认服务端IP配置异常[%s]!",cSerIp);
		return FALSE;
	}
	char c_strPortTime[200]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	
	char strPort[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	
	
	BOOL bSuccess=FALSE;
	//如果是TCP连接
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	
	//建立线程
	if (bSuccess )
	{
		m_SocketManager.CloseComm();
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "连接服务器[%s,%s]失败!",cSerIp, strPort);
		return FALSE;
	}
}

BOOL CDevMisPos::CheckNetSataes_DevA()
{
	char cDefIP[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cDefIP);

	
	
	//获得服务器地址
	char cSerIp[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "DEVIPA", cSerIp);
	if(strlen(cSerIp)<7)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "服务器A IP配置异常[%s]!",cSerIp);
		return FALSE;
	}


	if(memcmp(cDefIP,cSerIp,strlen(cSerIp))==0)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "服务器A配置和默认IP配置相同[%s],连接失败!",cSerIp);
		return FALSE;
	}

	
	char c_strPortTime[200]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	
	char strPort[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	
	
	BOOL bSuccess=FALSE;
	//如果是TCP连接
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	
	//建立线程
	if (bSuccess )
	{
		m_gentool.CFG_Set_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
		m_SocketManager.CloseComm();
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "连接服务器[%s,%s]失败!",cSerIp, strPort);
		return FALSE;
	}
}

BOOL CDevMisPos::CheckNetSataes_DevB()
{
	char cDefIP[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IP", cDefIP);

	//获得服务器地址
	char cSerIp[50]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "DEVIPB", cSerIp);
	if(strlen(cSerIp)<7)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "服务器B IP配置异常[%s]!",cSerIp);
		return FALSE;
	}
	
	
	if(memcmp(cDefIP,cSerIp,strlen(cSerIp))==0)
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "服务器B配置和默认IP配置相同[%s],连接失败!",cSerIp);
		return FALSE;
	}
	
	char c_strPortTime[200]={0};
	m_gentool.CFG_Get_Key(CONFIG_FILE, "HOST", "IST", c_strPortTime );
	
	char strPort[20]={0};
	m_gentool.GetFirstString(c_strPortTime,strPort,'!');
	
	
	BOOL bSuccess=FALSE;
	//如果是TCP连接
	bSuccess = m_SocketManager.ConnectTo( cSerIp, strPort, AF_INET, SOCK_STREAM);
	
	//建立线程
	if (bSuccess )
	{
			m_gentool.CFG_Set_Key(CONFIG_FILE, "HOST", "IP", cSerIp);
		m_SocketManager.CloseComm();
		return TRUE;
	}
	else
	{
		m_gentool.WriteLog( LOG_LEVEL1,"[网络通信]%s", "连接服务器[%s,%s]失败!",cSerIp, strPort);
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
