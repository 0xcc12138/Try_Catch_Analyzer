#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>  // �ṩ get_xxx ����
#include <windows.h>
#include <bytes.hpp>  // for get_many_bytes
#include "resource.h"
#include <allins.hpp>
#include <ua.hpp>
#include <name.hpp>

//�����ǵ����SDKͷ�ļ�
#include <stack>






int selection = 0;

unsigned int Try_Catch_Func_Start_Addr = 0;
unsigned int Try_Catch_Func_End_Addr = 0;
unsigned int CxxThrowException_Addr = 0;

//extern "C" __declspec(dllexport) void ShowMyDialog(HWND hWndParent) {
//	DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hWndParent, MyDialogProc);
//}

// Declare the dialog procedure
INT_PTR CALLBACK MyDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg) {
	case WM_INITDIALOG:
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_BUTTON1) {
			

			//��ȡ�༭������ݣ�
			// ��ȡ�༭��ľ��
			HWND hEdit = GetDlgItem(hwndDlg, IDC_EDIT1);

			// ׼��һ�����������ڴ洢�ı�����
			char buffer[256];

			// ��ȡ�༭���е��ı�
			GetWindowText(hEdit, buffer, sizeof(buffer));


			sscanf(buffer, "%x", &Try_Catch_Func_Start_Addr);

			
			hEdit = GetDlgItem(hwndDlg, IDC_EDIT2);

			char buffer2[256];

			// ��ȡ�༭���е��ı�
			GetWindowText(hEdit, buffer2, sizeof(buffer2));


			sscanf(buffer2, "%x", &CxxThrowException_Addr);




			hEdit = GetDlgItem(hwndDlg, IDC_EDIT3);

			char buffer3[256];
			// ��ȡ�༭���е��ı�
			GetWindowText(hEdit, buffer3, sizeof(buffer3));


			sscanf(buffer3, "%x", &Try_Catch_Func_End_Addr);


			EndDialog(hwndDlg, 0);
		}
		else if(LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hwndDlg, 0);
		}
	
		break;

	case WM_CLOSE:
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	return FALSE;
}



struct FuncInfo
{
	unsigned int magicNumber;//���������ɵĹ̶�����
	unsigned int maxState;//���ջչ�������±�ֵ��Ҳ����trylevel����ܳ���maxState,ͬʱҲ��ջչ�����Ĵ���
	unsigned int pUnwindMap; //ָ��ջչ���������ָ�룬ָ��UnwindMapEntry��ṹ
	unsigned int dwTryCount; //һ�����������Try�������
	unsigned int pTryBlockMap; //Try����б�ָ��TryBlockMapEntry��Ľṹ
};

struct TryBlockMapEntry
{
	unsigned int tryLow;	//try�����С״̬���������ڷ�Χ��飨trylevel����С������
	unsigned int tryHigh;  //try������״̬���������ڷ�Χ��飨trylevel�����������
	unsigned int catchHigh; //catch������״̬���������ڷ�Χ��飨trylevel�����ޣ�
	unsigned int dwCatchCount;	//catch��ĸ���
	unsigned int pCatchHandlerArray; //catch���������ָ��_msRttiDscr��ṹ
};


struct _msRttiDscr
{
	unsigned int nFlag;	//����Catch���ƥ����
	unsigned int pType;	//catch��Ҫ��׽�����ͣ�ָ��TypeDescriptor��ṹ��������㣬�ʹ����������ͣ���catch all
	unsigned int dispCatchObjOffset;  //���ڶ�λ�쳣�����ڵ�ǰESP�е�ƫ��λ��
	unsigned int CatchProc;	//catch����׵�ַ������������λcatch
};


struct TypeDescriptor
{
	unsigned int Hash;	//�������Ƶ�Hash��ֵ
	unsigned int spare;//����
	unsigned int name;	//��������
};



struct ThrowInfo
{
	unsigned int nFlag;  //�׳��쳣���ͱ��
	unsigned int pDestructor;	//�쳣���������������ַ
	unsigned int pForwardCompat;//δ֪
	unsigned int pCatchTableTypeArray; //catch�����ͱ�ָ��CatchTableTyoeArray��ṹ
};




struct CatchTableTyoeArray
{
	unsigned int dwCount;	//CatchTableType ���������Ԫ�ظ���
	unsigned int ppCatchTableType;	//catch���������Ϣ������ΪCatchTableType**
};


struct CatchTableType
{
	unsigned int flag;
	unsigned int pTypeInfo;//ָ���쳣���͵Ľṹ,ָ��TypeDescriptor��ṹ
	unsigned int thisDisplacement; //������Ϣ
	unsigned int sizeorOffset; //��Ĵ�С
	unsigned int pCopyFunction; //���ƹ��캯����ָ��
};




plugmod_t* idaapi init(void)
{
	//IDA��������ʱ������ÿ�������init������
	//����ֵ������ѡ��:
	//PLUGIN_SKIP�ʺ���Щ��֧�ֵĲ����IDA��������ظò��
	//PLUGIN_OK�ʺ���Щִ��һ���Թ��ܵĲ��
	//PLUGIN_KEEP�ʺ���Щ��Ҫһֱ���ֹ��ܵĲ��


	return PLUGIN_OK;
}

void idaapi term(void)
{
	//���������ʱ��һ���������ڴ����һ����������Ĵ��롣
	return;
}

void find_mov_ebp_var4(ea_t start, ea_t end) {
	ea_t current_addr = start;

	unsigned int Try_Start_Addr = 0;
	unsigned int Try_End_Addr = 0;
	unsigned int Try_Level = 6666;
	std::stack<unsigned int> myStack;
	// ����ָ��
	while (current_addr < end) {
		insn_t insn;
		decode_insn(&insn, current_addr);
		
		int reg = insn.ops[0].reg;
		// �ж��Ƿ�Ϊmovָ��
		if (insn.itype == NN_mov) {
			// ���������Ƿ����ģʽ [ebp+var_4]
			if (insn.ops[0].type == o_displ &&
				insn.ops[0].reg == 5 &&
				insn.ops[0].addr == -4) {

				//msg("Found mov [ebp+var_4] at %a\n", current_addr);
				Try_Start_Addr = current_addr;
				if (insn.ops[1].type == o_imm) {
					//��ȡTry Level
					Try_Level = insn.ops[1].value;

					
					myStack.push(Try_Start_Addr);
					myStack.push(Try_Level);
				}
			}
		}

		if (insn.itype == NN_call)
		{
			if (insn.ops[0].type == o_near && insn.ops[0].addr == CxxThrowException_Addr) {  // ���Ŀ���ַ�Ƿ�Ϊ CxxThrowException
				//msg("Found call to CxxThrowException at %a\n", current_addr);
				Try_End_Addr = current_addr;
				char str[50];

				unsigned int try_level = myStack.top();
				myStack.pop();

				unsigned int try_start_addr= myStack.top();
				myStack.pop();

				sprintf(str, " Try Start,Try Level: %d", Try_Level);
				set_cmt(Try_Start_Addr, str, false);
				set_item_color(Try_Start_Addr, 0x90EE90);



				sprintf(str, " Try End,Try Level: %d", Try_Level);
				set_cmt(Try_End_Addr, str, false);
				set_item_color(Try_End_Addr, 0x90EE90);
			}
		}

		// ��ȡ��һ��ָ���ַ
		current_addr = next_head(current_addr, end);
	}
}


void Analyze_TypeInfo(unsigned int Markers, TypeDescriptor* _TypeDescriptor)  //Markers��Ҫ��ע�͵ĵ�ַ
{
	TypeDescriptor* m_TypeDescriptor = _TypeDescriptor;

	/*qstring m_typename;
	get_strlit_contents(&m_typename, (ea_t)&m_TypeDescriptor->name, 0, STRTYPE_C);*/
	char m_typename[100];
	int num = get_bytes(m_typename, 20, (ea_t)&m_TypeDescriptor->name);



	
		char* ptr = m_typename;
		if (!strcmp(m_typename, ".H"))
		{
			ptr = (char*)" Int ";
		}
		else if (!strcmp(m_typename, ".N"))
		{
			ptr = (char*)" Double ";
		}
		else if (!strcmp(m_typename, ".I"))
		{
			ptr = (char*)" Unsigned Int ";
		}
		else if (!strcmp(m_typename, ".M"))
		{
			ptr = (char*)" Float ";
		}
		else if (!strcmp(m_typename, ".F"))
		{
			ptr = (char*)" Short ";
		}
		else if (!strcmp(m_typename, ".D"))
		{
			ptr = (char*)" Unsigned Char ";
		}
		else if (!strcmp(m_typename, ".G"))
		{
			ptr = (char*)" Unsigned Short ";
		}
		else if (!strcmp(m_typename, ".E"))
		{
			ptr = (char*)" Unsigned Char ";
		}
		else
			ptr = (char*)" Catch All ";

		qstring comment;
		get_cmt(&comment, Markers, false);
		char last_char=0;
		if(comment.length()!=0)
			last_char = comment.at(comment.length() - 1);
		if (last_char != '#')
		{
			comment += ptr;

			comment += '#';
			bool success = set_cmt(Markers, comment.c_str(), false);
			set_item_color(Markers, 0xFFA07A);
			//msg("Comment added to address 0x%a: %s\n", Markers, comment.c_str());
		}
	
	


}



bool Confirm_Capture_Type(unsigned int Addr)
{
	xrefblk_t xb;
	int count = 0;
	unsigned int quote_Func_Addr[0x20];
	for (bool ok = xb.first_to((ea_t)Addr, XREF_ALL); ok; ok = xb.next_to())
	{
		//msg("Code reference to function at: %a\n", xb.from);
		quote_Func_Addr[count++] = xb.from;
	}

	for (int j = 0; j < count; j++)
	{
		unsigned char* ptr = (unsigned char*)quote_Func_Addr[j];
		while (1)
		{
			if(get_byte((ea_t)ptr)==(unsigned char)'\x68')
			{
				break;
			}
			ptr--;
		}

		unsigned int Markers = (unsigned int)ptr;
		ptr++;
		sval_t input_value = get_dword((ea_t)ptr);
		ThrowInfo* m_throwinfo = (ThrowInfo*)(input_value);

		CatchTableTyoeArray* m_CatchTableTyoeArray = (CatchTableTyoeArray*)get_dword((ea_t)&m_throwinfo->pCatchTableTypeArray);
		int num = get_dword((ea_t)&m_CatchTableTyoeArray->dwCount);
		for (int i = 0; i < num; i++)
		{
			
			CatchTableType* m_CatchTableType = (CatchTableType*)(get_dword((ea_t)&m_CatchTableTyoeArray->ppCatchTableType) + sizeof(CatchTableType) * i);
			Analyze_TypeInfo(Markers, (TypeDescriptor*)(get_dword((ea_t)&m_CatchTableType->pTypeInfo)));
		}
	}


	
	
	return true;
}






bool Find_Try_Block(unsigned int Start_Addr,unsigned int End_Addr)
{
	
	unsigned char* ptr = (unsigned char*)Start_Addr;
	while (1)
	{
		if (get_byte((ea_t)ptr) == '\x68' && get_byte((ea_t)(ptr + 5)) == '\x64')
		{
			break;
		}
		ptr++;
		if(ptr==(unsigned char*)End_Addr)
		{
			return false;
		}

	}

	ptr++;
	unsigned int ehhandler = get_dword((ea_t)ptr);

	ptr = (unsigned char*)ehhandler;


	while (1)
	{
		if (get_byte((ea_t)ptr)== (unsigned char)'\xE9')
		{
			break;
		}
		ptr++;
		if (ptr == (unsigned char*)End_Addr)
		{
			return false;
		}
	}
	ptr = ptr - 4;

	

	sval_t input_value = get_dword((ea_t)ptr);

	
	FuncInfo* m_funcinfo = (FuncInfo*)(input_value);  //�õ�FuncInfo�ṹ��

	msg("There are 0x%x try blocks", get_dword((ea_t)&m_funcinfo->dwTryCount));

	TryBlockMapEntry* m_tryblockmapentry[0x20];
	int num = get_dword((ea_t)&m_funcinfo->dwTryCount);
	for (int i = 0; i < num; i++)
	{

		m_tryblockmapentry[i] = (TryBlockMapEntry*)(get_dword((ea_t)&m_funcinfo->pTryBlockMap) + sizeof(TryBlockMapEntry) * i);  //�õ�������TryBlockMapEntry�ṹ

		int num2 = get_dword((ea_t)&m_tryblockmapentry[i]->dwCatchCount);

		for (int j = 0; j < num2; j++)
		{
			_msRttiDscr* m_msRttiDscr = (_msRttiDscr*)(get_dword((ea_t)(&m_tryblockmapentry[i]->pCatchHandlerArray)) + sizeof(_msRttiDscr) * j);
			unsigned int CatchProc_Addr = get_dword((ea_t)&m_msRttiDscr->CatchProc);
			msg("Catch Block Address:0x%x  ", CatchProc_Addr);
			TypeDescriptor* m_TypeDescriptor = (TypeDescriptor*)(get_dword((ea_t)(&m_msRttiDscr->pType)));

			char m_typename[100];
			char* ptr = m_typename;
			if (m_TypeDescriptor != 0)
			{
				int num = get_bytes(m_typename, 20, (ea_t)&m_TypeDescriptor->name);



				
				if (!strcmp(m_typename, ".H"))
				{
					ptr = (char*)" Int ";
				}
				else if (!strcmp(m_typename, ".N"))
				{
					ptr = (char*)" Double ";
				}
				else if (!strcmp(m_typename, ".I"))
				{
					ptr = (char*)" Unsigned Int ";
				}
				else if (!strcmp(m_typename, ".M"))
				{
					ptr = (char*)" Float ";
				}
				else if (!strcmp(m_typename, ".F"))
				{
					ptr = (char*)" Short ";
				}
				else if (!strcmp(m_typename, ".D"))
				{
					ptr = (char*)" Unsigned Char ";
				}
				else if (!strcmp(m_typename, ".G"))
				{
					ptr = (char*)" Unsigned Short ";
				}
				else if (!strcmp(m_typename, ".E"))
				{
					ptr = (char*)" Unsigned Char ";
				}
				else
				{
					
				}
			}
			else
				ptr = (char*)" Catch All ";



				qstring comment;
				get_cmt(&comment, CatchProc_Addr, false);
				char last_char = 0;
				if(comment.length()!=0)
					last_char = comment.at(comment.length() - 1);
				if (last_char != '#')
				{
					comment += ptr;

					ptr = (char*)"  Try Level is";
					comment += ptr;

					char buffer[20];
					sprintf(buffer, "0x%x", get_dword((ea_t)&m_tryblockmapentry[i]->tryLow));

					comment += buffer;

					comment += '#';

					bool success = set_cmt(CatchProc_Addr, comment.c_str(), false);
					set_item_color(CatchProc_Addr, 0xFFDAB9);
					//msg("Comment added to address 0x%a: %s\n", CatchProc_Addr, comment.c_str());
				}

		}

	}
	return true;
}



bool idaapi run(size_t)
{
	HINSTANCE Temp = GetModuleHandle("IDA_Dll.dll");
	HWND hwndParent = GetActiveWindow();
	DialogBox(Temp, MAKEINTRESOURCE(IDD_DIALOG1), hwndParent, MyDialogProc);
	
	if (CxxThrowException_Addr != 0)  // �û�ѡ���� ThrowInfo
	{
		Confirm_Capture_Type(CxxThrowException_Addr);
		
	}
	if (Try_Catch_Func_Start_Addr != 0)  // �û�ѡ���� FuncInfo
	{
		Find_Try_Block(Try_Catch_Func_Start_Addr,Try_Catch_Func_End_Addr);
		find_mov_ebp_var4(Try_Catch_Func_Start_Addr, Try_Catch_Func_End_Addr);
	}
	

	
	return true;

	
}

static char comment[] = "It's a plugin to show Hello world!";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // �����һЩ����,һ��Ϊ0����
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // �����˵��,����ʾ��IDA�·���״̬����
  "",                   // multiline help about the plugin
  "Try_Catch_Analyzer",		// ������б�����ʾ������
  "Alt-F1"              // �����Ҫע��Ĺ��ܿ�ݼ�
};
