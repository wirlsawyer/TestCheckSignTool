#pragma once

class SignHelp
{
public:
	static SignHelp *Instance(void);
	~SignHelp(void);
	bool IsSigned(wchar_t* path);
private:
	SignHelp(void);
private:
	static SignHelp	*m_instance;
};
