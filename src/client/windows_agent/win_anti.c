#include <stdbool.h>
#include "agent_session.h"

extern void _stdcall alter_pe_sections(void);

bool protect_process(session* sess) {
	alter_pe_sections();
	return true;
}