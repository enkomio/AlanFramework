comment !
This stub is used to compile on both ml and ml64.
!
ifdef rax
	; compile as 64 bit code
	END_PROGRAM textequ <END>
	.code
	include x64\alter_pe_sections.inc

else
	; compile as 32 bit code
	END_PROGRAM textequ <END>
	.model flat,stdcall

	.code 
	include x86\alter_pe_sections.inc
endif

END_PROGRAM