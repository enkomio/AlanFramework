;
; Parameter Helper Header File
;
;   Toby Opferman  2017
;
;   Src: https://raw.githubusercontent.com/opferman/SixtyFourBits/master/public/inc/amd64/paramhelp_public.inc


LOCAL_PARAMETER_FRAME8 struct
    PeFile         dq ?
    Kernel32Base   dq ?
    ImageBase      dq ?
    MzFile         dq ?
    ResolvedDllHandle      dq ?
    ResolvedEdata          dq ?
    Edata          dq ?
    Param8         dq ?
LOCAL_PARAMETER_FRAME8 ends

LOCAL_PARAMETER_FRAME4 struct
    Param1         dq ?
    Param2         dq ?
    Param3         dq ?
    Param4         dq ?
LOCAL_PARAMETER_FRAME4 ends

FUNCTION_PARAMETERS_FRAME struct
    ReturnAddress  dq ?
    Param1         dq ?
    Param2         dq ?
    Param3         dq ?
    Param4         dq ?
    Param5         dq ?
    Param6         dq ?
    Param7         dq ?
    Param8         dq ?
FUNCTION_PARAMETERS_FRAME ends

SAVE_REGISTERS_FRAME struct
    SaveR12  dq ?
    SaveR13  dq ?
    SaveR14  dq ?
    SaveR15  dq ?
    SaveRdi  dq ?
    SaveRsi  dq ?
    SaveRbx  dq ?
    SaveRbp  dq ?
SAVE_REGISTERS_FRAME ends

SAVE_REGISTERS_FRAME_XMM struct
    SaveXmm6  oword ?
    SaveXmm7  oword ?
    SaveXmm8  oword ?
    SaveXmm9  oword ?
    SaveXmm10 oword ?
    SaveXmm11 oword ?
    SaveXmm12 oword ?
    SaveXmm13 oword ?
    SaveXmm14 oword ?
    SaveXmm15 oword ?
SAVE_REGISTERS_FRAME_XMM ends

LOCAL_VARIABLES8 struct
   LocalVar1 dq ?
   LocalVar2 dq ?
   LocalVar3 dq ?
   LocalVar4 dq ?
   LocalVar5 dq ?
   LocalVar6 dq ?
   LocalVar7 dq ?
   LocalVar8 dq ?
LOCAL_VARIABLES8 ends

STD_FUNCTION_STACK_LV struct
    Parameters  LOCAL_PARAMETER_FRAME8    <?>
    LocalVariables LOCAL_VARIABLES8       <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    SaveXmmRegs SAVE_REGISTERS_FRAME_XMM  <?>
    Padding     dq                         ?
STD_FUNCTION_STACK_LV ends

STD_FUNCTION_STACK_LV_PARAMS struct
    Parameters  LOCAL_PARAMETER_FRAME8    <?>
    LocalVariables LOCAL_VARIABLES8       <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    SaveXmmRegs SAVE_REGISTERS_FRAME_XMM  <?>
    Padding     dq                         ?
    FuncParams  FUNCTION_PARAMETERS_FRAME <?>
STD_FUNCTION_STACK_LV_PARAMS ends

STD_FUNCTION_STACK struct
    Parameters  LOCAL_PARAMETER_FRAME8    <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    SaveXmmRegs SAVE_REGISTERS_FRAME_XMM  <?>
    Padding     dq                         ?
STD_FUNCTION_STACK ends

STD_FUNCTION_STACK_PARAMS struct
    Parameters  LOCAL_PARAMETER_FRAME8    <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    SaveXmmRegs SAVE_REGISTERS_FRAME_XMM  <?>
    Padding     dq                         ?
    FuncParams  FUNCTION_PARAMETERS_FRAME <?>
STD_FUNCTION_STACK_PARAMS ends

STD_FUNCTION_STACK_MIN struct
    Parameters  LOCAL_PARAMETER_FRAME8    <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    Padding     dq                         ?
STD_FUNCTION_STACK_MIN ends

STD_FUNCTION_STACK_MIN_PARAMS struct
    Parameters  LOCAL_PARAMETER_FRAME8    <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    Padding     dq                         ?
    FuncParams  FUNCTION_PARAMETERS_FRAME <?>
STD_FUNCTION_STACK_MIN_PARAMS ends

STD_FUNCTION_STACK_MICRO struct
    Parameters  LOCAL_PARAMETER_FRAME4    <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    Padding     dq                         ?
STD_FUNCTION_STACK_MICRO ends

STD_FUNCTION_STACK_MICRO_PARAMS struct
    Parameters  LOCAL_PARAMETER_FRAME4    <?>
    SaveRegs    SAVE_REGISTERS_FRAME      <?>
    Padding     dq                         ?
    FuncParams  FUNCTION_PARAMETERS_FRAME <?>
STD_FUNCTION_STACK_MICRO_PARAMS ends

SAVE_ALL_STD_REGS MACRO Structure
 save_reg r12, Structure.SaveRegs.SaveR12
 save_reg r13, Structure.SaveRegs.SaveR13
 save_reg r14, Structure.SaveRegs.SaveR14
 save_reg r15, Structure.SaveRegs.SaveR15
 save_reg rdi, Structure.SaveRegs.SaveRdi
 save_reg rsi, Structure.SaveRegs.SaveRsi
 save_reg rbx, Structure.SaveRegs.SaveRbx
 save_reg rbp, Structure.SaveRegs.SaveRbp
ENDM

RESTORE_ALL_STD_REGS MACRO Structure
 MOV r12, Structure.SaveRegs.SaveR12[RSP]
 MOV r13, Structure.SaveRegs.SaveR13[RSP]
 MOV r14, Structure.SaveRegs.SaveR14[RSP]
 MOV r15, Structure.SaveRegs.SaveR15[RSP]
 MOV rdi, Structure.SaveRegs.SaveRdi[RSP]
 MOV rsi, Structure.SaveRegs.SaveRsi[RSP]
 MOV rbx, Structure.SaveRegs.SaveRbx[RSP]
 MOV rbp, Structure.SaveRegs.SaveRbp[RSP]
ENDM

SAVE_ALL_XMM_REGS MACRO Structure
 MOVAPS  Structure.SaveXmmRegs.SaveXmm6[RSP], xmm6  
 MOVAPS  Structure.SaveXmmRegs.SaveXmm7[RSP], xmm7  
 MOVAPS  Structure.SaveXmmRegs.SaveXmm8[RSP], xmm8  
 MOVAPS  Structure.SaveXmmRegs.SaveXmm9[RSP], xmm9  
 MOVAPS  Structure.SaveXmmRegs.SaveXmm10[RSP], xmm10 
 MOVAPS  Structure.SaveXmmRegs.SaveXmm11[RSP], xmm11 
 MOVAPS  Structure.SaveXmmRegs.SaveXmm12[RSP], xmm12 
 MOVAPS  Structure.SaveXmmRegs.SaveXmm13[RSP], xmm13 
 MOVAPS  Structure.SaveXmmRegs.SaveXmm14[RSP], xmm14 
 MOVAPS  Structure.SaveXmmRegs.SaveXmm15[RSP], xmm15 
ENDM

RESTORE_ALL_XMM_REGS MACRO Structure
 MOVAPS  xmm6, Structure.SaveXmmRegs.SaveXmm6[RSP]
 MOVAPS  xmm7, Structure.SaveXmmRegs.SaveXmm7[RSP]
 MOVAPS  xmm8, Structure.SaveXmmRegs.SaveXmm8[RSP]
 MOVAPS  xmm9, Structure.SaveXmmRegs.SaveXmm9[RSP]
 MOVAPS  xmm10, Structure.SaveXmmRegs.SaveXmm10[RSP]
 MOVAPS  xmm11, Structure.SaveXmmRegs.SaveXmm11[RSP]
 MOVAPS  xmm12, Structure.SaveXmmRegs.SaveXmm12[RSP]
 MOVAPS  xmm13, Structure.SaveXmmRegs.SaveXmm13[RSP]
 MOVAPS  xmm14, Structure.SaveXmmRegs.SaveXmm14[RSP]
 MOVAPS  xmm15, Structure.SaveXmmRegs.SaveXmm15[RSP]
ENDM
