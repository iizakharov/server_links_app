; AMneZinu: removing the app also removes its VPN service (asks for administrator rights, UAC).
; Not on updates: the new version keeps the installed service (the app offers to update it).
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    nsExec::ExecToStack 'sc.exe query AmnezinuVPN'
    Pop $0
    Pop $1
    ${If} $0 = 0
      ExecShellWait "runas" "$INSTDIR\amz-helper.exe" "uninstall" SW_HIDE
    ${EndIf}
  ${EndIf}
!macroend
