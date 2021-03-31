@echo off

if exist config.txt (
  echo Load saved user info
  < config.txt (
    set /p id=
    set /p pwd=
  )
) else (
  set /p id="Login name: "
  set /p pwd="Password: "
)
(
  echo %id%
  echo %pwd%
) > config.txt

@color 0a

:loop
echo | set /p ="%pwd%" > tmp
type tmp | python cli.py auth4 login -u %id% -n
del tmp
timeout 300
goto loop

echo stopped
