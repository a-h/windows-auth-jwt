.\.nuget\nuget.exe restore -PackagesDirectory .\packages
"C:\program Files (x86)\msBuild\14.0\Bin\msbuild.exe" .\SignedJWTCreator\SignedJwtCreator.csproj /t:Build
copy .\SignedJWTCreator\bin\*.dll .\WindowsAuthJwt\bin\
