.PHONY : build build-osx build-linux clean format

clean:
	rm -rf app

build-osx:
	dotnet publish NetCrypsi.App/NetCrypsi.App.csproj -c Release -r osx-x64 --self-contained true -o ./app/

build-linux:
	dotnet publish NetCrypsi.App/NetCrypsi.App.csproj -c Release -r linux-x64 --self-contained true -o ./app/

build:
	dotnet publish NetCrypsi.App/NetCrypsi.App.csproj -c Release -o app --no-restore

format:
	dotnet format ./NetCrypsi.sln