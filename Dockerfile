FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY PubMessagesApp.sln ./
COPY ./ ./PubMessagesApp

WORKDIR /src/PubMessagesApp
RUN dotnet restore

RUN dotnet build -c Release -o /app/build

RUN dotnet publish -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish .

ENV DATABASE_PASSWORD=Very0#ArrrdT0gue$sPAS$worD531

ENTRYPOINT ["dotnet", "PubMessagesApp.dll"]
EXPOSE 433
