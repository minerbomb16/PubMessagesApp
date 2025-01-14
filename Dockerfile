# Użycie obrazu bazowego .NET SDK
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Kopiowanie plików projektu
COPY PubMessagesApp.sln ./
COPY ./ ./PubMessagesApp

# Przywracanie zależności
WORKDIR /src/PubMessagesApp
RUN dotnet restore

# Budowanie aplikacji
RUN dotnet build -c Release -o /app/build

# Publikowanie aplikacji
RUN dotnet publish -c Release -o /app/publish

# Użycie obrazu runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Kopiowanie aplikacji z etapu build
COPY --from=build /app/publish .

# Ustawienie zmiennej środowiskowej dla SQLite Password
ENV DATABASE_PASSWORD=Very0#ArrrdT0gue$sPAS$worD531

ENTRYPOINT ["dotnet", "PubMessagesApp.dll"]
EXPOSE 5000
