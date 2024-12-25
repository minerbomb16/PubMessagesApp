FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Kopiowanie pliku rozwiązania (.sln)
COPY PubMessagesApp.sln ./ 

# Kopiowanie folderu aplikacji
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
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "PubMessagesApp.dll"]
EXPOSE 5000
