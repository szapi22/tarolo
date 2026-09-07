# 1. Hivatalos, pehelysúlyú Node.js Alpine alap image
FROM node:20-alpine

# 2. Munkakönyvtár beállítása a konténeren belül
WORKDIR /app

# 3. Csomagleírók másolása a réteg-gyorsítótárazás (cache) kihasználásához
COPY package*.json ./

# 4. Függőségek telepítése (éles környezethez ajánlott a ci)
RUN npm ci --only=production

# 5. Teljes forráskód bemásolása
COPY . .

# 6. Port megadása, amin az alkalmazás figyel (pl. 3000)
EXPOSE 3000

# 7. Alkalmazás indítása nem-root felhasználóként a biztonságért
USER node
CMD ["node", "server.js"]