# JWT Server Boilerplate

## Set-up

- Clone Repo.
- Change dotenv.example to .env.
- Generate Access Token and Refresh token secret using `crypto`.

```javascript
  require("crypto").randomBytes(64).toString("hex");
```

- Change `ormconfig.json.example` to `ormconfig.json` and update databases infomations.

## Build && Run 

- run: 
```
  yarn build 
```
- then run: 
```
  yarn start
```

## Development
- run: `yarn watch`
- open new therminal and run: `yarn dev`