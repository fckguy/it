CREATE TABLE subscriptions (
       apiKey varchar(64),
       platformID varchar(64),
       UseUniqueWallet boolean,
       UseSingleWallet boolean,
       startDate TIMESTAMP,
       endDate TIMESTAMP
) CREATE TABLE users (
       email varchar(128),
       userID varchar(64),
       password varchar(255),
       emailVerified boolean,
       added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       UNIQUE (email)
) CREATE TABLE wallets (
       userID varchar(64),
       walletID varchar(64),
       platformID varchar(64) DEFAULT "0x0",
       isPlatformLocked boolean DEFAULT 0,
       address varchar(64),
       isEVM varchar(42),
       secret text,
       recovery text,
       added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) CREATE TABLE sessions (
       sessionID varchar(64),
       userID varchar(64)
);