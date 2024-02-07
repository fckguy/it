# **Wen Auth Web3 service ser**


**flow login:** <br>
flow login:<br>
- /login: login if good gives cookie with sessionID<br>
- /getWallets: from the sessionID we can link uuid, and send all the wallet addresses with the walletID's<br>
- /getSecretPiece: this will have a parameter with walletID, for each walletID we will send the shamir secret piece<br><br>

**Steps to do:** <br>
I'll discuss the main most important steps here, there probably are some more smaller steps.

-- Add some sort of session management, may it be through http sessions or through local storage jwt tokens (http sessions more professional)<br>
-- Add Shamir's secret sharing, if you don't know: [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)<br>
-- Connect to solana through a web3 package, if we can't find any go packages, create our own


**Questions without an answer:** <br>
This piece assumes the fact that a part of the secret will be saved on the backend. One will be for the user, another one
will be for the user as well, in case of recovery.

-- What happens if the user removes the sessions somehow? Will he have to redo the logging in of secrets for his wallet?
Especially if he has multiple wallets. Also, wouldn't it somehow be a security breach if we have the user logged in and then after
have the user put in his secret parts for his wallets? Even though an attacker couldn't login to his wallet, he'd still know
that the user with specified email address has an account on our service.<br>

-- How would we go from a platform that allows multiple wallets to a platform that only allows one? Would the user have to choose one? Would the user have to create a new one?<br>

-- What exactly needs to appear in the wallet and what needs to be saved?