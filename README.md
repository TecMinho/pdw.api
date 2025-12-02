## 🎒 Credentials Wallet API (EBSI SSI Mobile Wallet)

This API serves to compliment the functionalities developed in the credential
wallet, allowing the full issuance and verification flow part expected in the
holder architecture.

## 🛠️ Technologies Used

- NestJS
- Node 20.19.0
- EBSI's [Verifiable Credentials](https://code.europa.eu/ebsi/public/core-libs/-/tree/main/packages/verifiable-credential?ref_type=heads) and [Verifiable Presentations](https://code.europa.eu/ebsi/public/core-libs/-/tree/main/packages/verifiable-presentation?ref_type=heads) packages

## 🧪 Features

- 📥 Accept credentials via QR code and credential offer URL
- 🧾 Present credentials when requested with Selective Disclosure
- ☑️ Full compliance with the EBSI conformance tests
- ❎ Revoke a credential (in progress)

## 🧱 Project Structure

```
/src
|-- /config             // Centralized configuration files for issuer, verifier, and status list modules
|-- /controllers        // Defines API route handlers and business logic entry points
|-- /environment        // EBSI v5 registry issuer used in the main wallet flow
|-- /events             // WebSocket gateway for real-time communication with the EBSI portal
|-- /interfaces         // Shared TypeScript interfaces and data models, including the holder's DID structure
|-- /scripts            // Utility scripts, such as those for initializing a revocation status list
|-- /services           // Core service layer containing reusable logic used by controllers
|-- /utils              // General-purpose utility functions and helpers
```

## ▶️ Running the API

#### 1. Clone the project

```
git clone https://github.com/DaxLedger/portuguese-digital-wallet-api.git
cd portuguese-digital-wallet-api
```

#### 2. Install dependencies

```
npm install
```

#### 3. Configure the environment variables

Edit `.env` file:

```
PORT=<API_PORT>
```

#### 4. Start the app

```
npm run start
```

## ▶️ Build Docker

```
docker build -t pdw.api .
```

## ▶️ Run Docker

```
docker run -p 8080:3000  -e PORT=3000 --name pdw.api pdw.api
```

| Parameter             | Description                                                                                                     | Example Usage                                                     |
| --------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| -p <host>:<container> | Maps a port on the host machine to a port inside the container. Allows you to access the app via the host port. | -p 8080:3000 maps host port 8080 to container port 3000           |
| -e <KEY>=<VALUE>      | Sets an environment variable inside the container. Useful for configuring runtime behavior.                     | -e PORT=3000 sets environment variable PORT=3000 inside container |
