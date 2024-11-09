import 'dotenv/config';
import * as anchor from '@coral-xyz/anchor';
import { ZexAssetmanSol } from "../target/types/zex_assetman_sol";
import {
    createMint,
    mintTo,
    getOrCreateAssociatedTokenAccount,
    TOKEN_PROGRAM_ID,
	getAssociatedTokenAddress,
	getAssociatedTokenAddressSync
} from '@solana/spl-token';
import { 
	PublicKey, 
	Keypair, 
	Ed25519Program,
	Transaction, 
	TransactionInstruction, 
	sendAndConfirmTransaction, 
	SYSVAR_INSTRUCTIONS_PUBKEY
} from '@solana/web3.js';
import BN from "bn.js"
import { keyGen, signFrost } from './utils';

const ED25519_PROGRAM_ID = new PublicKey('Ed25519SigVerify111111111111111111111111111');

const DECIMALS = 2;
const VAULTS_SEED = Buffer.from("vault");
const VAULTS_AUTHORITY_SEED = Buffer.from("vault-authority");

// Configure the client to use the local cluster.
const provider = anchor.AnchorProvider.local();
anchor.setProvider(provider);

const program = anchor.workspace.ZexAssetmanSol as anchor.Program<ZexAssetmanSol>;
const user = provider.wallet.publicKey;

// Function to create a new token mint
async function createTokenMint(authority: PublicKey): Promise<PublicKey> {
    const mint = await createMint(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        authority,
        null,
        DECIMALS // Decimal places for the token
    );
    return mint;
}

// Function to mint tokens to a destination account
async function mintTokens(mint: PublicKey, destination: PublicKey, amount: number) {
    await mintTo(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        mint,
        destination,
		// @ts-ignore
        provider.wallet.payer,
        amount
    );
}

// Function to create an associated token account
async function createAssociatedTokenAccount(mint: PublicKey): Promise<PublicKey> {
    const account = await getOrCreateAssociatedTokenAccount(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        mint,
        provider.wallet.publicKey
    );
    return account.address;
}

function getAssetManagerAuthority(assetManager: PublicKey): [PublicKey, number] {
	const [publicKey, bump] = anchor.web3.PublicKey.findProgramAddressSync(
        [VAULTS_AUTHORITY_SEED, assetManager.toBuffer()],
        program.programId
    );
	return [publicKey, bump];
}

function getAssetManagerVault(assetManager: PublicKey, mint: PublicKey): [PublicKey, number] {
	return anchor.web3.PublicKey.findProgramAddressSync(
        [
            VAULTS_SEED,
            assetManager.toBuffer(),
            mint.toBuffer(),
        ],
        program.programId
    );
}

async function initializeAssetManager(assetManager: Keypair, withdrawAuthor: PublicKey) {
	// Create Instruction
	const initInst = await program.methods
		.initialize(withdrawAuthor)
		.accounts({
			assetManager: assetManager.publicKey,
			user: provider.wallet.publicKey,
			systemProgram: anchor.web3.SystemProgram.programId,
		})
		.signers([assetManager])
		.instruction()

	// Step 2: Add Instruction to Transaction
    const tx = new anchor.web3.Transaction().add(initInst);

    // Step 3: Send the Transaction
    const signature = await provider.sendAndConfirm(tx, [assetManager]);

    console.log("AssetManager initialized with signature:", signature);
}

async function initializeVault(assetManager: PublicKey, mint: PublicKey) {
    // Calculate PDA for the vault account
    const [vaultAccount] = getAssetManagerVault(assetManager, mint);
	// Calculate PDA for vault authority
	const [authority] = getAssetManagerAuthority(assetManager);
	// Create Instruction
	const initVaultInst = await program.methods
		.initializeVault()
		.accounts({
				vault: vaultAccount, // The vault account to initialize
				assetManager, // The asset manager account
				admin: provider.wallet.publicKey, // The authority
				mint, // The token mint
				assetManagerAuthority: authority,
		})
		.signers([])
		.instruction()

	// Step 2: Add Instruction to Transaction
    const tx = new anchor.web3.Transaction().add(initVaultInst);

    // Step 3: Send the Transaction
    return await provider.sendAndConfirm(tx);

}

async function deposit(assetManager: PublicKey, mint: PublicKey, amount: BN) {
    // Calculate PDA for the vault account
    const [vault] = getAssetManagerVault(assetManager, mint);
	// Create Instruction
	const depositInst = await program.methods
		.depositToken(amount)
		.accounts({
			vault,
			assetManager,
			mint,
			user,
			userTokenAccount: getAssociatedTokenAddressSync(mint, user)
		})
		.signers([])
		.instruction()

	// Step 2: Add Instruction to Transaction
    const tx = new anchor.web3.Transaction().add(depositInst);

    // Step 3: Send the Transaction
    return await provider.sendAndConfirm(tx);
}

async function verifyEd25519Onchain(signature: Buffer, message: Buffer, publicKey: Buffer) {
	// Add the instruction to the transaction
	const tx = new anchor.web3.Transaction().add(
		Ed25519Program.createInstructionWithPublicKey({
			signature,
			message,
			publicKey,
		})
	);

	return await provider.sendAndConfirm(tx);
}

async function withdraw(assetManager: PublicKey, mint: PublicKey, amount: BN, signature, verifyInstruction) {
    // Calculate PDA for the vault account
    const [vault] = getAssetManagerVault(assetManager, mint);
	// Calculate PDA for vault authority
	const [assetManagerAuthority] = getAssetManagerAuthority(assetManager);
	// Create Instruction
	const depositInst = await program.methods
		.withdrawToken(amount, signature)
		.accounts({
			vault,
			assetManager,
			mint,
			destination: await getAssociatedTokenAddress(mint, user),
			instructions: SYSVAR_INSTRUCTIONS_PUBKEY,
			assetManagerAuthority,
		})
		.instruction()

	// Step 2: Add Instruction to Transaction
    const tx = new anchor.web3.Transaction()
		.add(verifyInstruction)
		.add(depositInst);

    // Step 3: Send the Transaction
    return await provider.sendAndConfirm(tx);
}

// Main function to run the test
async function runTest() {
    const tokenAuthority = provider.wallet; // Use the wallet as the token authority

    // Create three new token mints
    const tokenMints: PublicKey[] = [];
    for (let i = 0; i < 3; i++) {
        const mint = await createTokenMint(tokenAuthority.publicKey);
        tokenMints.push(mint);
        console.log(`Created token mint: ${mint.toString()}`);
    }

    // Create associated token accounts and mint tokens
    const assetManagerAccount = Keypair.generate(); // New asset manager account
    const assetManagerTokenAccounts: PublicKey[] = [];

    for (const mint of tokenMints) {
        const tokenAccount = await createAssociatedTokenAccount(mint);
        assetManagerTokenAccounts.push(tokenAccount);
        console.log(`Created associated token account: ${tokenAccount.toString()}`);
        
        // Mint tokens to the asset manager's associated token account
        const mintAmount = 1000;
        await mintTokens(mint, tokenAccount, mintAmount);
        console.log(`Minted ${mintAmount} tokens to ${tokenAccount.toString()}`);
    }

	// create frost shared-key
	const {keyPackages, pubkeyPackage} = keyGen(3, 2);
	const withdrawAuthor:PublicKey = new PublicKey(Buffer.from(pubkeyPackage["verifying_key"], "hex"));
	console.log("Withdraw Author: ", withdrawAuthor.toBase58());

    // Initialize the asset manager account
	console.log("\nInitializing AssetManager...")
	await initializeAssetManager(assetManagerAccount, withdrawAuthor)
	console.log("Initializing AssetManager complete successfully.")

    // Initialize vaults for each token mint
	const [assetManagerAuthority] = anchor.web3.PublicKey.findProgramAddressSync(
        [VAULTS_AUTHORITY_SEED, assetManagerAccount.publicKey.toBuffer()],
        program.programId
    );

    for (const mint of tokenMints) {
		console.log(`\ninitializing vault for mint: ${mint} `)
		let tx = await initializeVault(assetManagerAccount.publicKey, mint);
		console.log("Vault initialized with hash:", tx);

		console.log("Depositing token...")
		tx = await deposit(assetManagerAccount.publicKey, mint, new BN('10'));
		console.log("Deposit done with hash:", tx);
    }

	// console.log("ed25519 verification tx ...")
	let message = `allowed withdraw to ${await getAssociatedTokenAddress(tokenMints[0], user)}`;
	console.log({message});
	let signature = signFrost(Buffer.from(message, 'utf-8'), keyPackages, pubkeyPackage);

	const verificationInstruction = Ed25519Program.createInstructionWithPublicKey({
		signature: Buffer.from(signature, 'hex'),
		message: Buffer.from(message, 'utf-8'),
		publicKey: Buffer.from(pubkeyPackage.verifying_key, 'hex'),
	})

	console.log("\nWithdrawing token...")
	let tx = await withdraw(
		assetManagerAccount.publicKey, 
		tokenMints[0], 
		new BN('5'), 
		Buffer.from(signature, 'hex'),
		verificationInstruction,
	)
	console.log("Withdraw done with hash:", tx);

	// Print summary
	console.log("\n===================== Summary =====================")
    for(let [i, mint] of tokenMints.entries()) {
		console.log(`Token ${i}: ${mint}`)
	}
	console.log(`AssetManager: ${assetManagerAccount.publicKey}`)
	console.log(`VaultAuthority: ${getAssetManagerAuthority(assetManagerAccount.publicKey)}`)
    for(let [i, mint] of tokenMints.entries()) {
		console.log(`Vault ${i}: ${getAssetManagerVault(assetManagerAccount.publicKey, mint)}`)
	}
}

// Execute the test function
runTest().catch((err) => {
    console.error(err);
    process.exit(1);
});