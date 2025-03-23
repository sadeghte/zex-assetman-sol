import 'dotenv/config';
import * as anchor from '@coral-xyz/anchor';
import { ZexAssetmanSol } from "../target/types/zex_assetman_sol";
import {
    createMint,
    mintTo,
    transfer,
    getOrCreateAssociatedTokenAccount,
    TOKEN_PROGRAM_ID,
	getAssociatedTokenAddressSync
} from '@solana/spl-token';
import { 
	PublicKey, 
	Keypair, 
	Ed25519Program,
	Transaction, 
	TransactionInstruction, 
	sendAndConfirmTransaction, 
	SYSVAR_INSTRUCTIONS_PUBKEY,
    Signer,
    SystemProgram
} from '@solana/web3.js';
import BN from "bn.js"
import { keyGen, signFrost } from './frost-utils';
import { ASSOCIATED_PROGRAM_ID } from '@coral-xyz/anchor/dist/cjs/utils/token';

const ED25519_PROGRAM_ID = new PublicKey('Ed25519SigVerify111111111111111111111111111');

const DECIMALS = 2;
// const ASSETMAN_CONFIG_SEEDS = Buffer.from("assetman-configs");
const VAULTS_SEED = Buffer.from("vault");
const VAULTS_AUTHORITY_SEED = Buffer.from("vault-authority");

const ASSETMAN_CONFIG_SEEDS = Buffer.from("assetman-configs");
const MAIN_VAULTS_SEED = Buffer.from("main-vault");
const USER_VAULTS_SEED = Buffer.from("user-vault");

// Configure the client to use the local cluster.
const provider = anchor.AnchorProvider.local();
anchor.setProvider(provider);

const program = anchor.workspace.ZexAssetmanSol as anchor.Program<ZexAssetmanSol>;
const admin = provider.wallet.publicKey;

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
async function mintTokens(mint: PublicKey, owner: PublicKey, amount: number) {
    const destination = await getOrCreateAssociatedTokenAccount(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        mint,
        owner,
    )

    return await mintTo(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        mint,
        destination.address,
		// @ts-ignore
        provider.wallet.payer,
        amount
    );
}

async function transferSol(sender: Signer, to: PublicKey, amount: number) {
    const tx = new Transaction().add(
        SystemProgram.transfer({
            fromPubkey: sender.publicKey,
            toPubkey: to,
            lamports: amount,
        })
    );
    return await provider.sendAndConfirm(tx);
}

async function transferToken(mint: PublicKey, from: PublicKey, to: PublicKey, amount: number) {
    const fromTokenAccount = getAssociatedTokenAddressSync(mint, from, true)
    const toTokenAccount = await createAssociatedTokenAccount(mint, to, true)
    return await transfer(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        fromTokenAccount,
        toTokenAccount,
        from,
        amount
    )
}

// Function to create an associated token account
async function createAssociatedTokenAccount(mint: PublicKey, owner: PublicKey, allowOwnerOffCurve?: boolean): Promise<PublicKey> {
    const account = await getOrCreateAssociatedTokenAccount(
        provider.connection,
		// @ts-ignore
        provider.wallet.payer,
        mint,
        owner,
        allowOwnerOffCurve,
    );
    return account.address;
}

function getConfigsPDA(programId: PublicKey): PublicKey {
    const [accountPDA, accountBump] = PublicKey.findProgramAddressSync(
        [ASSETMAN_CONFIG_SEEDS],
        programId
    );
    return accountPDA;
}

function getMainVaultPDA(programId: PublicKey): PublicKey {
    const [accountPDA, accountBump] = PublicKey.findProgramAddressSync(
        [MAIN_VAULTS_SEED],
        programId
    );
    return accountPDA;
}

function getUserVaultPDA(programId: PublicKey, agent: string, accountIndex: number, userIndex: number): PublicKey {
    const agentBuff = Buffer.from(agent.substr(2), "hex");
    
    const accountBuff = Buffer.alloc(8);
    accountBuff.writeBigUInt64BE(BigInt(accountIndex))

    const userBuff = Buffer.alloc(8);
    userBuff.writeBigUInt64BE(BigInt(userIndex))
    
    const [accountPDA, accountBump] = PublicKey.findProgramAddressSync(
        [USER_VAULTS_SEED, agentBuff, accountBuff, userBuff],
        programId
    );
    return accountPDA;
}

async function initializeAssetManager(withdrawAuthority: PublicKey) {
	const [configs, _] = anchor.web3.PublicKey.findProgramAddressSync(
        [ASSETMAN_CONFIG_SEEDS],
        program.programId
    );
	// Create Instruction
	const initInst = await program.methods
		.initialize(withdrawAuthority)
		.accounts({
			configs,
			admin: provider.wallet.publicKey,
			systemProgram: anchor.web3.SystemProgram.programId,
		})
		.signers([])
		.instruction()

	// Step 2: Add Instruction to Transaction
    const tx = new anchor.web3.Transaction().add(initInst);

    // Step 3: Send the Transaction
    const signature = await provider.sendAndConfirm(tx);
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

async function transferSolToMainVault(agent: string, accountIndex: number, userIndex: number) {
    const userVault = getUserVaultPDA(program.programId, agent, accountIndex, userIndex);
    const mainVault = getMainVaultPDA(program.programId);

    let tx = new Transaction().add(
        await program.methods.transferSolToMainVault(
            // @ts-ignore
            Buffer.from(agent.substr(2), "hex"), 
            new BN(accountIndex), 
            new BN(userIndex)
        )
        .accounts({
            userVault,
            mainVault,
        })
        .signers([])
        .instruction()
    )

    return await provider.sendAndConfirm(tx);
}

async function transferSplToMainVault(mint: PublicKey, agent: string, accountIndex: number, userIndex: number) {
    const userVault = getUserVaultPDA(program.programId, agent, accountIndex, userIndex);
    const userTokenAccount = getAssociatedTokenAddressSync(mint, userVault, true);
    const mainVault = getMainVaultPDA(program.programId);
    const mainVaultTokenAccount = getAssociatedTokenAddressSync(mint, mainVault, true)

    console.log({
        mint: mint.toBase58(),
        userVault: userVault.toBase58(),
        mainVault: mainVault.toBase58(),
        userTokenAccount: userTokenAccount.toBase58(),
        mainVaultTokenAccount: mainVaultTokenAccount.toBase58(),
        tokenProgram: TOKEN_PROGRAM_ID.toBase58(),
        associatedTokenProgram: ASSOCIATED_PROGRAM_ID.toBase58()
    })

    let tx = new Transaction().add(
        await program.methods.transferSplToMainVault(
            // @ts-ignore
            Buffer.from(agent.substr(2), "hex"), 
            new BN(accountIndex), 
            new BN(userIndex)
        )
        .accounts({
            mint,
            userVault,
            mainVault,
            userTokenAccount,
            mainVaultTokenAccount,
            tokenProgram: TOKEN_PROGRAM_ID,
            associatedTokenProgram: ASSOCIATED_PROGRAM_ID
        })
        .signers([])
        .instruction()
    )

    return await provider.sendAndConfirm(tx);
}

function get_withdraw_message(token: string, amount: number, destination: string): string {
    return `allowed withdraw ${amount} ${token} to address ${destination}`
}

async function withdrawSol(amount: number, to: PublicKey, message: string, signature: string, verifyingKey: string) {
    const configs = getConfigsPDA(program.programId);
    const mainVault = getMainVaultPDA(program.programId);
    const tx = new Transaction();
    tx.add(
        Ed25519Program.createInstructionWithPublicKey({
            signature: Buffer.from(signature, 'hex'),
            message: Buffer.from(message, 'utf-8'),
            publicKey: Buffer.from(verifyingKey, 'hex'),
        })
    ) 
    tx.add(
        await program.methods
            // @ts-ignore
            .withdrawSol(new BN(amount), Buffer.from(signature, "hex"))
            .accounts({
                configs,
                mainVault,
                destination: to,
                instructions: SYSVAR_INSTRUCTIONS_PUBKEY,
            })
            .signers([])
            .instruction()
    );
    return await provider.sendAndConfirm(tx);
}

async function withdrawSpl(mint: PublicKey, amount: number, to: PublicKey, message: string, signature: string, verifyingKey: string) {
    const configs = getConfigsPDA(program.programId);
    const mainVault = getMainVaultPDA(program.programId);
    const tx = new Transaction();
    tx.add(
        Ed25519Program.createInstructionWithPublicKey({
            signature: Buffer.from(signature, 'hex'),
            message: Buffer.from(message, 'utf-8'),
            publicKey: Buffer.from(verifyingKey, 'hex'),
        })
    ) 
    tx.add(
        await program.methods
            // @ts-ignore
            .withdrawSpl(new BN(amount), Buffer.from(signature, "hex"))
            .accounts({
                configs,
                mainVault,
                mainVaultTokenAccount: getAssociatedTokenAddressSync(mint, mainVault, true),
                destinationTokenAccount: getAssociatedTokenAddressSync(mint, to, true),
                mint,
                instructions: SYSVAR_INSTRUCTIONS_PUBKEY,
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([])
            .instruction()
    );
    return await provider.sendAndConfirm(tx);
}

async function runTest() {
    const tokenAuthority = provider.wallet; // Use the wallet as the token authority
	let lampardsToTest = 1_000_000_000; // 1 SOL
	let splAmountToTest = 100; // 1 SOL

    const agent = "0x036c6fd279b30872def5311835159af253ce8d91f695b21021849fa384afdff2";
    const accountIndex = 0;
    const userIndex = 0;

    const mainVault = getMainVaultPDA(program.programId);
    const userVault = getUserVaultPDA(program.programId, agent, accountIndex, userIndex);

    console.log({
        mainVault: mainVault.toBase58(),
        userVault: userVault.toBase58(),
    })

    // Deposit 9 SOL token
    // @ts-ignore
    await transferSol(provider.wallet, userVault, 9_000_000_000);
    console.log("Depositted 9 SOL")

    // Create three new token mints
    const tokenMints: PublicKey[] = [];
    for (let i = 0; i < 1; i++) {
        const mint = await createTokenMint(tokenAuthority.publicKey);
        tokenMints.push(mint);
        console.log(`Created token mint: ${mint.toString()}`);
    }

    // Create associated token accounts and mint tokens
    const assetManagerAccount = Keypair.generate(); // New asset manager account
    const userTokenAccounts: PublicKey[] = [];
    const userVaultTokenAccounts: PublicKey[] = [];
    const mainVaultTokenAccounts: PublicKey[] = [];

    for (const mint of tokenMints) {
        // const userTokenAccount = await createAssociatedTokenAccount(mint, admin);
        // const userVaultTokenAccount = await createAssociatedTokenAccount(mint, userVault, true);
        // const mainVaultTokenAccount = await createAssociatedTokenAccount(mint, mainVault, true);

        const userTokenAccount = getAssociatedTokenAddressSync(mint, admin);
        const userVaultTokenAccount = getAssociatedTokenAddressSync(mint, userVault, true);
        const mainVaultTokenAccount = getAssociatedTokenAddressSync(mint, mainVault, true);

        userTokenAccounts.push(userTokenAccount);
        userVaultTokenAccounts.push(userVaultTokenAccount);
        mainVaultTokenAccounts.push(mainVaultTokenAccount);

        // console.log(`Created associated token account: ${userTokenAccount.toString()}`);
        
        // Mint tokens to the asset manager's associated token account
        const mintAmount = 1000;
        await mintTokens(mint, admin, mintAmount);
        console.log(`Minted ${mintAmount} tokens to ${userTokenAccount.toString()}`);

        // Deposit to user vault 
        // @ts-ignore
        await transferToken(mint, admin, userVault, 900)
        console.log(`Deposited 900 tokens to ${userVault.toString()}`);
    }

	// create frost shared-key
	const {keyPackages, pubkeyPackage} = keyGen(3, 2);
	const withdrawAuthority:PublicKey = new PublicKey(Buffer.from(pubkeyPackage["verifying_key"], "hex"));
	console.log("Withdraw Author: ", withdrawAuthority.toBase58());

    // Initialize the asset manager account
	await initializeAssetManager(withdrawAuthority)
	console.log("Initializing AssetManager complete successfully.")

    const solTransTx = await transferSolToMainVault(agent, accountIndex, userIndex);
    console.log("Tansfer SOL to main Vault ", mainVault.toBase58())
    for(const mint of tokenMints) {
        let splTransTx = await transferSplToMainVault(mint, agent, accountIndex, userIndex)
        console.log("Tansfer SPL to main Vault ", mainVault.toBase58())
    }

	// console.log("ed25519 verification tx ...")
	let solWithdrawMessage = get_withdraw_message("SOL", lampardsToTest, admin.toBase58());
	let solSignature = signFrost(Buffer.from(solWithdrawMessage, 'utf-8'), keyPackages, pubkeyPackage);
    // console.log(pubkeyPackage)
    const solWithdrawTx = await withdrawSol(
        lampardsToTest, 
        admin, 
        solWithdrawMessage, 
        solSignature, 
        pubkeyPackage["verifying_key"]
    )
    console.log("Withdraw SOL from main Vault: ", solWithdrawTx)

    for(const mint of tokenMints) {
        let splWithdrawMessage = get_withdraw_message(
            mint.toBase58(), 
            splAmountToTest, 
            getAssociatedTokenAddressSync(mint, admin, true).toBase58()
        );
        let splSignature = signFrost(Buffer.from(splWithdrawMessage, 'utf-8'), keyPackages, pubkeyPackage);

        const splWithdrawTx = await withdrawSpl(
            mint,
            splAmountToTest, 
            admin, 
            splWithdrawMessage, 
            splSignature, 
            pubkeyPackage["verifying_key"]
        )
        console.log("Withdraw SPL from main Vault: ", splWithdrawTx)
    }

	// const verificationInstruction = Ed25519Program.createInstructionWithPublicKey({
	// 	signature: Buffer.from(signature, 'hex'),
	// 	message: Buffer.from(message, 'utf-8'),
	// 	publicKey: Buffer.from(pubkeyPackage.verifying_key, 'hex'),
	// })

	// console.log("\nWithdrawing token...")
	// let tx = await withdraw(
	// 	assetManagerAccount.publicKey, 
	// 	tokenMints[0], 
	// 	new BN('5'), 
	// 	Buffer.from(signature, 'hex'),
	// 	verificationInstruction,
	// )
	// console.log("Withdraw done with hash:", tx);

	// // Print summary
	// console.log("\n===================== Summary =====================")
    // for(let [i, mint] of tokenMints.entries()) {
	// 	console.log(`Token ${i}: ${mint}`)
	// }
	// console.log(`AssetManager: ${assetManagerAccount.publicKey}`)
	// console.log(`VaultAuthority: ${getAssetManagerAuthority(assetManagerAccount.publicKey)}`)
    // for(let [i, mint] of tokenMints.entries()) {
	// 	console.log(`Vault ${i}: ${getAssetManagerVault(assetManagerAccount.publicKey, mint)}`)
	// }
}

// Execute the test function
runTest().catch((err) => {
    console.error(err);
    process.exit(1);
});