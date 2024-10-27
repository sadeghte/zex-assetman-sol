use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint};

const VAULTS_SEED: &[u8] = b"vault";
const VAULTS_AUTHORITY_SEED: &[u8] = b"vault-authority";

declare_id!("7KNvnNe6sMAVRwXijVeEJ3qn8ACLMcZT3gQQ76VPoKDN");

#[program]
pub mod zex_assetman_sol {
    use super::*;

    // Initialize the AssetManager
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let admin = ctx.accounts.user.key();
        let allowed_tokens = vec![]; // Initialize with an empty list of allowed tokens
        let admins = vec![admin];

        let asset_manager = &mut ctx.accounts.asset_manager;
        asset_manager.admins = admins;
        asset_manager.allowed_tokens = allowed_tokens;

        Ok(())
    }

    // Add a new admin to the AssetManager
    pub fn add_admin(ctx: Context<ModifyAdmin>, new_admin: Pubkey) -> Result<()> {
        let asset_manager = &mut ctx.accounts.asset_manager;
        require!(asset_manager.is_admin(ctx.accounts.admin.key()), CustomError::Unauthorized);
        asset_manager.admins.push(new_admin);
        Ok(())
    }

    // Update the allowed tokens in the AssetManager
    pub fn update_allowed_tokens(ctx: Context<ModifyAdmin>, tokens: Vec<Pubkey>) -> Result<()> {
        let asset_manager = &mut ctx.accounts.asset_manager;
        require!(asset_manager.is_admin(ctx.accounts.admin.key()), CustomError::Unauthorized);
        asset_manager.allowed_tokens = tokens;
        Ok(())
    }

    // Initialize a vault
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let asset_manager = &ctx.accounts.asset_manager;
        let user = ctx.accounts.user.key();

        // Check if the user is an admin
        require!(asset_manager.is_admin(user), CustomError::Unauthorized);

        Ok(())
    }

    // Deposit tokens into the vault
    pub fn deposit_token(ctx: Context<DepositToken>, amount: u64) -> Result<()> {
        let asset_manager = &ctx.accounts.asset_manager;

        // Check if the token being deposited is allowed
        // require!(asset_manager.is_allowed_token(ctx.accounts.user_token_account.mint), CustomError::TokenNotAllowed);

        // Transfer tokens from the user's token account to the vault
        token::transfer(ctx.accounts.into_transfer_context(), amount)?;
        Ok(())
    }

    // Transfer tokens from one account to another
    pub fn withdraw_token(ctx: Context<WithdrawToken>, amount: u64) -> Result<()> {
        let assetman = &ctx.accounts.asset_manager;

        // require!(asset_manager.is_allowed_token(ctx.accounts.source.key()), CustomError::TokenNotAllowed);

		let bump:u8 = ctx.bumps.asset_manager_authority;
		let assetman_key = assetman.key();
    	let seeds = &[VAULTS_AUTHORITY_SEED, assetman_key.as_ref(), &[bump]];

        token::transfer(ctx.accounts.into_transfer_context().with_signer(&[&seeds[..]]), amount)?;
        Ok(())
    }
}

// Define the AssetManager account
#[account]
#[derive(Default)]
pub struct AssetManager {
    admins: Vec<Pubkey>,
    allowed_tokens: Vec<Pubkey>,
}

// Error checking functions remain within the AssetManager struct
impl AssetManager {
	fn is_admin(&self, user: Pubkey) -> bool {
		self.admins.contains(&user)
	}

	fn is_allowed_token(&self, token: Pubkey) -> bool {
		self.allowed_tokens.contains(&token)
	}
}

// Define account contexts for instructions
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 32 + 32 * 10)]
    pub asset_manager: Account<'info, AssetManager>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ModifyAdmin<'info> {
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    #[account(mut)]
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = user,
        seeds = [VAULTS_SEED, asset_manager.key().as_ref(), mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = asset_manager_authority
    )]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,

    #[account(seeds = [VAULTS_AUTHORITY_SEED, asset_manager.key().as_ref()], bump)]
    /// CHECK: This is a PDA authority for the vault. No further checks are required.
    pub asset_manager_authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DepositToken<'info> {
    #[account(
        mut,
        seeds = [VAULTS_SEED, asset_manager.key().as_ref(), mint.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

impl<'info> DepositToken<'info> {
    fn into_transfer_context(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let cpi_accounts = token::Transfer {
            from: self.user_token_account.to_account_info(),
            to: self.vault.to_account_info(),
            authority: self.user.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

#[derive(Accounts)]
pub struct WithdrawToken<'info> {
    #[account(
        mut,
        seeds = [VAULTS_SEED, asset_manager.key().as_ref(), mint.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,

    #[account(seeds = [VAULTS_AUTHORITY_SEED, asset_manager.key().as_ref()], bump)]
    /// CHECK: This is a PDA authority for the vault. No further checks are required.
    pub asset_manager_authority: AccountInfo<'info>,
}

impl<'info> WithdrawToken<'info> {
    fn into_transfer_context(&self) -> CpiContext<'info, 'info, 'info, 'info, token::Transfer<'info>> {
        let cpi_accounts = token::Transfer {
            from: self.vault.to_account_info(),
            to: self.destination.to_account_info(),
            authority: self.asset_manager_authority.to_account_info(),
        };
        CpiContext::new(self.token_program.to_account_info(), cpi_accounts)
    }
}

// Define custom errors
#[error_code]
pub enum CustomError {
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Token not allowed")]
    TokenNotAllowed,
}
