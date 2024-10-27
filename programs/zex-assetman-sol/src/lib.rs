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
        let admins = vec![admin];

        let asset_manager = &mut ctx.accounts.asset_manager;
        asset_manager.admins = admins;

        Ok(())
    }

    // Add a new admin to the AssetManager
	#[access_control(ctx.accounts.asset_manager.is_admin(&ctx.accounts.admin))]
    pub fn admin_add(ctx: Context<AdminAdd>, new_admin: Pubkey) -> Result<()> {
        let asset_manager = &mut ctx.accounts.asset_manager;
		
        asset_manager.admins.push(new_admin);
        Ok(())
    }
	
	#[access_control(ctx.accounts.asset_manager.is_admin(&ctx.accounts.admin))]
	pub fn admin_delete(ctx: Context<AdminDelete>, admin_to_remove: Pubkey) -> Result<()> {
		let asset_manager = &mut ctx.accounts.asset_manager;
	
		// Check if the admin to be removed is in the list
		let admin_index = asset_manager.admins.iter().position(|&admin| admin == admin_to_remove);
	
		require!(admin_index.is_some(), CustomError::MissingData);
	
		// Remove the admin
		asset_manager.admins.remove(admin_index.unwrap());
	
		Ok(())
	}

	#[access_control( ctx.accounts.asset_manager.is_admin(&ctx.accounts.admin) )]
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        Ok(())
    }

    // Deposit tokens into the vault
    pub fn deposit_token(ctx: Context<DepositToken>, amount: u64) -> Result<()> {
        // Transfer tokens from the user's token account to the vault
        token::transfer(ctx.accounts.into_transfer_context(), amount)?;
        Ok(())
    }

    // Transfer tokens from one account to another
    pub fn withdraw_token(ctx: Context<WithdrawToken>, amount: u64) -> Result<()> {
        let assetman = &ctx.accounts.asset_manager;

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
}

// Error checking functions remain within the AssetManager struct
impl AssetManager {
	pub fn is_admin(&self, user: &AccountInfo) -> Result<()> {
		if !self.admins.contains(&user.key()) {
			return Err(CustomError::AdminRestricted.into());
		}
		Ok(())
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
pub struct AdminAdd<'info> {
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminDelete<'info> {
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    pub admin: Signer<'info>,  // This represents the caller, who must be an admin
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = admin,
        seeds = [VAULTS_SEED, asset_manager.key().as_ref(), mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = asset_manager_authority
    )]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub asset_manager: Account<'info, AssetManager>,
    #[account(mut)]
    pub admin: Signer<'info>,
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
    #[msg("Admin restricted method")]
    AdminRestricted,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Missing data")]
    MissingData,
}
