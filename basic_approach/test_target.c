
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Secret value that should be protected
static const char SECRET_KEY[] = "ThisIsASecretKey123!";
static int license_valid = 0;

// Function that should be protected/obfuscated
int validate_license(const char* input_key) {
    // This is the type of function you'd want to protect
    if (strcmp(input_key, SECRET_KEY) == 0) {
        license_valid = 1;
        return 1;
    }
    return 0;
}

// Another function to protect - game logic simulation
int calculate_score(int base_points, int multiplier, int bonus) {
    // Some "sensitive" game logic
    int score = base_points * multiplier;
    
    if (bonus > 100) {
        score *= 2; // Secret bonus multiplier
    }
    
    return score + bonus;
}

// Premium feature that should be license-gated
void premium_feature() {
    if (!license_valid) {
        printf("Access denied: Premium feature requires valid license\n");
        return;
    }
    
    printf("🎉 Premium feature unlocked! Here's your exclusive content:\n");
    printf("   • Advanced calculations available\n");
    printf("   • Extended functionality enabled\n");
    printf("   • Special algorithms unlocked\n");
}

// Simulate some game state
typedef struct {
    char player_name[64];
    int level;
    int experience;
    int coins;
} GameState;

void display_game_state(GameState* state) {
    printf("\n=== Game State ===\n");
    printf("Player: %s\n", state->player_name);
    printf("Level: %d\n", state->level);
    printf("Experience: %d\n", state->experience);
    printf("Coins: %d\n", state->coins);
    printf("License: %s\n", license_valid ? "VALID" : "INVALID");
    printf("==================\n\n");
}

int main(int argc, char* argv[]) {
    // Suppress unused parameter warnings
    (void)argc;
    (void)argv;
    
    printf("=== Test Target Application ===\n");
    printf("This is a simple app to practice software protection on.\n\n");
    
    GameState game = {0};
    strcpy(game.player_name, "TestPlayer");
    game.level = 5;
    game.experience = 1250;
    game.coins = 500;
    
    display_game_state(&game);
    
    // Interactive license validation
    char input_key[256];
    printf("Enter license key (or 'skip' to continue without license): ");
    fgets(input_key, sizeof(input_key), stdin);
    
    // Remove newline
    input_key[strcspn(input_key, "\n")] = 0;
    
    if (strcmp(input_key, "skip") != 0) {
        if (validate_license(input_key)) {
            printf("✅ License validated successfully!\n");
        } else {
            printf("❌ Invalid license key.\n");
        }
    }
    
    // Try to access premium feature
    printf("\nAttempting to access premium feature...\n");
    premium_feature();
    
    // Some game calculations
    printf("\nPerforming game calculations...\n");
    int score1 = calculate_score(100, 5, 50);
    int score2 = calculate_score(200, 3, 150); // This should trigger secret bonus
    
    printf("Score 1: %d\n", score1);
    printf("Score 2: %d (with secret bonus!)\n", score2);
    
    // Update game state
    game.experience += score1 + score2;
    game.coins += (score1 + score2) / 10;
    
    if (game.experience > 2000) {
        game.level++;
        printf("🎆 Level up! You are now level %d!\n", game.level);
    }
    
    display_game_state(&game);
    
    printf("\n=== Analysis Notes ===\n");
    printf("Functions to protect:\n");
    printf("  • validate_license() - Contains hardcoded key comparison\n");
    printf("  • calculate_score() - Contains secret bonus logic\n");
    printf("  • premium_feature() - License-gated functionality\n");
    printf("\nData to protect:\n");
    printf("  • SECRET_KEY constant - Hardcoded license key\n");
    printf("  • license_valid flag - Controls feature access\n");
    printf("  • Secret bonus threshold (100) in calculate_score\n");
    
    printf("\nTry analyzing this with:\n");
    printf("  • strings test_target (to find the secret key)\n");
    printf("  • objdump -d test_target (to see assembly)\n");
    printf("  • gdb test_target (to debug and modify memory)\n");
    printf("  • hexedit test_target (to patch the binary)\n");
    
    return 0;
}