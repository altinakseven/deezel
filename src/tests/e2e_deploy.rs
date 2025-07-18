use super::e2e_helpers::{E2ETestScenario, TestStep};
use crate::tests::TestConfig;

#[tokio::test]
async fn test_e2e_deploy_amm() {
    let config = TestConfig::default();
    E2ETestScenario::new(config)
        .await
        .unwrap()
        .step(TestStep::CreateWallet {
            name: "test_wallet".to_string(),
        })
        .step(TestStep::RunCommand {
            args: vec!["build-contracts".to_string()],
            expect_success: true,
        })
        .step(TestStep::RunCommand {
            args: vec!["deploy".to_string(), "amm".to_string()],
            expect_success: true,
        })
        .execute()
        .await
        .unwrap();
}