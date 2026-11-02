import { expect, test } from "@playwright/test";

test("admin signs in and can add an encrypted DNS provider", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await page.getByLabel("Admin password").fill(process.env.E2E_PASSWORD ?? "e2e-test-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Your certificates" })).toBeVisible();
  await expect(page.getByText("No certificates tracked yet.")).toBeVisible();

  await page.getByRole("button", { name: "DNS providers" }).click();
  await page.getByLabel("Provider preset").selectOption("ionos");
  await page.getByLabel("Credentials JSON").fill('{"dns_ionos_prefix":"test","dns_ionos_secret":"secret"}');
  await page.getByRole("button", { name: "Save encrypted credentials" }).click();

  await expect(page.locator(".provider-row").filter({ hasText: "IONOS" }).first()).toBeVisible();
  await expect(
    page.locator(".provider-row").filter({ hasText: "IONOS" }).first().getByText("Credentials encrypted"),
  ).toBeVisible();
  await expect(page.getByText("DNS provider saved. Credentials are encrypted in the database.")).toBeVisible();
});
