// The keys config the tests run against.
export const TEST_CONFIG = {
  products: {
    app: {
      name: "Test App",
      prefix: "TAPP",
      editions: { standard: { features: ["core"] }, pro: { features: ["core", "export"] } },
      deviceLimit: 2,
      trialDays: 14,
      leaseDays: 30,
      renewAfterDays: 23,
      graceDays: 7,
      map: {
        stripe: { price_std: "standard", price_pro: "pro", plink_std: "standard", price_up: { edition: "pro", upgrade: true } },
        lemonsqueezy: { 111: "standard", 222: "pro" },
        gumroad: { gprod1: "standard" },
        itch: { 999: "standard" },
      },
    },
    sub: {
      name: "Sub App",
      prefix: "SUBA",
      editions: { monthly: { features: ["all"] } },
      duration: 35,
      deviceLimit: 1,
      map: { stripe: { price_sub: "monthly" }, lemonsqueezy: { 333: "monthly" } },
    },
    offline: {
      name: "Offline Tool",
      prefix: "OFFT",
      editions: { std: { features: ["tool"] } },
      activation: "none",
      map: {},
    },
  },
  refunds: { stripe: "full-only", lemonsqueezy: "full-only", gumroad: "any" },
  disputes: "revoke",
};
