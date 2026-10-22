import { startLab } from "../tests/fixture-server.mjs";

const lab = await startLab();
process.stdout.write(`LAB_URL=${lab.url}\n`);
const stop = async () => {
  await lab.close();
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
setInterval(() => {}, 60_000);
