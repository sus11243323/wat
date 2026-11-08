'use strict';
require('dotenv').config();
const {
  Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder,
  ButtonStyle, Events
} = require('discord.js');

const apiBase = (process.env.WATASZIT_API_URL || '').replace(/\/$/, '');
const secret = process.env.BETA_REVIEW_SECRET || '';
const channelId = process.env.DISCORD_BETA_CHANNEL_ID || '';
const reviewerRoleId = process.env.DISCORD_REVIEW_ROLE_ID || '';
const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const posted = new Set();
let polling = false;

async function api(path, options = {}) {
  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Beta-Review-Secret': secret,
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || `Wataszit API returned HTTP ${response.status} for ${path}`);
  }
  return data;
}

function reviewButtons(id, disabled = false) {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId(`beta_accept:${id}`).setLabel('Accept').setStyle(ButtonStyle.Success).setDisabled(disabled),
    new ButtonBuilder().setCustomId(`beta_decline:${id}`).setLabel('Decline').setStyle(ButtonStyle.Danger).setDisabled(disabled)
  );
}

async function publishPending() {
  if (polling) return;
  polling = true;
  try {
    const channel = await client.channels.fetch(channelId);
    if (!channel || !channel.isTextBased() || !channel.send) throw new Error('Beta review channel is unavailable or the bot cannot send messages there.');
    const result = await api('/api/internal/beta-applications/pending');
    for (const application of result.applications || []) {
      if (posted.has(application.id)) continue;
      const message = await channel.send({
        content: `**Wataszit beta application**\nUser: **${application.username}**\nEmail: ${application.email}\nIP: \`${application.ip}\`\nApplication: \`${application.id}\``,
        components: [reviewButtons(application.id)]
      });
      posted.add(application.id);
      console.log(`[Wataszit] Posted beta application ${application.id} as Discord message ${message.id}`);
    }
  } catch (error) {
    console.error('[Wataszit] Could not publish pending applications:', error.message);
  } finally {
    polling = false;
  }
}


async function syncDiscordChannels() {
  try {
    const guilds = await client.guilds.fetch();
    const channels = [];
    for (const [, partial] of guilds) {
      const guild = await partial.fetch();
      const fetched = await guild.channels.fetch();
      for (const [, channel] of fetched) {
        if (channel && channel.isTextBased() && channel.id && channel.name) {
          channels.push({ id: channel.id, name: channel.name, guildName: guild.name });
        }
      }
    }
    await api('/api/internal/discord/channels', { method: 'POST', body: JSON.stringify({ channels }) });
    console.log(`[Wataszit] Synced ${channels.length} Discord text channels.`);
  } catch (error) { console.error('[Wataszit] Channel sync failed:', error.message); }
}

async function deliverWebsiteMessages() {
  try {
    const result = await api('/api/internal/discord/queue');
    for (const item of result.messages || []) {
      let delivered = false, errorText = '';
      try {
        const channel = await client.channels.fetch(item.channelId);
        if (!channel || !channel.isTextBased() || !channel.send) throw new Error('Channel unavailable or not writable.');
        await channel.send({ content: `**${item.username}** (Wataszit website): ${item.content}` });
        delivered = true;
      } catch (error) { errorText = error.message; }
      await api('/api/internal/discord/delivered', {
        method: 'POST',
        body: JSON.stringify({ id: item.id, success: delivered, error: errorText })
      });
    }
  } catch (error) { console.error('[Wataszit] Website chat bridge:', error.message); }
}

client.once(Events.ClientReady, () => {
  console.log(`[Wataszit] Beta review bot ready as ${client.user.tag}`);
  publishPending();
  syncDiscordChannels();
  deliverWebsiteMessages();
  setInterval(publishPending, 5000);
  setInterval(syncDiscordChannels, 30000);
  setInterval(deliverWebsiteMessages, 2000);
});

client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.isButton() || !interaction.customId.startsWith('beta_')) return;
  const [action, id] = interaction.customId.split(':');
  const decision = action === 'beta_accept' ? 'accepted' : action === 'beta_decline' ? 'declined' : null;
  if (!decision || !id) return;

  if (reviewerRoleId) {
    const member = interaction.member;
    const roleIds = member?.roles?.cache
      ? [...member.roles.cache.keys()]
      : Array.isArray(member?.roles) ? member.roles : [];
    if (!roleIds.includes(reviewerRoleId)) {
      return interaction.reply({ content: 'You are not allowed to review beta applications.', ephemeral: true });
    }
  }

  try {
    await interaction.deferUpdate();
    await api('/api/internal/beta-application/review', {
      method: 'POST',
      body: JSON.stringify({ id, decision, reviewer: interaction.user.tag })
    });
    const suffix = `\n\n**${decision.toUpperCase()}** by ${interaction.user.tag}`;
    await interaction.message.edit({
      content: interaction.message.content.replace(/\n\n\*\*(ACCEPTED|DECLINED)\*\* by .+$/, '') + suffix,
      components: [reviewButtons(id, true)]
    });
  } catch (error) {
    console.error('[Wataszit] Beta review failed:', error.message);
    const message = `Could not update the application: ${error.message}`;
    if (interaction.deferred || interaction.replied) {
      await interaction.followUp({ content: message, ephemeral: true }).catch(() => {});
    } else {
      await interaction.reply({ content: message, ephemeral: true }).catch(() => {});
    }
  }
});

if (!process.env.DISCORD_BOT_TOKEN || !channelId || !secret || !apiBase) {
  console.error('Missing DISCORD_BOT_TOKEN, DISCORD_BETA_CHANNEL_ID, BETA_REVIEW_SECRET or WATASZIT_API_URL in .env');
  process.exit(1);
}
client.login(process.env.DISCORD_BOT_TOKEN);
