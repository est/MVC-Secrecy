/*
 * Shared, client-safe policy manifest (v2).
 *
 * This file is loaded by the browser and required by Node. It declares UI
 * surfaces, scope/body keys and coarse metadata. It intentionally contains no
 * ACL/authorization logic; server-policy.js is the authority.
 */
(function (root, factory) {
  const policy = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = policy;
  } else {
    root.SECRECY_POLICY = policy;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  return {
    version: 2,
    views: {
      login: { actions: [], ui: ["login"] },
      home: {
        actions: ["createPost", "post:edit", "post:submit"],
        ui: ["viewFeed", "openChat"]
      },
      chat: { actions: ["sendMessage", "mention", "chat:join", "chat:leave"] },
      profile: { actions: ["changeAvatar"] }
    },
    actions: {
      createPost: {
        scope: { boardId: "BoardId" },
        body: { text: "Text1to2000" },
        risk: "low",
        maxUses: 1,
        ttlSeconds: 300,
        presence: false,
        authorize: "board.write"
      },
      sendMessage: {
        scope: { chatId: "ChatId" },
        body: { text: "Text1to2000" },
        risk: "low",
        maxUses: 1,
        ttlSeconds: 60,
        presence: false,
        authorize: "chat.write"
      },
      mention: {
        scope: { chatId: "ChatId", userIds: "UserIdList1to20" },
        body: { text: "Text1to2000" },
        risk: "medium",
        maxUses: 1,
        ttlSeconds: 60,
        presence: false,
        authorize: "chat.mention"
      },
      "chat:join": {
        scope: { chatId: "ChatId" },
        body: {},
        risk: "low",
        maxUses: 1,
        ttlSeconds: 60,
        presence: false,
        authorize: "chat.join"
      },
      "chat:leave": {
        scope: { chatId: "ChatId" },
        body: {},
        risk: "low",
        maxUses: 1,
        ttlSeconds: 60,
        presence: false,
        authorize: "chat.leave"
      },
      changeAvatar: {
        scope: { mime: "AvatarMime", maxSize: "Bytes1to104857600" },
        body: { reason: "Text1to200" },
        risk: "high",
        maxUses: 1,
        ttlSeconds: 120,
        presence: true,
        authorize: "self.profile"
      },
      "post:edit": {
        scope: { boardId: "BoardId" },
        body: { text: "Text1to2000" },
        risk: "low",
        maxUses: 1,
        ttlSeconds: 300,
        presence: false,
        authorize: "board.write",
        next: "post:submit"
      },
      "post:submit": {
        scope: {
          boardId: "BoardId",
          draftId: "DraftId",
          draftHash: "Sha256"
        },
        body: {},
        risk: "low",
        maxUses: 1,
        ttlSeconds: 300,
        presence: false,
        authorize: "board.write",
        parent: "post:edit"
      }
    }
  };
});
