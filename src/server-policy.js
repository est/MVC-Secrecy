"use strict";

/*
 * Server-only authorization and policy validation.
 *
 * This file must never be shipped to the browser. The shared policy declares
 * resource IDs and types, but only this file decides whether the authenticated
 * principal may act on those resources.
 */

const protocol = require("./public/protocol.js");

const BOARDS = new Set(["b1", "b2"]);
const CHATS = new Set(["c_general"]);

const SCOPE_TYPES = new Set([
  "BoardId",
  "ChatId",
  "UserIdList1to20",
  "AvatarMime",
  "Bytes1to104857600",
  "DraftId",
  "Sha256"
]);
const BODY_TYPES = new Set(["Text1to2000", "Text1to200"]);

const authorizers = {
  "board.write"(scope, auth, context) {
    if (!BOARDS.has(scope.boardId)) {
      return deny(`Unknown board ${scope.boardId}`);
    }
    if (!context.isBoardMember(auth.userId, scope.boardId)) {
      return deny(`User is not a member of board ${scope.boardId}`);
    }
    return allow();
  },

  "chat.write"(scope, auth, context) {
    if (!CHATS.has(scope.chatId)) {
      return deny(`Unknown chat ${scope.chatId}`);
    }
    if (!context.isChatMember(auth.userId, scope.chatId)) {
      return deny(`User is not a member of ${scope.chatId}`);
    }
    return allow();
  },

  "chat.mention"(scope, auth, context) {
    const base = authorizers["chat.write"](scope, auth, context);
    if (!base.ok) return base;
    for (const userId of scope.userIds) {
      if (!context.users.has(userId)) {
        return deny(`Unknown mentioned user ${userId}`);
      }
      if (!context.isChatMember(userId, scope.chatId)) {
        return deny(`Mentioned user ${userId} is not a member of ${scope.chatId}`);
      }
    }
    return allow();
  },

  "chat.join"(scope) {
    return CHATS.has(scope.chatId)
      ? allow()
      : deny(`Unknown chat ${scope.chatId}`);
  },

  "chat.leave"(scope, auth, context) {
    if (!CHATS.has(scope.chatId)) return deny(`Unknown chat ${scope.chatId}`);
    if (!context.isChatMember(auth.userId, scope.chatId)) {
      return deny(`User is not a member of ${scope.chatId}`);
    }
    return allow();
  },

  "self.profile"() {
    // changeAvatar has no target user; it always updates auth.user.
    return allow();
  }
};

function allow() {
  return { ok: true };
}

function deny(message, code = "FORBIDDEN") {
  return { ok: false, code, message };
}

function authorize(action, scope, auth, context) {
  if (!Object.hasOwn(context.policy.actions, action)) {
    return deny(`No policy for ${action}`);
  }
  const config = context.policy.actions[action];
  if (!Object.hasOwn(authorizers, config.authorize)) {
    return deny(`No server authorizer for ${config.authorize}`);
  }
  return authorizers[config.authorize](scope, auth, context);
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertStringArray(value, label) {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`${label} must be a string array`);
  }
}

function validateFieldTypes(fields, label) {
  assertPlainObject(fields, label);
  for (const [key, type] of Object.entries(fields)) {
    protocol.assertSafeKey(key);
    if (typeof type !== "string" || (!SCOPE_TYPES.has(type) && !BODY_TYPES.has(type))) {
      throw new Error(`${label}.${key} has unknown type ${type}`);
    }
  }
}

function validatePolicy(policy) {
  // Also rejects __proto__/prototype/constructor and non-JSON policy values.
  protocol.stableStringify(policy);

  if (policy.version !== 2) throw new Error("Policy version must be 2");
  assertPlainObject(policy.views, "policy.views");
  assertPlainObject(policy.actions, "policy.actions");

  const actionNames = new Set(Object.keys(policy.actions));
  const actionPattern = /^[A-Za-z0-9:_-]+$/;

  for (const [viewName, view] of Object.entries(policy.views)) {
    protocol.assertSafeKey(viewName);
    assertPlainObject(view, `view ${viewName}`);
    assertStringArray(view.actions || [], `view ${viewName}.actions`);
    assertStringArray(view.ui || [], `view ${viewName}.ui`);
    for (const action of view.actions || []) {
      if (!actionNames.has(action)) {
        throw new Error(`View ${viewName} references unknown action ${action}`);
      }
    }
  }

  for (const [action, config] of Object.entries(policy.actions)) {
    protocol.assertSafeKey(action);
    if (!actionPattern.test(action)) throw new Error(`Invalid action name ${action}`);
    assertPlainObject(config, `action ${action}`);
    validateFieldTypes(config.scope, `action ${action}.scope`);
    validateFieldTypes(config.body, `action ${action}.body`);
    if (Object.keys(config.scope).length === 0) {
      throw new Error(`Action ${action} needs a non-empty scope`);
    }
    if (
      typeof config.ttlSeconds !== "number" ||
      !Number.isFinite(config.ttlSeconds) ||
      config.ttlSeconds <= 0
    ) {
      throw new Error(`Action ${action} needs a positive ttlSeconds`);
    }
    if (!Number.isInteger(config.maxUses) || config.maxUses !== 1) {
      throw new Error(`Action ${action} must use maxUses: 1`);
    }
    if (typeof config.presence !== "boolean") {
      throw new Error(`Action ${action} needs a boolean presence flag`);
    }
    if (!["low", "medium", "high"].includes(config.risk)) {
      throw new Error(`Action ${action} has an invalid risk`);
    }
    if (config.risk === "high" && !config.presence) {
      throw new Error(`High-risk action ${action} must require presence`);
    }
    if (
      typeof config.authorize !== "string" ||
      !Object.hasOwn(authorizers, config.authorize)
    ) {
      throw new Error(`Action ${action} has no server authorizer`);
    }
    if (config.next !== undefined) {
      const next = policy.actions[config.next];
      if (!next || next.parent !== action) {
        throw new Error(`Action ${action}.next must be reciprocal`);
      }
    }
    if (config.parent !== undefined) {
      const parent = policy.actions[config.parent];
      if (!parent || parent.next !== action) {
        throw new Error(`Action ${action}.parent must be reciprocal`);
      }
    }
  }

  // Reject next/parent cycles.
  for (const start of actionNames) {
    const seen = new Set();
    let current = start;
    while (policy.actions[current]?.next !== undefined) {
      if (seen.has(current)) throw new Error(`Policy next cycle at ${current}`);
      seen.add(current);
      current = policy.actions[current].next;
    }
    if (seen.has(current)) throw new Error(`Policy next cycle at ${current}`);
  }

  return true;
}

function visibleBoards(auth, context) {
  if (!auth || !context) return [];
  return [...BOARDS].filter((boardId) =>
    context.isBoardMember(auth.userId, boardId)
  );
}

function visibleChats() {
  return [...CHATS];
}

module.exports = {
  authorizers,
  authorize,
  validatePolicy,
  visibleBoards,
  visibleChats
};
