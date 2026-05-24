/**
 * Mini Express app with planted authz/IDOR vulnerabilities.
 * Intentionally vulnerable — never deploy this code.
 */

const express = require('express');
const router = express.Router();

// Simulated DB.
const users = {1: {id: 1, name: 'alice'}, 2: {id: 2, name: 'bob'}};
const orders = {
  1: {id: 1, owner_id: 1, amount: 100},
  2: {id: 2, owner_id: 2, amount: 200},
};

function getCurrentUser(req) {
  // In real app: read from JWT or session.
  return req.user;  // may be undefined if not authenticated.
}

// VULN: IDOR — order accessible by any user (no ownership check).
router.get('/orders/:id', getOrder);
function getOrder(req, res) {
  // BUG: missing ownership check: if (order.owner_id !== req.user.id) return res.status(403)
  const order = orders[req.params.id];
  if (!order) return res.status(404).json({error: 'not found'});
  res.json(order);
}

// VULN: auth bypass — no authentication middleware on sensitive delete route.
router.delete('/orders/:id', deleteOrder);
function deleteOrder(req, res) {
  // BUG: no authentication check (missing: if (!req.user) return res.status(401))
  const id = req.params.id;
  delete orders[id];
  res.json({deleted: id});
}

// VULN: privilege escalation — user can set their own role.
router.put('/users/:id/role', updateRole);
function updateRole(req, res) {
  const userId = req.params.id;
  // BUG: any user can change any user's role — no admin check
  const user = users[userId];
  if (!user) return res.status(404).json({error: 'not found'});
  user.role = req.body.role;  // attacker sends role: "admin"
  res.json(user);
}

// SAFE endpoint (true negative).
router.get('/me/orders', getMyOrders);
function getMyOrders(req, res) {
  if (!req.user) return res.status(401).json({error: 'unauthorized'});
  const myOrders = Object.values(orders).filter(o => o.owner_id === req.user.id);
  res.json(myOrders);
}

module.exports = router;
