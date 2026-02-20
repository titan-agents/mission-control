import { NextRequest, NextResponse } from 'next/server';
import { v4 as uuidv4 } from 'uuid';
import { createHmac } from 'crypto';
import { queryOne, queryAll, run } from '@/lib/db';
import type { Task, Agent, OpenClawSession } from '@/lib/types';

/**
 * Verify HMAC-SHA256 signature of webhook request
 */
function verifyWebhookSignature(signature: string, rawBody: string): boolean {
  const webhookSecret = process.env.WEBHOOK_SECRET;
  
  if (!webhookSecret) {
    // Dev mode - skip validation
    return true;
  }

  if (!signature) {
    return false;
  }

  const expectedSignature = createHmac('sha256', webhookSecret)
    .update(rawBody)
    .digest('hex');

  return signature === expectedSignature;
}

/**
 * POST /api/webhooks/agent-completion
 *
 * Receives completion notifications from agents.
 *
 * Preferred all-in-one payload:
 * {
 *   "task_id": "uuid",
 *   "status": "review",                    // optional, defaults to "testing"
 *   "summary": "Built the auth system",
 *   "deliverables": [                      // optional
 *     {"type": "file", "title": "auth.ts", "path": "/workspace/auth.ts"},
 *     {"type": "url",  "title": "Demo",    "path": "http://localhost:3000"}
 *   ]
 * }
 *
 * Legacy session-based payload:
 * {
 *   "session_id": "mission-control-engineering",
 *   "message": "TASK_COMPLETE: Built the authentication system"
 * }
 */
export async function POST(request: NextRequest) {
  try {
    // Read raw body for signature verification
    const rawBody = await request.text();
    
    // Verify webhook signature if WEBHOOK_SECRET is set
    const webhookSecret = process.env.WEBHOOK_SECRET;
    if (webhookSecret) {
      const signature = request.headers.get('x-webhook-signature');
      
      if (!signature || !verifyWebhookSignature(signature, rawBody)) {
        console.warn('[WEBHOOK] Invalid signature attempt');
        return NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        );
      }
    }

    const body = JSON.parse(rawBody);
    const now = new Date().toISOString();

    // Handle direct task_id completion
    if (body.task_id) {
      const task = queryOne<Task & { assigned_agent_name?: string }>(
        `SELECT t.*, a.name as assigned_agent_name
         FROM tasks t
         LEFT JOIN agents a ON t.assigned_agent_id = a.id
         WHERE t.id = ?`,
        [body.task_id]
      );

      if (!task) {
        return NextResponse.json({ error: 'Task not found' }, { status: 404 });
      }

      // Determine target status (default: testing, allow "review" or "done")
      const allowedStatuses = ['testing', 'review', 'done'];
      const targetStatus = allowedStatuses.includes(body.status) ? body.status : 'testing';

      // Only move forward - don't overwrite a later status
      const statusOrder = ['planning', 'inbox', 'assigned', 'in_progress', 'testing', 'review', 'done'];
      const currentIdx = statusOrder.indexOf(task.status);
      const targetIdx = statusOrder.indexOf(targetStatus);

      const newStatus = targetIdx > currentIdx ? targetStatus : task.status;
      if (newStatus !== task.status) {
        run(
          'UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?',
          [newStatus, now, task.id]
        );
      }

      // Register deliverables if provided
      const deliverables: Array<{ type: string; title: string; path?: string; description?: string }> = body.deliverables || [];
      for (const d of deliverables) {
        run(
          `INSERT INTO task_deliverables (id, task_id, deliverable_type, title, path, description, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [uuidv4(), task.id, d.type || 'file', d.title, d.path || null, d.description || null, now]
        );
      }

      // Log completion activity
      run(
        `INSERT INTO task_activities (id, task_id, agent_id, activity_type, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [uuidv4(), task.id, task.assigned_agent_id, 'completed', body.summary || 'Task finished', now]
      );

      // Log completion event
      run(
        `INSERT INTO events (id, type, agent_id, task_id, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          uuidv4(),
          'task_completed',
          task.assigned_agent_id,
          task.id,
          `${task.assigned_agent_name} completed: ${body.summary || 'Task finished'}`,
          now
        ]
      );

      // Set agent back to standby
      if (task.assigned_agent_id) {
        run(
          'UPDATE agents SET status = ?, updated_at = ? WHERE id = ?',
          ['standby', now, task.assigned_agent_id]
        );
      }

      return NextResponse.json({
        success: true,
        task_id: task.id,
        new_status: newStatus,
        deliverables_registered: deliverables.length,
        message: `Task moved to ${newStatus}`
      });
    }

    // Handle session-based completion (from message parsing)
    if (body.session_id && body.message) {
      // Parse TASK_COMPLETE message
      const completionMatch = body.message.match(/TASK_COMPLETE:\s*(.+)/i);
      if (!completionMatch) {
        return NextResponse.json(
          { error: 'Invalid completion message format. Expected: TASK_COMPLETE: [summary]' },
          { status: 400 }
        );
      }

      const summary = completionMatch[1].trim();

      // Find agent by session
      const session = queryOne<OpenClawSession>(
        'SELECT * FROM openclaw_sessions WHERE openclaw_session_id = ? AND status = ?',
        [body.session_id, 'active']
      );

      if (!session) {
        return NextResponse.json(
          { error: 'Session not found or inactive' },
          { status: 404 }
        );
      }

      // Find active task for this agent
      const task = queryOne<Task & { assigned_agent_name?: string }>(
        `SELECT t.*, a.name as assigned_agent_name
         FROM tasks t
         LEFT JOIN agents a ON t.assigned_agent_id = a.id
         WHERE t.assigned_agent_id = ? 
           AND t.status IN ('assigned', 'in_progress')
         ORDER BY t.updated_at DESC
         LIMIT 1`,
        [session.agent_id]
      );

      if (!task) {
        return NextResponse.json(
          { error: 'No active task found for this agent' },
          { status: 404 }
        );
      }

      // Only move to testing if not already in testing, review, or done
      // (Don't overwrite user's approval or testing results)
      if (task.status !== 'testing' && task.status !== 'review' && task.status !== 'done') {
        run(
          'UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?',
          ['testing', now, task.id]
        );
      }

      // Log completion with summary
      run(
        `INSERT INTO events (id, type, agent_id, task_id, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          uuidv4(),
          'task_completed',
          session.agent_id,
          task.id,
          `${task.assigned_agent_name} completed: ${summary}`,
          now
        ]
      );

      // Set agent back to standby
      run(
        'UPDATE agents SET status = ?, updated_at = ? WHERE id = ?',
        ['standby', now, session.agent_id]
      );

      return NextResponse.json({
        success: true,
        task_id: task.id,
        agent_id: session.agent_id,
        summary,
        new_status: 'testing',
        message: 'Task moved to testing for automated verification'
      });
    }

    return NextResponse.json(
      { error: 'Invalid payload. Provide either task_id or session_id + message' },
      { status: 400 }
    );
  } catch (error) {
    console.error('Agent completion webhook error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/webhooks/agent-completion
 * 
 * Returns webhook status and recent completions
 */
export async function GET() {
  try {
    const recentCompletions = queryAll(
      `SELECT e.*, a.name as agent_name, t.title as task_title
       FROM events e
       LEFT JOIN agents a ON e.agent_id = a.id
       LEFT JOIN tasks t ON e.task_id = t.id
       WHERE e.type = 'task_completed'
       ORDER BY e.created_at DESC
       LIMIT 10`
    );

    return NextResponse.json({
      status: 'active',
      recent_completions: recentCompletions,
      endpoint: '/api/webhooks/agent-completion'
    });
  } catch (error) {
    console.error('Failed to fetch completion status:', error);
    return NextResponse.json(
      { error: 'Failed to fetch status' },
      { status: 500 }
    );
  }
}
