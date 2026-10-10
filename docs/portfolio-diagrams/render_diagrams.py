from pathlib import Path
from xml.etree import ElementTree

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Arc, Ellipse, FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle
from PIL import Image

OUT = Path(__file__).resolve().parent
C = {
    "ink": "#0F172A", "muted": "#64748B", "blue": "#2563EB", "blue_fill": "#EFF6FF",
    "teal": "#0F766E", "teal_fill": "#F0FDFA", "green": "#15803D", "green_fill": "#F0FDF4",
    "amber": "#B45309", "amber_fill": "#FFFBEB", "red": "#B91C1C", "red_fill": "#FEF2F2",
    "gray": "#64748B", "gray_fill": "#F8FAFC",
    "line": "#CBD5E1", "panel": "#F8FAFC", "white": "#FFFFFF",
}


def canvas(width, height, number, title, subtitle):
    plt.rcParams.update({"font.family": "sans-serif", "font.sans-serif": ["Segoe UI", "Arial", "DejaVu Sans"],
                         "svg.fonttype": "none", "svg.hashsalt": "agentshield-portfolio"})
    fig = plt.figure(figsize=(width, height), dpi=120, facecolor=C["white"])
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set(xlim=(0, width), ylim=(0, height))
    ax.axis("off")
    ax.text(.7, height-.42, "AGENTSHIELD  /  ENGINEERING OVERVIEW", color=C["blue"], fontsize=10,
            fontweight="bold", va="center")
    ax.text(.7, height-1.12, title, color=C["ink"], fontsize=25, fontweight="bold", va="center")
    ax.text(.72, height-1.62, subtitle, color=C["muted"], fontsize=11.5, va="center")
    ax.text(width-.7, height-1.06, number, color=C["blue"], fontsize=19, fontweight="bold",
            ha="right", va="center")
    ax.plot([.7, width-.7], [height-1.96]*2, color=C["line"], lw=.8)
    return fig, ax


def panel(ax, x, y, w, h, label, dashed=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=.02,rounding_size=.16",
                               facecolor=C["panel"], edgecolor=C["line"], linewidth=1.05,
                               linestyle=(0, (4, 3)) if dashed else "solid", zorder=0))
    ax.text(x+.22, y+h-.25, label.upper(), color=C["muted"], fontsize=8.5, fontweight="bold",
            va="center", zorder=2)


def card(ax, x, y, w, h, title, detail="", kind="blue", title_size=10, detail_size=8):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=.03,rounding_size=.14",
                               facecolor=C[f"{kind}_fill"], edgecolor=C[kind], linewidth=1.1, zorder=3))
    multiline = detail.count("\n") > 0 if detail else False
    ax.text(x+.18, y+h*(.68 if multiline else .62), title, color=C["ink"], fontsize=title_size,
            fontweight="bold", va="center", zorder=4)
    if detail:
        ax.text(x+.18, y+h*(.32 if multiline else .27), detail, color=C["muted"], fontsize=detail_size,
                va="center", linespacing=1.25, zorder=4)
    return x, y, w, h


def note(ax, x, y, w, h, text, kind="gray", size=8):
    edge, fill = (C["line"], C["panel"]) if kind == "gray" else (C[kind], C[f"{kind}_fill"])
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=.025,rounding_size=.1",
                               facecolor=fill, edgecolor=edge, linewidth=.9, zorder=3))
    ax.text(x+.13, y+h/2, text, color=C["muted"], fontsize=size, va="center",
            linespacing=1.2, zorder=4)


def diamond(ax, cx, cy, w, h, text, kind="amber", size=9):
    pts = [(cx, cy+h/2), (cx+w/2, cy), (cx, cy-h/2), (cx-w/2, cy)]
    ax.add_patch(Polygon(pts, closed=True, facecolor=C[f"{kind}_fill"], edgecolor=C[kind],
                         linewidth=1.1, zorder=3))
    ax.text(cx, cy, text, color=C["ink"], fontsize=size, fontweight="bold", ha="center",
            va="center", linespacing=1.2, zorder=4)


def database(ax, x, y, w, h, title, detail):
    ax.add_patch(Rectangle((x, y+.16*h), w, .68*h, facecolor=C["teal_fill"], edgecolor=C["teal"],
                           linewidth=1.1, zorder=3))
    ax.add_patch(Ellipse((x+w/2, y+.82*h), w, .30*h, facecolor=C["teal_fill"],
                         edgecolor=C["teal"], linewidth=1.1, zorder=3))
    ax.add_patch(Arc((x+w/2, y+.16*h), w, .30*h, theta1=180, theta2=360,
                     edgecolor=C["teal"], linewidth=1.1, zorder=3))
    ax.text(x+.2, y+.61*h, title, color=C["ink"], fontsize=10.3, fontweight="bold",
            va="center", zorder=4)
    ax.text(x+.2, y+.34*h, detail, color=C["muted"], fontsize=7.7, va="center",
            linespacing=1.2, zorder=4)


def arrow(ax, start, end, label="", color=None, dashed=False, rad=0, label_xy=None, size=7.3):
    color = color or C["muted"]
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=10,
                                 linewidth=1.2, color=color,
                                 linestyle=(0, (4, 3)) if dashed else "solid",
                                 connectionstyle=f"arc3,rad={rad}", zorder=1))
    if label:
        lx, ly = label_xy or ((start[0]+end[0])/2, (start[1]+end[1])/2)
        ax.text(lx, ly, label, fontsize=size, color=color, ha="center", va="center",
                bbox={"boxstyle": "round,pad=.18", "fc": C["white"], "ec": "none", "alpha": .96},
                zorder=5)


def elbow(ax, points, label="", color=None, dashed=True, label_xy=None, size=7.2):
    color = color or C["muted"]
    for a, b in zip(points[:-2], points[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=1.2,
                linestyle=(0, (4, 3)) if dashed else "solid", zorder=1)
    arrow(ax, points[-2], points[-1], color=color, dashed=dashed)
    if label:
        lx, ly = label_xy or points[len(points)//2]
        ax.text(lx, ly, label, fontsize=size, color=color, ha="center", va="center",
                bbox={"boxstyle": "round,pad=.18", "fc": C["white"], "ec": "none", "alpha": .96},
                zorder=5)


def finish(fig, stem):
    svg, png = OUT/f"{stem}.svg", OUT/f"{stem}.png"
    fig.savefig(svg, format="svg", facecolor=C["white"], metadata={"Date": None})
    fig.savefig(png, format="png", dpi=120, facecolor=C["white"])
    plt.close(fig)
    ElementTree.parse(svg)
    with Image.open(png) as image:
        image.verify()
    with Image.open(png) as image:
        assert image.mode in {"RGB", "RGBA"} and image.width >= 2200
    return svg, png


def render_architecture():
    fig, ax = canvas(24, 14.6, "01", "System architecture",
                     "How the system is designed, connected, and engineered.")
    panel(ax, .55, 6.8, 7.8, 4.8, "Client and edge · outside Compose")
    panel(ax, 8.55, 2.25, 14.9, 9.35, "Docker Compose runtime", dashed=True)
    panel(ax, 8.83, 8.3, 8.2, 2.7, "Request and control plane")
    panel(ax, 8.83, 2.65, 10.3, 5.4, "Asynchronous evaluation")
    panel(ax, 19.35, 2.65, 3.82, 3.95, "Operations")

    card(ax, .9, 9.45, 3, 1.3, "Web workbench", "HTML · CSS · JavaScript\nSession-scoped API key", "blue")
    card(ax, .9, 7.4, 3, 1.15, "REST client", "JSON API over HTTPS", "blue")
    card(ax, 4.45, 8.15, 3.5, 1.5, "TLS reverse proxy", "Deployment-specific edge\nAPI binds to loopback", "gray")
    card(ax, 9.15, 9.15, 3.35, 1.35, "FastAPI / Uvicorn", "REST routes · static pages\nAPI key auth · RBAC · Pydantic", "blue")
    card(ax, 12.85, 9.15, 3.85, 1.35, "Evaluation API", "Validate target and scenarios\nIdempotency · snapshot · outbox", "blue")
    database(ax, 18.95, 8.95, 4, 1.7, "PostgreSQL 16",
             "Tenant-scoped runs · policies · evidence\nSnapshots · transactional outbox")

    card(ax, 9.15, 5.05, 3.1, 1.25, "Redis 7", "Celery broker\nRate counters · run lock", "teal")
    card(ax, 16.05, 6.85, 2.8, 1.0, "Celery Beat", "Dispatch outbox every 10 s", "blue", 9.4, 7.4)
    card(ax, 12.85, 5.05, 2.8, 1.25, "Celery worker", "Late acknowledgement\nBounded retries · time limits", "blue")
    card(ax, 16.05, 5.05, 2.8, 1.25, "Deterministic evaluator", "Schema · tenant · approval\nAllowlist · call-budget checks", "amber", 9.2, 7.2)
    card(ax, 12.55, 3.2, 3, 1.15, "Scenario catalog", "50 versioned cases\nSecurity · benign · reliability", "gray", 9.8, 7.4)
    card(ax, 19.65, 4.85, 3.2, 1.4, "Service signals", "JSON logs + request IDs\n/health · /health/ready (PG + Redis)", "gray", 9.8, 7.4)

    arrow(ax, (3.9, 10.1), (4.45, 9.25), "HTTPS", C["blue"], rad=-.12, label_xy=(4, 9.95))
    arrow(ax, (3.9, 7.98), (4.45, 8.55), "HTTPS", C["blue"], rad=.12, label_xy=(4, 8.15))
    arrow(ax, (7.95, 8.9), (9.15, 9.8), "REST", C["blue"], label_xy=(8.55, 9.57))
    arrow(ax, (12.5, 9.83), (12.85, 9.83), "validated", C["blue"], label_xy=(12.68, 10.14), size=6.5)
    arrow(ax, (16.7, 9.82), (18.95, 9.82), "SQL · atomic run + outbox", C["teal"], label_xy=(17.83, 10.18), size=6.9)
    arrow(ax, (10.8, 9.15), (10.7, 6.3), "rate limits", C["teal"], label_xy=(11.35, 6.85), size=7)
    arrow(ax, (13.0, 9.15), (12.25, 5.85), "Celery task · async", C["blue"], dashed=True, label_xy=(12.25, 7.7), size=6.8)
    arrow(ax, (16.05, 7.35), (12.25, 5.85), "dispatch", C["blue"], dashed=True, label_xy=(14.15, 6.85), size=6.7)
    arrow(ax, (12.25, 5.67), (12.85, 5.67), color=C["blue"], dashed=True)
    arrow(ax, (15.65, 5.67), (16.05, 5.67), color=C["blue"])
    elbow(ax, [(15.65, 6.3), (15.8, 6.45), (19.1, 6.45), (19.1, 8.95)],
          "read snapshots · persist results", C["teal"], dashed=False, label_xy=(17.45, 6.45), size=6.8)
    arrow(ax, (18.95, 9.6), (18.85, 7.45), "unsent outbox", C["teal"], dashed=True, label_xy=(20.0, 8.5), size=6.8)
    arrow(ax, (15.55, 3.78), (17.05, 5.05), "cases", C["muted"], label_xy=(16.15, 4.45), size=6.5)

    ax.plot([.8, 1.35], [1.55, 1.55], color=C["blue"], lw=1.4)
    ax.annotate("", xy=(1.35, 1.55), xytext=(1.05, 1.55),
                arrowprops={"arrowstyle": "-|>", "color": C["blue"], "lw": 1.2})
    ax.text(1.55, 1.55, "Synchronous request / data", color=C["muted"], fontsize=8, va="center")
    ax.plot([4.6, 5.15], [1.55, 1.55], color=C["blue"], lw=1.2, linestyle=(0, (4, 3)))
    ax.text(5.35, 1.55, "Asynchronous dispatch", color=C["muted"], fontsize=8, va="center")
    return finish(fig, "system-architecture")


def render_flow():
    fig, ax = canvas(26, 18, "02", "End-to-end execution flow",
                     "How a request moves through the system, from input to outcome.")
    panel(ax, .55, 10.45, 24.9, 5.1, "01  Request intake · synchronous API")
    panel(ax, .55, 6.15, 24.9, 3.8, "02  Durable dispatch · asynchronous worker")
    panel(ax, .55, 1.15, 24.9, 4.45, "03  Per-scenario evaluation · evidence and response")

    card(ax, .85, 12.1, 2.65, 1.15, "Submit evaluation", "Workbench or REST client\nPOST /api/v1/evaluations", "blue", 9.2, 7.3)
    card(ax, 3.9, 12.1, 3.25, 1.15, "API boundary", "Trusted host · 1 MiB cap\nAPI key auth · rate limits", "blue", 9.3, 7.2)
    diamond(ax, 8.75, 12.67, 2.8, 1.5, "Credential valid\n+ role allowed?", "amber", 8.2)
    card(ax, 10.45, 14.1, 3.5, .85, "401 / 403", "Missing key or insufficient role", "red", 9, 7.3)
    card(ax, 11.95, 12.1, 3.4, 1.15, "Validate request", "Strict schema · known target\nAuthorized simulator · ≤ 50 cases", "blue", 9.2, 7.2)
    card(ax, 11.95, 10.7, 3.4, .85, "422 validation error", "Unknown IDs or invalid payload", "red", 8.8, 7)
    diamond(ax, 17.05, 12.67, 3, 1.5, "Idempotency\nkey exists?", "amber", 8.4)
    note(ax, 15.15, 14.1, 9, .85, "Same key + same body → reuse run     ·     Same key + changed body → 409", "amber", 8)
    database(ax, 20.45, 11.95, 4.25, 1.5, "PostgreSQL transaction",
             "Run + snapshots + policy ref, atomically\nAPI returns 202 + run ID")

    arrow(ax, (3.5, 12.67), (3.9, 12.67), color=C["blue"])
    arrow(ax, (7.15, 12.67), (7.35, 12.67), color=C["blue"])
    arrow(ax, (8.75, 13.42), (10.45, 14.1), "No", C["red"], rad=-.08, label_xy=(9.6, 13.92), size=6.8)
    arrow(ax, (10.15, 12.67), (11.95, 12.67), "Yes", C["green"], label_xy=(11.05, 12.95), size=6.8)
    arrow(ax, (13.65, 12.1), (13.65, 11.55), "invalid", C["red"], label_xy=(14.15, 11.84), size=6.5)
    arrow(ax, (15.35, 12.67), (15.55, 12.67), color=C["blue"])
    arrow(ax, (17.05, 13.42), (19.05, 14.1), "Yes", C["amber"], rad=.08, label_xy=(18.12, 13.93), size=6.7)
    arrow(ax, (18.55, 12.67), (20.45, 12.67), "No · new key", C["green"], label_xy=(19.5, 12.96), size=6.6)

    card(ax, .85, 7.4, 4.7, 1.2, "Local development", "FastAPI BackgroundTasks", "gray", 9.2, 7.4)
    card(ax, 6.15, 7.4, 4, 1.2, "Celery worker", "Per-run Redis lock · late ack\nRetries ≤ 5 · time limits", "blue", 9.2, 7.2)
    card(ax, 11, 7.4, 3.7, 1.2, "Redis 7 broker", "Task queue · run lock\nRate-limit counters", "teal", 9.2, 7.2)
    card(ax, 15.55, 7.4, 8.7, 1.2, "Production dispatch", "API immediate enqueue; Beat republishes pending outbox every 10 s", "blue", 9.2, 7.2)
    note(ax, 6.15, 6.35, 16.1, .65,
         "Infrastructure retries use exponential backoff; after 5 retries the run is FAILED. Cancellation is checked between cases.",
         "amber", 7.6)

    arrow(ax, (22.55, 11.95), (21.6, 8.6), "enqueue after commit", C["blue"], dashed=True, label_xy=(23.2, 10.25), size=6.8)
    arrow(ax, (15.55, 8), (14.7, 8), color=C["blue"], dashed=True)
    arrow(ax, (11, 8), (10.15, 8), color=C["blue"], dashed=True)

    card(ax, .85, 3.25, 3.65, 1.3, "Load run snapshot", "Stored scenario versions\nStored policy reference", "blue", 9.1, 7.3)
    card(ax, 4.85, 3.25, 3.4, 1.3, "Start next case", "Fresh state · check cancellation", "gray", 9, 7.2)
    diamond(ax, 9.95, 3.9, 3.2, 1.55, "Policy gate\nallows call?", "amber", 8.4)
    card(ax, 8.05, 1.55, 3.9, .95, "Denied", "Skip action · record reason", "red", 8.8, 7)
    card(ax, 13.65, 3.25, 3.3, 1.3, "Allowed action", "Run against fixture state", "green", 9, 7.2)
    card(ax, 17.25, 3.25, 3.4, 1.3, "Check outcome", "Postconditions + raw secret check\nRunner exception → ERROR; continue", "amber", 9, 7)
    card(ax, 20.95, 3.25, 3.8, 1.3, "Persist final outcome",
         "PASS / FAIL / ERROR / INCONCLUSIVE\nRedact evidence · workbench polls REST", "teal", 9, 7)

    arrow(ax, (8.15, 7.4), (2.68, 4.55), "load snapshots + policy", C["blue"], label_xy=(5.5, 5.92), size=7)
    arrow(ax, (3.2, 7.4), (2.68, 4.55), "local", C["muted"], dashed=True, rad=.1, label_xy=(2.5, 6.1), size=6.6)
    arrow(ax, (4.5, 3.9), (4.85, 3.9), color=C["blue"])
    arrow(ax, (8.25, 3.9), (8.35, 3.9), color=C["muted"])
    arrow(ax, (11.55, 3.9), (13.65, 3.9), "Allowed", C["green"], label_xy=(12.58, 4.18), size=6.8)
    arrow(ax, (9.95, 3.12), (9.95, 2.5), "Denied", C["red"], label_xy=(10.6, 2.82), size=6.8)
    arrow(ax, (11.95, 2.02), (17.25, 3.25), "continue case", C["red"], rad=-.1, label_xy=(14.8, 2.68), size=6.8)
    arrow(ax, (16.95, 3.9), (17.25, 3.9), color=C["muted"])
    arrow(ax, (20.65, 3.9), (20.95, 3.9), color=C["teal"])
    elbow(ax, [(24.75, 3.9), (25.2, 3.9), (25.2, 12.67), (24.7, 12.67)],
          "persist run outcome", C["teal"], label_xy=(25.2, 8.3), size=6.4)

    ax.text(.8, .55, "Solid arrows: request and case execution     ·     Dashed arrows: asynchronous dispatch, retry, or polling",
            color=C["muted"], fontsize=7.7, va="center")
    return finish(fig, "execution-flow")


if __name__ == "__main__":
    outputs = [*render_architecture(), *render_flow()]
    print("Rendered and validated:")
    for output in outputs:
        print(output)
