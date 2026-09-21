import base64, math, json
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont


def _normalize_chains(raw, cause_principale=""):
    """Normalize legacy values and the AT-compatible tree for PDF drawing."""
    if not raw:
        return []

    if isinstance(raw, dict) and isinstance(raw.get("causes"), list):
        chains = []
        for cause in raw["causes"]:
            if not isinstance(cause, dict):
                continue
            label = str(cause.get("label") or "").strip()
            for branch in cause.get("branches", []):
                values = branch.get("pourquoi", []) if isinstance(branch, dict) else branch
                values = list(values) if isinstance(values, list) else [values]
                values = [str(value or "") for value in values[:5]]
                values.extend([""] * (5 - len(values)))
                if any(value.strip() for value in values) or label:
                    chains.append({
                        "chain": [{"pourquoi": value} for value in values[:4]],
                        "justification": values[4],
                        "cause_label": label,
                    })
        return chains

    if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], list):
        chains = []
        for branch in raw:
            values = [str(s or "") for s in branch[:5]]
            values.extend([""] * (5 - len(values)))
            chain_nodes = [{"pourquoi": s} for s in values[:4]]
            p5 = values[4].strip()
            justif = p5 or cause_principale
            if chain_nodes or justif:
                chains.append({"chain": chain_nodes, "justification": justif})
        return chains

    if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], dict) and "chain" in raw[0]:
        result = []
        for item in raw:
            chain = item.get("chain") or []
            result.append({
                "chain": [{"pourquoi": str(node.get("pourquoi", "") if isinstance(node, dict) else node or "")} for node in chain[:4]],
                "justification": str(item.get("justification") or ""),
            })
        return result

    if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], dict) and "pourquoi" in raw[0]:
        chain = [{"pourquoi": d.get("pourquoi", "")} for d in raw if d.get("pourquoi")]
        if chain:
            return [{"chain": chain, "justification": cause_principale}]
        return []

    if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], str):
        chain = [{"pourquoi": s} for s in raw if s]
        if chain:
            return [{"chain": chain, "justification": cause_principale}]
        return []

    return []


def draw_wrapped_text(draw, x, y, width, height, text, font, fill="#002060", line_spacing=26):
    """Draw text wrapped inside a bounding box with proper padding and vertical centering.
    
    Guarantees no newline characters exist in individual line strings to prevent PIL anchor errors.
    """
    if not text:
        return

    lines = []
    for paragraph in str(text).splitlines():
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current_line = ""
        for w in words:
            test_line = f"{current_line} {w}" if current_line else w
            bbox = draw.textbbox((0, 0), test_line, font=font)
            line_w = bbox[2] - bbox[0]
            if line_w <= width - 18:
                current_line = test_line
            else:
                if current_line:
                    lines.append(current_line)
                current_line = w
        if current_line:
            lines.append(current_line)

    if not lines:
        return

    total_h = len(lines) * line_spacing
    start_y = y + max(8, (height - total_h) // 2)
    for l in lines:
        if l:
            draw.text((x + width // 2, start_y), l, font=font, fill=fill, anchor="mt")
        start_y += line_spacing


def draw_arrow_connector(draw, x1, y1, x2, y2, color="#305496", width=8, arrow_size=22):
    """Draw a bold connector line with a clean arrowhead terminating exactly at (x2, y2)."""
    dx = x2 - x1
    dy = y2 - y1
    dist = math.hypot(dx, dy)
    if dist < 2:
        return
    ux, uy = dx / dist, dy / dist
    px, py = -uy, ux

    stop_x = x2 - ux * arrow_size
    stop_y = y2 - uy * arrow_size
    draw.line([(x1, y1), (stop_x, stop_y)], fill=color, width=width)

    p1 = (x2, y2)
    p2 = (x2 - ux * arrow_size + px * (arrow_size * 0.65), y2 - uy * arrow_size + py * (arrow_size * 0.65))
    p3 = (x2 - ux * arrow_size - px * (arrow_size * 0.65), y2 - uy * arrow_size - py * (arrow_size * 0.65))
    draw.polygon([p1, p2, p3], fill=color)


def _draw_chain_row(draw, item, col_x, col_w, row_y, box_h,
                    color_blue_bg, color_blue_border, color_blue_text,
                    color_pink_bg, color_pink_border, color_pink_text,
                    font_node_bold):
    """Draw a single horizontal chain row of up to 5 Pourquoi boxes + 1 conclusion box."""
    chain = item.get('chain', []) if isinstance(item, dict) else []
    conc = item.get('justification', '') if isinstance(item, dict) else ''
    if not chain and not conc:
        return

    cy = row_y
    box_cy = cy + box_h // 2

    # Draw arrows between consecutive boxes
    for c_idx in range(len(chain) - 1):
        if c_idx < 4:
            src_right_x = col_x[c_idx] + col_w[c_idx]
            tgt_left_x = col_x[c_idx + 1]
            draw_arrow_connector(draw, src_right_x, box_cy, tgt_left_x, box_cy, color=color_blue_border)

    # Arrow from last chain box to conclusion box (column 4)
    if len(chain) > 0 and len(chain) <= 4:
        last_idx = len(chain) - 1
        src_right_x = col_x[last_idx] + col_w[last_idx]
        tgt_left_x = col_x[4]
        draw_arrow_connector(draw, src_right_x, box_cy, tgt_left_x, box_cy, color=color_blue_border)

    # Chain boxes (cols 0..3 or 0..4)
    for c_idx in range(min(len(chain), 4)):
        txt = chain[c_idx].get('pourquoi', '') if isinstance(chain[c_idx], dict) else str(chain[c_idx])
        if txt:
            cx = col_x[c_idx]
            cw = col_w[c_idx]
            draw.rounded_rectangle([(cx, cy), (cx + cw, cy + box_h)], radius=14, fill=color_blue_bg, outline=color_blue_border, width=3)
            draw_wrapped_text(draw, cx, cy, cw, box_h, txt, font_node_bold, fill=color_blue_text, line_spacing=26)

    # Conclusion box (column 4 - Pink/Orange Box)
    if not conc and len(chain) >= 5:
        conc = chain[4].get('pourquoi', '') if isinstance(chain[4], dict) else str(chain[4])

    if conc:
        cx = col_x[4]
        cw = col_w[4]
        draw.rounded_rectangle([(cx, cy), (cx + cw, cy + box_h)], radius=14, fill=color_pink_bg, outline=color_pink_border, width=4)
        draw_wrapped_text(draw, cx, cy, cw, box_h, conc, font_node_bold, fill=color_pink_text, line_spacing=26)

def generate_d4_diagram_base64(analyse_d4=None):
    """Render every AT-shaped Doc.83 branch without dropping existing values."""
    try:
        font_title = ImageFont.truetype("arialbd.ttf", 38)
        font_sec = ImageFont.truetype("arialbd.ttf", 32)
        font_head = ImageFont.truetype("arialbd.ttf", 26)
        font_node = ImageFont.truetype("arialbd.ttf", 21)
        font_small = ImageFont.truetype("arialbi.ttf", 21)
        font_footer = ImageFont.truetype("arialbd.ttf", 22)
    except Exception:
        font_title = font_sec = font_head = font_node = font_small = font_footer = ImageFont.load_default()

    col_x = [25, 290, 545, 800, 1055]
    col_w = [230, 220, 220, 220, 320]
    box_h = 175
    row_step = 195
    blue_bg, blue_border, blue_text = "#d9e1f2", "#305496", "#002060"
    orange_bg, orange_border, orange_text = "#fce4d6", "#c65911", "#000000"

    nd_raw = getattr(analyse_d4, "pourquoi_non_detection", []) if analyse_d4 else []
    tech_raw = getattr(analyse_d4, "pourquoi_technique", []) if analyse_d4 else []
    nd_synth = getattr(analyse_d4, "cause_principale_non_detection", "") if analyse_d4 else ""
    tech_synth = getattr(analyse_d4, "cause_principale_technique", "") if analyse_d4 else ""
    nd_rows = _normalize_chains(nd_raw, nd_synth)
    tech_rows = _normalize_chains(tech_raw, tech_synth)

    nd_count = max(len(nd_rows), 1)
    tech_count = max(len(tech_rows), 1)
    d41_start = 265
    d42_title_y = max(855, d41_start + nd_count * row_step + 60)
    d42_header_y = d42_title_y + 125
    d42_start = d42_header_y + 65
    instruction_y = d42_start + tech_count * row_step + 30
    footer_y = instruction_y + 95
    img = Image.new("RGB", (1400, footer_y + 50), (255, 255, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(25, 15), (1375, 80)], outline="#000000", width=4)
    draw.text((700, 48), "D 4.1 à D 4.2", font=font_title, fill="#000000", anchor="mm")

    def draw_headers(y):
        labels = ["1er POURQUOI?", "2ème POURQUOI?", "3ème POURQUOI?", "4ème POURQUOI?"]
        for idx, label in enumerate(labels):
            draw.text((col_x[idx] + col_w[idx] // 2, y), label, font=font_head, fill="#000000", anchor="mm")
        draw.text((col_x[4] + col_w[4] // 2, y - 10), "5ème POURQUOI /", font=font_head, fill="#000000", anchor="mm")
        draw.text((col_x[4] + col_w[4] // 2, y + 15), "CAUSE RACINE", font=font_head, fill="#000000", anchor="mm")

    def draw_empty_row(y):
        for idx in range(4):
            draw.rounded_rectangle([(col_x[idx], y), (col_x[idx] + col_w[idx], y + box_h)], radius=14, fill=blue_bg, outline=blue_border, width=3)
        draw.rounded_rectangle([(col_x[4], y), (col_x[4] + col_w[4], y + box_h)], radius=14, fill=orange_bg, outline=orange_border, width=4)

    def draw_axis(title, title_y, header_y, rows, synth):
        draw.text((25, title_y), title, font=font_sec, fill="#000000")
        draw.rectangle([(25, title_y + 40), (1375, title_y + 95)], fill="#ffff00", outline="#000000", width=3)
        cause_labels = []
        for row in rows:
            label = str(row.get("cause_label") or "").strip()
            if label and label not in cause_labels:
                cause_labels.append(label)
        cause_text = " / ".join(cause_labels) or str(synth or "") or "Cause favorite"
        draw.text((700, title_y + 68), cause_text, font=font_head, fill="#000000", anchor="mm")
        draw_headers(header_y)
        if not rows:
            draw_empty_row(header_y + 40)
        else:
            for idx, item in enumerate(rows):
                _draw_chain_row(
                    draw, item, col_x, col_w, header_y + 40 + idx * row_step, box_h,
                    blue_bg, blue_border, blue_text,
                    orange_bg, orange_border, orange_text, font_node,
                )

    draw_axis("D 4.1 - NON DETECTION", 100, 225, nd_rows, nd_synth)
    draw_axis("D 4.2 - CAUSE TECHNIQUE", d42_title_y, d42_header_y, tech_rows, tech_synth)

    draw.rectangle([(25, instruction_y), (1375, instruction_y + 75)], fill="#ffffff", outline="#000000", width=3)
    instruction_text = "A chaque étape du 5 pourquoi, vérifier avec les données que le lien de cause à effet soit effectif. Se demander pourquoi ? Autant de fois que nécessaire."
    draw_wrapped_text(draw, 25, instruction_y, 1350, 75, instruction_text, font_small, fill="#000000", line_spacing=24)
    draw.text((25, footer_y), "D4.1 D4.2", font=font_footer, fill="#000000")

    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")
