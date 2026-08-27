import datetime
import flask
import os
import random
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Callable, Literal
from zoneinfo import ZoneInfo

from saifguard.agent import SAIFGuardAgent
from saifguard.config import MODEL, TIMEZONE


import mesop as me

Role = Literal["user", "bot"]


_APP_TITLE = "SAIFGuard"
_BOT_AVATAR_LETTER = "S"
_EMPTY_CHAT_MESSAGE = "Get started with an example"
_EXAMPLE_USER_QUERIES = (
  "What is SAIFGuard?",
  "Secure my design.",
  "Inspect my GCP project and analyze security failures.",
)
_CHAT_MAX_WIDTH = "800px"
_MOBILE_BREAKPOINT = 640

agent = SAIFGuardAgent()


def _current_timestamp() -> str:
  try:
    tz = ZoneInfo(TIMEZONE)
    return datetime.datetime.now(tz).strftime("%H:%M")
  except Exception:
    return datetime.datetime.now().strftime("%H:%M")


@dataclass(kw_only=True)
class ChatMessage:
  """Chat message metadata."""

  role: Role = "user"
  content: str = ""
  edited: bool = False
  model: str = ""
  timestamp: str = ""
  # 1 is positive
  # -1 is negative
  # 0 is no rating
  rating: int = 0


@me.stateclass
class State:
  input: str = ""
  output: list[ChatMessage]
  in_progress: bool = False
  sidebar_expanded: bool = False
  selected_model: str = MODEL
  user_id: str = ""
  current_session_id: str = ""
  sessions: list[dict]


def _extract_user_id(state: State) -> str:
  """Extract user identity from Google IAP headers, query parameters, or browser session."""
  # 1. Google Cloud Identity-Aware Proxy (IAP) Headers
  try:
    if flask.has_request_context():
      iap_email = flask.request.headers.get("X-Goog-Authenticated-User-Email")
      if iap_email:
        clean_email = iap_email.split(":")[-1].strip().lower()
        if clean_email:
          return clean_email

      iap_user_id = flask.request.headers.get("X-Goog-Authenticated-User-Id")
      if iap_user_id:
        clean_id = iap_user_id.split(":")[-1].strip()
        if clean_id:
          return f"iap_{clean_id}"
  except Exception:
    pass

  # 2. URL query parameters (e.g. ?user=user@company.com)
  try:
    user_param = me.query_params.get("user")
    if user_param and user_param.strip():
      return user_param.strip()
  except Exception:
    pass

  # 3. Existing state.user_id if already set
  if state.user_id and state.user_id != "user_default":
    return state.user_id

  # 4. Fallback: generate a unique ID for this browser profile
  return f"user_{uuid.uuid4().hex[:8]}"


def _refresh_sessions_and_load_latest(state: State):
  raw_sessions = agent.list_user_sessions(user_id=state.user_id)
  state.sessions = raw_sessions
  if state.sessions:
    state.current_session_id = state.sessions[0]["session_id"]
    _load_session(state, state.current_session_id)
  else:
    state.current_session_id = agent.create_user_session(state.user_id)
    state.output = []


def _load_session(state: State, session_id: str):
  if not session_id:
    state.output = []
    return
  try:
    raw_messages = agent.get_session_messages(user_id=state.user_id, session_id=session_id)
    if raw_messages:
      state.output = [
        ChatMessage(
          role=m.get("role", "user"),
          content=str(m.get("content", "")),
          model=str(state.selected_model or MODEL),
          timestamp=str(m.get("timestamp") or _current_timestamp()),
        )
        for m in raw_messages
        if isinstance(m, dict) and m.get("content")
      ]
    else:
      state.output = []
  except Exception:
    state.output = []


def respond_to_chat(input: str):
  state = me.state(State)
  selected_model = getattr(state, "selected_model", None) or MODEL
  if not state.current_session_id:
    state.current_session_id = f"session_{uuid.uuid4().hex[:10]}"

  response = agent.invoke(
    user_id=state.user_id,
    session_id=state.current_session_id,
    message=input,
    model=selected_model,
  )
  for line in response:
    time.sleep(0.05)
    yield line + " "


def on_load(e: me.LoadEvent):
  me.set_theme_mode("system")
  state = me.state(State)
  state.user_id = _extract_user_id(state)
  if not state.current_session_id:
    _refresh_sessions_and_load_latest(state)


@me.page(
  security_policy=me.SecurityPolicy(
    allowed_iframe_parents=["https://mesop-dev.github.io"]
  ),
  title="SAIFGuard Application",
  path="/",
  on_load=on_load,
)
def page():
  state = me.state(State)

  with me.box(
    style=me.Style(
      background=me.theme_var("surface-container-lowest"),
      display="flex",
      flex_direction="column",
      height="100vh",
      overflow="hidden",
    )
  ):
    with me.box(
      style=me.Style(
        display="flex",
        flex_direction="row",
        flex_grow=1,
        height="100%",
        overflow="hidden",
      )
    ):
      with me.box(
        style=me.Style(
          background=me.theme_var("surface-container-low"),
          display="flex",
          flex_direction="column",
          flex_shrink=0,
          position="absolute"
          if state.sidebar_expanded and _is_mobile()
          else None,
          height="100%" if state.sidebar_expanded and _is_mobile() else None,
          width=300 if state.sidebar_expanded else 60,
          z_index=2000,
          overflow_y="auto",
        )
      ):
        sidebar()

      with me.box(
        style=me.Style(
          display="flex",
          flex_direction="column",
          flex_grow=1,
          height="100%",
          overflow="hidden",
          padding=me.Padding(left=60)
          if state.sidebar_expanded and _is_mobile()
          else None,
        )
      ):
        with me.box(style=me.Style(flex_shrink=0)):
          header()

        with me.box(
          style=me.Style(
            flex_grow=1,
            height=0,
            overflow_y="auto",
            display="flex",
            flex_direction="column",
          )
        ):
          if state.output:
            chat_pane()
          else:
            examples_pane()

        with me.box(style=me.Style(flex_shrink=0)):
          chat_input()


def sidebar():
  state = me.state(State)
  with me.box(
    style=me.Style(
      display="flex",
      flex_direction="column",
      flex_grow=1,
    )
  ):
    with me.box(style=me.Style(display="flex", gap=20)):
      menu_icon(icon="menu", tooltip="Menu", on_click=on_click_menu_icon)
      if state.sidebar_expanded:
        me.text(
          _APP_TITLE,
          style=me.Style(margin=me.Margin(bottom=0, top=14)),
          type="headline-6",
        )

    if state.sidebar_expanded:
      menu_item(icon="add", label="New chat", on_click=on_click_new_chat)
    else:
      menu_icon(icon="add", tooltip="New chat", on_click=on_click_new_chat)

    if state.sidebar_expanded:
      session_list_pane()


def session_list_pane():
  state = me.state(State)
  if not state.sessions:
    with me.box(
      style=me.Style(
        padding=me.Padding.all(15),
        color=me.theme_var("outline"),
      )
    ):
      me.text("No previous sessions", style=me.Style(font_size=13, font_style="italic"))
    return

  for session in state.sessions:
    s_id = session.get("session_id", "")
    is_active = (s_id == state.current_session_id)
    title = session.get("title") or f"Session {s_id[:8]}"
    with me.box(
      key=f"session-{s_id}",
      on_click=on_click_session,
      style=me.Style(
        background=me.theme_var("surface-container-high")
        if is_active
        else me.theme_var("surface-container"),
        border=me.Border.all(
          me.BorderSide(
            width=2 if is_active else 1,
            color=me.theme_var("primary")
            if is_active
            else me.theme_var("outline-variant"),
            style="solid",
          )
        ),
        border_radius=8,
        cursor="not-allowed" if state.in_progress else "pointer",
        opacity=0.6 if (state.in_progress and not is_active) else 1.0,
        margin=me.Margin.symmetric(horizontal=10, vertical=5),
        padding=me.Padding.all(10),
        display="flex",
        align_items="center",
        gap=8,
      ),
    ):
      me.icon(
        "chat_bubble_outline",
        style=me.Style(
          font_size=18,
          color=me.theme_var("primary")
          if is_active
          else me.theme_var("outline"),
        ),
      )
      me.text(
        _truncate_text(title, 28),
        style=me.Style(
          font_weight="bold" if is_active else "normal",
          font_size=13,
        ),
      )


def on_model_selection_change(e: me.SelectSelectionChangeEvent):
  state = me.state(State)
  state.selected_model = e.value


def header():
  state = me.state(State)
  with me.box(
    style=me.Style(
      align_items="center",
      background=me.theme_var("surface-container-lowest"),
      display="flex",
      gap=10,
      justify_content="space-between",
      padding=me.Padding.symmetric(horizontal=20, vertical=10),
    )
  ):
    with me.box(style=me.Style(display="flex", gap=5, align_items="center")):
      if not state.sidebar_expanded:
        me.text(
          _APP_TITLE,
          style=me.Style(margin=me.Margin(bottom=0)),
          type="headline-6",
        )

      me.select(
        label="Model",
        options=[
          me.SelectOption(label="Gemini 3.7 Flash", value="gemini-3.7-flash"),
          me.SelectOption(label="Gemini 3.6 Flash", value="gemini-3.6-flash"),
          me.SelectOption(label="Gemini 3.5 Flash", value="gemini-3.5-flash"),
          me.SelectOption(label="Gemini 3.5 Flash Lite", value="gemini-3.5-flash-lite"),
          me.SelectOption(label="Gemini 3.1 Pro", value="gemini-3.1-pro"),
        ],
        value=state.selected_model or "gemini-3.7-flash",
        on_selection_change=on_model_selection_change,
        style=me.Style(width="220px"),
      )
      icon_button(
        key="btn_generate_dashboard",
        icon="analytics",
        tooltip="Generate / Update Data Studio Dashboard",
        on_click=on_click_header_dashboard,
      )
      icon_button(
        key="",
        icon="dark_mode" if me.theme_brightness() == "light" else "light_mode",
        tooltip="Dark mode"
        if me.theme_brightness() == "light"
        else "Light mode",
        on_click=on_click_theme_brightness,
      )


def examples_pane():
  with me.box(
    style=me.Style(
      margin=me.Margin.symmetric(horizontal="auto"),
      padding=me.Padding.all(15),
      width=f"min({_CHAT_MAX_WIDTH}, 100%)",
    )
  ):
    with me.box(style=me.Style(margin=me.Margin(top=25), font_size=24)):
      me.text(_EMPTY_CHAT_MESSAGE)

    with me.box(
      style=me.Style(
        display="flex",
        flex_direction="column" if _is_mobile() else "row",
        gap=20,
        margin=me.Margin(top=25),
      )
    ):
      for index, query in enumerate(_EXAMPLE_USER_QUERIES):
        with me.box(
          key=f"query-{index}",
          on_click=on_click_example_user_query,
          style=me.Style(
            background=me.theme_var("surface-container-highest"),
            border_radius=15,
            padding=me.Padding.all(20),
            cursor="pointer",
          ),
        ):
          me.text(query)


def chat_pane():
  state = me.state(State)
  with me.box(
    style=me.Style(
      background=me.theme_var("surface-container-lowest"),
      color=me.theme_var("on-surface"),
      display="flex",
      flex_direction="column",
      margin=me.Margin.symmetric(horizontal="auto"),
      padding=me.Padding.all(15),
      width=f"min({_CHAT_MAX_WIDTH}, 100%)",
    )
  ):
    for index, msg in enumerate(state.output):
      if msg.role == "user":
        user_message(message=msg)
      else:
        if not msg.content.strip().startswith("*tool*:"):
            bot_message(message_index=index, message=msg)

    if state.in_progress:
      with me.box(key="scroll-to", style=me.Style(height=250)):
        pass


def user_message(*, message: ChatMessage):
  with me.box(
    style=me.Style(
      display="flex",
      flex_direction="column",
      align_items="flex-end",
      margin=me.Margin.all(20),
    )
  ):
    with me.box(
      style=me.Style(
        background=me.theme_var("surface-container-low"),
        border_radius=10,
        color=me.theme_var("on-surface-variant"),
        padding=me.Padding.symmetric(vertical=0, horizontal=10),
        width="66%",
      )
    ):
      me.markdown(message.content)
    if message.timestamp:
      me.text(
        message.timestamp,
        style=me.Style(
          color=me.theme_var("outline"),
          font_size=11,
          margin=me.Margin(top=4, right=4),
          opacity=0.75,
        ),
      )


def bot_message(*, message_index: int, message: ChatMessage):
  with me.box(style=me.Style(display="flex", gap=15, margin=me.Margin.all(20))):
    text_avatar(
      background=me.theme_var("primary"),
      color=me.theme_var("on-primary"),
      label=_BOT_AVATAR_LETTER,
    )

    # Bot message response
    with me.box(style=me.Style(display="flex", flex_direction="column")):
      me.markdown(
        message.content,
        style=me.Style(color=me.theme_var("on-surface")),
      )

      # Actions & metadata panel
      with me.box(style=me.Style(display="flex", align_items="center", gap=15, margin=me.Margin(top=5))):
        with me.box(style=me.Style(display="flex")):
          icon_button(
            key=f"thumb_up-{message_index}",
            icon="thumb_up",
            is_selected=message.rating == 1,
            tooltip="Good response",
            on_click=on_click_thumb_up,
          )
          icon_button(
            key=f"thumb_down-{message_index}",
            icon="thumb_down",
            is_selected=message.rating == -1,
            tooltip="Bad response",
            on_click=on_click_thumb_down,
          )
          icon_button(
            key=f"restart-{message_index}",
            icon="restart_alt",
            tooltip="Regenerate answer",
            on_click=on_click_regenerate,
          )
          icon_button(
            key=f"dashboard-{message_index}",
            icon="analytics",
            tooltip="Publish / Update Data Studio Dashboard",
            on_click=on_click_publish_msg_dashboard,
          )
        metadata_parts = []
        if message.model:
          metadata_parts.append(f"Model: {message.model}")
        if message.timestamp:
          metadata_parts.append(message.timestamp)

        if metadata_parts:
          me.text(
            " • ".join(metadata_parts),
            style=me.Style(
              color=me.theme_var("outline"),
              font_size=12,
              font_style="italic",
              opacity=0.75,
            ),
          )


def chat_input():
  state = me.state(State)
  with me.box(
    style=me.Style(
      background=me.theme_var("surface-container"),
      border_radius=16,
      display="flex",
      align_items="center",
      margin=me.Margin.symmetric(horizontal="auto", vertical=10),
      padding=me.Padding(top=4, bottom=4, left=12, right=8),
      width=f"min({_CHAT_MAX_WIDTH}, 90%)",
    )
  ):
    with me.box(
      style=me.Style(
        flex_grow=1,
      )
    ):
      me.native_textarea(
        autosize=True,
        key="chat_input",
        min_rows=2,
        max_rows=6,
        on_blur=on_chat_input,
        shortcuts={
          me.Shortcut(shift=True, key="Enter"): on_submit_chat_msg,
        },
        placeholder="Enter your prompt",
        style=me.Style(
          background=me.theme_var("surface-container"),
          border=me.Border.all(
            me.BorderSide(style="none"),
          ),
          color=me.theme_var("on-surface-variant"),
          outline="none",
          overflow_y="auto",
          padding=me.Padding(top=8, bottom=8, left=4),
          width="100%",
        ),
        value=state.input,
      )
    with me.content_button(
      disabled=state.in_progress,
      on_click=on_click_submit_chat_msg,
      type="icon",
    ):
      me.icon("send")


@me.component
def text_avatar(*, label: str, background: str, color: str):
  me.text(
    label,
    style=me.Style(
      background=background,
      border_radius="50%",
      color=color,
      font_size=20,
      height=40,
      line_height="1",
      margin=me.Margin(top=16),
      padding=me.Padding(top=10),
      text_align="center",
      width="40px",
    ),
  )


@me.component
def icon_button(
  *,
  icon: str,
  tooltip: str,
  key: str = "",
  is_selected: bool = False,
  on_click: Callable | None = None,
):
  selected_style = me.Style(
    background=me.theme_var("surface-container-low"),
    color=me.theme_var("on-surface-variant"),
  )
  with me.tooltip(message=tooltip):
    with me.content_button(
      type="icon",
      key=key,
      on_click=on_click,
      style=selected_style if is_selected else None,
    ):
      me.icon(icon)


@me.component
def menu_icon(
  *, icon: str, tooltip: str, key: str = "", on_click: Callable | None = None
):
  with me.tooltip(message=tooltip):
    with me.content_button(
      key=key,
      on_click=on_click,
      style=me.Style(margin=me.Margin.all(10)),
      type="icon",
    ):
      me.icon(icon)


@me.component
def menu_item(
  *, icon: str, label: str, key: str = "", on_click: Callable | None = None
):
  with me.box(on_click=on_click):
    with me.box(
      style=me.Style(
        background=me.theme_var("surface-container-high"),
        border_radius=20,
        cursor="pointer",
        display="inline-flex",
        gap=10,
        line_height=1,
        margin=me.Margin.all(10),
        padding=me.Padding(top=10, left=10, right=20, bottom=10),
      ),
    ):
      me.icon(icon)
      me.text(label, style=me.Style(height=24, line_height="24px"))


# Event Handlers


def on_click_example_user_query(e: me.ClickEvent):
  """Populates the user input with the example query"""
  state = me.state(State)
  if state.in_progress:
    return
  _, example_index = e.key.split("-")
  state.input = _EXAMPLE_USER_QUERIES[int(example_index)]
  me.focus_component(key="chat_input")


def on_click_header_dashboard(e: me.ClickEvent):
  """Populates user prompt to trigger dashboard generation."""
  state = me.state(State)
  if state.in_progress:
    return
  state.input = "Publish the latest security audit findings to the Data Studio BigQuery dashboard."
  me.focus_component(key="chat_input")


def on_click_publish_msg_dashboard(e: me.ClickEvent):
  """Populates user prompt to publish a specific message's findings to the dashboard."""
  state = me.state(State)
  if state.in_progress:
    return
  _, msg_index = e.key.split("-")
  msg_index = int(msg_index)
  target_msg = state.output[msg_index]
  state.input = f"Publish the following security audit findings to the Data Studio BigQuery dashboard:\n\n{target_msg.content}"
  me.focus_component(key="chat_input")


def on_click_thumb_up(e: me.ClickEvent):
  """Gives the message a positive rating"""
  state = me.state(State)
  _, msg_index = e.key.split("-")
  msg_index = int(msg_index)
  state.output[msg_index].rating = 1


def on_click_thumb_down(e: me.ClickEvent):
  """Gives the message a negative rating"""
  state = me.state(State)
  _, msg_index = e.key.split("-")
  msg_index = int(msg_index)
  state.output[msg_index].rating = -1


def on_click_new_chat(e: me.ClickEvent):
  """Starts a new chat session."""
  state = me.state(State)
  if state.in_progress:
    return
  state.current_session_id = agent.create_user_session(state.user_id)
  state.output = []
  me.focus_component(key="chat_input")


def on_click_session(e: me.ClickEvent):
  """Loads existing chat from Agent Platform Sessions."""
  state = me.state(State)
  if state.in_progress:
    return
  raw_key = str(getattr(e, "key", "") or "")
  session_id = raw_key.removeprefix("session-").strip()
  if session_id and session_id != state.current_session_id:
    state.current_session_id = session_id
    _load_session(state, session_id)
  me.focus_component(key="chat_input")


def on_click_theme_brightness(e: me.ClickEvent):
  """Toggles dark mode."""
  if me.theme_brightness() == "light":
    me.set_theme_mode("dark")
  else:
    me.set_theme_mode("light")


def on_click_menu_icon(e: me.ClickEvent):
  """Expands and collapses sidebar menu."""
  state = me.state(State)
  state.sidebar_expanded = not state.sidebar_expanded


def on_chat_input(e: me.InputBlurEvent):
  """Capture chat text input on blur."""
  state = me.state(State)
  state.input = e.value


def _format_progress_card(progress_steps: list[str]) -> str:
  formatted_steps = [f"> * {s}" for s in progress_steps]
  steps_md = "\n>\n".join(formatted_steps)
  return f"**Security Audit in Progress...**\n>\n{steps_md}"


def on_click_regenerate(e: me.ClickEvent):
  """Regenerates response from an existing message"""
  state = me.state(State)
  if state.in_progress:
    return
  _, msg_index = e.key.split("-")
  msg_index = int(msg_index)

  # Get the user message which is the previous message
  user_message = state.output[msg_index - 1]
  # Get bot message to be regenerated
  assistant_message = state.output[msg_index]
  assistant_message.content = ""
  state.in_progress = True
  yield

  start_time = time.time()
  output_message = respond_to_chat(user_message.content)
  progress_steps: list[str] = []

  for content in output_message:
    is_tool_response = content.strip().startswith("*tool*:")
    is_progress_message = content.strip().startswith("*progress*:")

    if is_tool_response:
      continue
    elif is_progress_message:
      progress_text = content.strip().removeprefix("*progress*:").strip()
      if progress_text and progress_text not in progress_steps:
        progress_steps.append(progress_text)
      assistant_message.content = _format_progress_card(progress_steps)
      yield
    else:
      if assistant_message.content.startswith("> 🔄 **Security Audit in Progress..."):
        assistant_message.content = content
      else:
        assistant_message.content += content

      if (time.time() - start_time) >= 0.15:
        start_time = time.time()
        yield

  state.in_progress = False
  me.focus_component(key="chat_input")
  yield


def on_submit_chat_msg(e: me.TextareaShortcutEvent):
  state = me.state(State)
  state.input = e.value
  yield
  yield from _submit_chat_msg()


def on_click_submit_chat_msg(e: me.ClickEvent):
  yield from _submit_chat_msg()


def _submit_chat_msg():
  """Handles submitting a chat message."""
  state = me.state(State)
  if state.in_progress or not state.input:
    return

  # Ensure active session ID
  if not state.current_session_id:
    state.current_session_id = agent.create_user_session(state.user_id)

  active_session_id = state.current_session_id
  user_input = state.input
  session_title = _clean_session_title(user_input, 32)

  # Check if session exists in sidebar list, or update title from user's first query
  found_session = False
  for s in state.sessions:
    if s.get("session_id") == state.current_session_id:
      found_session = True
      # If current title is generic, update it with user's query summary
      if s.get("title", "").startswith("Session ") or s.get("title") == "New Chat":
        s["title"] = session_title
      break

  if not found_session:
    new_session_entry = {
      "session_id": state.current_session_id,
      "title": session_title,
      "last_update_time": time.time(),
    }
    state.sessions.insert(0, new_session_entry)

  # 1. Add the user's message to the output and clear the input field
  state.output.append(
    ChatMessage(role="user", content=user_input, timestamp=_current_timestamp())
  )
  state.input = ""
  state.in_progress = True
  me.scroll_into_view(key="scroll-to")
  yield

  # 2. Get the agent's response generator
  response_generator = respond_to_chat(user_input)

  # This variable will point to the message we are actively streaming the final answer into.
  current_final_message = None
  progress_steps: list[str] = []

  selected_model = getattr(state, "selected_model", "") or MODEL

  for chunk in response_generator:
    # Abort if the session was switched concurrently
    if state.current_session_id != active_session_id:
      break

    is_tool_response = chunk.strip().startswith("*tool*:")
    is_progress_message = chunk.strip().startswith("*progress*:")

    if is_tool_response:
      # If this is a tool response, add it as a new, complete message.
      state.output.append(ChatMessage(role="bot", content=chunk.strip()))
      current_final_message = None
      yield
    elif is_progress_message:
      progress_text = chunk.strip().removeprefix("*progress*:").strip()
      if progress_text and progress_text not in progress_steps:
        progress_steps.append(progress_text)
      progress_card = _format_progress_card(progress_steps)
      if current_final_message is None:
        new_message = ChatMessage(
          role="bot",
          content=progress_card,
          model=selected_model,
          timestamp=_current_timestamp(),
        )
        state.output.append(new_message)
        current_final_message = new_message
      else:
        current_final_message.content = progress_card
      yield
    else:
      # This is a chunk of the final, visible agent answer.
      if current_final_message is None:
        new_message = ChatMessage(
          role="bot",
          content=chunk,
          model=selected_model,
          timestamp=_current_timestamp(),
        )
        state.output.append(new_message)
        current_final_message = new_message
      else:
        if current_final_message.content.startswith("> 🔄 **Security Audit in Progress..."):
          current_final_message.content = chunk
        else:
          current_final_message.content += chunk
      yield

  state.in_progress = False
  me.focus_component(key="chat_input")
  yield


# Helpers


def _is_mobile():
  return me.viewport_size().width < _MOBILE_BREAKPOINT


def _truncate_text(text, char_limit=100):
  """Truncates text that is too long."""
  if not text:
    return ""
  text_str = str(text)
  if len(text_str) <= char_limit:
    return text_str
  truncated_text = text_str[:char_limit].rsplit(" ", 1)[0]
  return truncated_text.rstrip(".,!?;:") + "..."


def _clean_session_title(text: str, char_limit: int = 32) -> str:
  """Generates a clean human-readable title from the first user query."""
  if not text:
    return "New chat"
  # Take first non-empty line
  lines = [line.strip() for line in str(text).splitlines() if line.strip()]
  if not lines:
    return "New chat"
  first_line = lines[0]
  # Strip leading prompt/markdown characters
  clean = first_line.lstrip("#* `>-").strip()
  if len(clean) <= char_limit:
    return clean
  truncated = clean[:char_limit].rsplit(" ", 1)[0]
  return truncated.rstrip(".,!?;:-") + "..."
