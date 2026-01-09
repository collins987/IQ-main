"""
Email template rendering service using Jinja2.
Provides reusable templates for password reset, verification emails, etc.
"""

from jinja2 import Environment, FileSystemLoader, TemplateNotFound


def get_template_env():
    """Initialize Jinja2 environment for templates."""
    return Environment(loader=FileSystemLoader("app/templates"))


def render_template(template_name: str, context: dict) -> str:
    """
    Render an email template with context data.
    
    Args:
        template_name: Name of template file (e.g., "password_reset.html")
        context: Dictionary of variables for template
    
    Returns:
        Rendered HTML string
    
    Raises:
        TemplateNotFound if template doesn't exist
    """
    env = get_template_env()
    template = env.get_template(template_name)
    return template.render(**context)
