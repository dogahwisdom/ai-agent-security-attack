from agent_security.exploration.prompt_catalog import PromptCatalog


def test_default_prompt_catalog_is_non_empty() -> None:
    catalog = PromptCatalog()
    assert len(catalog.prompts) > 0


def test_shell_prompt_catalog_differs_from_default() -> None:
    default = PromptCatalog(target_shell=False)
    shell = PromptCatalog(target_shell=True)
    assert default.prompts != shell.prompts
