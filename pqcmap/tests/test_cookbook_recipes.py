"""The cookbook's "after" snippets must keep working against the real backend.

Each recipe in docs/COOKBOOK.md is executed by examples/cookbook_recipes.py; this test
runs every one so the docs can't silently drift from the public API.
"""
import pytest

from examples import cookbook_recipes


@pytest.mark.parametrize("label,fn", cookbook_recipes.RECIPES, ids=[r[0].split()[0] for r in cookbook_recipes.RECIPES])
def test_cookbook_recipe(label, fn, tmp_path):
    import inspect

    if "tmp_path" in inspect.signature(fn).parameters:
        fn(tmp_path=tmp_path)
    else:
        fn()
