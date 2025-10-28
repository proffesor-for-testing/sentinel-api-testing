"""Test backward compatibility of deprecated agents."""
import warnings
import pytest


def test_functional_positive_agent_deprecation():
    """Test that FunctionalPositiveAgent shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent

        # Should have deprecation warning
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "deprecated" in str(w[0].message).lower()


def test_functional_negative_agent_deprecation():
    """Test that FunctionalNegativeAgent shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)


def test_security_auth_agent_deprecation():
    """Test that SecurityAuthAgent shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)


def test_security_injection_agent_deprecation():
    """Test that SecurityInjectionAgent shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)


def test_old_agent_still_works():
    """Test that old agent API still functions."""
    from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
    from sentinel_backend.data_service.models.spec import APISpec

    agent = FunctionalPositiveAgent()

    # Create minimal spec
    spec = APISpec(
        api_name="Test API",
        base_url="http://test.com",
        version="1.0",
        paths={
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    )

    # Should still work
    result = agent.execute(spec)
    assert result.status == "success"
    assert len(result.test_cases) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
