from app import create_app


def test_enterprise_pages_render() -> None:
    app = create_app("testing")
    with app.test_client() as client:
        assert client.get("/reports").status_code == 200
        assert client.get("/settings").status_code == 200
        assert client.get("/about").status_code == 200
