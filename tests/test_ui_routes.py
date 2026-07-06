from app import create_app


def test_dashboard_and_pages_render() -> None:
    app = create_app("testing")
    with app.test_client() as client:
        assert client.get("/", follow_redirects=True).status_code == 200
        assert client.get("/scan").status_code == 200
        assert client.get("/history").status_code == 200
        assert client.get("/analytics").status_code == 200


def test_scan_form_validation() -> None:
    app = create_app("testing")
    with app.test_client() as client:
        response = client.post(
            "/scan",
            data={"host": "", "start_port": "1", "end_port": "0", "threads": "2"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Host/IP is required" in response.data


def test_not_found_page() -> None:
    app = create_app("testing")
    with app.test_client() as client:
        response = client.get("/missing")
        assert response.status_code == 404
