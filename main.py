from mcp.server.fastmcp import FastMCP
import httpx
mcp = FastMCP("LeetCode MCP")


BACKEND_URL = "http://localhost:9000"

@mcp.tool()
async def get_profile(username: str):
    """
    Get the LeetCode profile of a connected user.
    """

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BACKEND_URL}/leetcode/profile/{username}"
        )

        response.raise_for_status()

        return response.json()

@mcp.tool()
async def review_latest_submission(username: str) -> dict:
    """
    Reviews the user's latest LeetCode submission.
    """

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BACKEND_URL}/leetcode/submission/review-latest-submission/{username}",
                timeout=60
            )

        response.raise_for_status()

        return response.json()

    except httpx.RequestError as e:
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    mcp.run( 
        transport="streamable-http",
        # host="0.0.0.0",
        # port=9000
    )
