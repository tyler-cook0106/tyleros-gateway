export interface Env {}

export default {
  async fetch(request: Request, _env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.hostname === "dmz.tyleros.uk") {
      return new Response("TylerOS DMZ Gateway OK", {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=UTF-8",
        },
      });
    }

    if (url.hostname === "tyleros.uk") {
      return new Response("TylerOS Gateway OK", {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=UTF-8",
        },
      });
    }

    return new Response("Unknown TylerOS gateway hostname", {
      status: 404,
      headers: {
        "content-type": "text/plain; charset=UTF-8",
      },
    });
  },
};