import { FormEvent } from "react";

export async function GetAllPost() {
    try {
        const response = await fetch("https://eureka-blond.vercel.app/posts", {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        if (!response.ok) {
            console.error("Failed to fetch data:", response.statusText);
            return;
        }
        const result = await response.json();
        let l = [];
        for (const i of result) {
            let k = [];
            if (i.replies) {
                for (const reply of i.replies) {
                    k.push([reply.users.username, reply.content]);
                }
            }
            l.push({
                title: i.title || "",
                author: i.users?.username || "Unknown",
                desc: i.content || "",
                interested: i.interested?.[0]?.count || 0,
                tags: i.tags ? i.tags.split(",") : [],
                comments: k
            });
        }
    return(l);
    } catch (error) {
        console.error("Error fetching data:", error);
        return({
            title: "Title Not Loaded Properly",
            author: "Author",
            desc: "No Description",
            interested: 0,
            tags: ["AI", "ML", "Web", "DeepNet", "Blockchain"],
            comments: [[""]],
        })
    }
}


export async function AddAPost(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);

    const req = {
        title: data.get("title"),
        content: data.get("content"),
        tags: data.get("tags"),
    };

    if (!req.title || !req.content) {
        console.error("Title and content cannot be empty.");
        return;
    }

    try {
        const response = await fetch("https://eureka-blond.vercel.app/post", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(req),
        });

        if (!response.ok) {
            console.error("Failed to post:", response.statusText);
            return;
        }

        return GetAllPost();
    } catch (error) {
        console.error("Error posting:", error);
    }
}
