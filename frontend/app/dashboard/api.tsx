import { FormEvent } from "react";

export async function GetAllPost() {
    try {
        const response = await fetch("http://127.0.0.1:5000/posts", {
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
    try {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        console.log(data);
        const req={
        }
        console.log(req);
        const response = await fetch("http://127.0.0.1:5000/post", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(req)
        });
        if (!response.ok) {
            console.error("Failed to fetch data:", response.statusText);
            return;
        }
        const result = await response.json();
        return(GetAllPost());
    } catch (error) {
        console.error("Error fetching data:", error);
        return([{
            title: "Title Not Loaded Properly",
            author: "Author",
            desc: "No Description",
            interested: 0,
            tags: ["AI", "ML", "Web", "DeepNet", "Blockchain"],
            comments: [[""]],
        }])
    }
}
