import { FormEvent } from "react";


export async function Register(event: FormEvent<HTMLFormElement>) {
    try {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        const req={
            username:data.get('username'),
            email:data.get('email'),
            password:data.get('password'),
        }
        const response = await fetch("http://127.0.0.1:5000/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(req)
        });
        if (!response.ok) {
            console.error("Failed to fetch data:", response.statusText);
            return 400;
        }
        return 200;
    } catch (error) {
        console.error("Error fetching data:", error);
        return 400;
    }
}


export async function Login(event: FormEvent<HTMLFormElement>) {
    try {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        const req={
            email:data.get('email'),
            password:data.get('password'),
        }
        const response = await fetch("http://127.0.0.1:5000/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(req)
        });
        if (!response.ok) {
            console.error("Failed to fetch data:", response.statusText);
            return 400;
        }
        return 200;
    } catch (error) {
        console.error("Error fetching data:", error);
        return 400;
    }
}
