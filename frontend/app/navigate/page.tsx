"use client";
import { LogIn } from "lucide-react";
import React, { useState } from "react";
import { Register, Login } from "./api";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [login, setLogin] = useState(false);
  const [signin, setSignin] = useState(true);
  const router = useRouter();

  function handlesign() {
    setLogin(false);
    setSignin(true);
  }

  function handlelogin() {
    setLogin(true);
    setSignin(false);
  }

  return (
    <div className="flex h-screen w-full bg-gradient-to-r from-blue-600 via-purple-600 to-pink-900 text-white">
      <div></div>
      <div className="flex flex-col justify-center items-center md:w-1/2 p-8">
        <div className="w-full max-w-sm">
          {signin && (
            <h1 className="text-4xl font-bold mb-7 text-left">Welcome</h1>
          )}
          {login && (
            <h1 className="text-4xl font-bold mb-7 text-left">Welcome back</h1>
          )}
          <form
            onSubmit={async (event) => {
              event.preventDefault(); // Prevent default form submission

              if (signin) {
                const status = await Register(event);
                if (status === 200) {
                  handlelogin(); // Switch to login view after registration
                }
              } else if (login) {
                const status = await Login(event);
                if (status === 200) {
                  router.push("/dashboard"); // Redirect to dashboard after successful login
                } else {
                  console.log("Login failed");
                }
              }
            }}
          >
            <>
              <label className="text-md font-semibold m-1">Email</label>
              <input
                type="email"
                placeholder="Enter email"
                name="email"
                className="w-full p-3 mb-4 rounded bg-white text-black border border-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </>
            {signin && (
              <>
                <label className="text-md font-semibold m-1">Username</label>
                <input
                  type="username"
                  name="username"
                  placeholder="Enter username"
                  className="w-full p-3 mb-4 rounded bg-white text-black border border-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </>
            )}
            <label className="text-md font-semibold m-1">Password</label>
            <input
              type="password"
              name="password"
              placeholder="Enter password"
              className="w-full p-3 mb-6 rounded bg-white text-black border border-white focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            {signin && (
              <button
                type="submit"
                className="w-full p-3 mb-6 bg-blue-600 border-white border-[.5px] shadow-lg rounded font-bold hover:bg-gray-50 hover:text-black transition"
              >
                Sign Up
              </button>
            )}
            {login && (
              <button
                type="submit"
                className="w-full p-3 mb-6 bg-blue-600 border-white border-[.5px] shadow-lg rounded font-bold hover:bg-gray-50 hover:text-black transition"
              >
                Login
              </button>
            )}
          </form>
          {login && (
            <p className="text-center font-semibold text-white mt-4">
              Don't have an account?{" "}
              <button className="text-blue-400" onClick={handlesign}>
                Sign up
              </button>
            </p>
          )}
          {signin && (
            <p className="text-center font-semibold text-white mt-4">
              Already have an account?{" "}
              <button className="text-blue-300" onClick={handlelogin}>
                Log In
              </button>
            </p>
          )}
        </div>
      </div>

      <div className="hidden md:flex w-1/2 justify-center items-stretch relative overflow-hidden">
        <div
          className="absolute w-full h-full bg-repeat"
          style={{
            backgroundImage: "url('/bg.svg')",
            animation: "bgScroll 40s linear infinite",
            backgroundSize: "100% auto",
            backgroundPosition: "top left",
          }}
        ></div>
      </div>

      <style jsx>{`
        @keyframes bgScroll {
          from {
            background-position: top left;
          }
          to {
            background-position: bottom left;
          }
        }
      `}</style>
    </div>
  );
}
