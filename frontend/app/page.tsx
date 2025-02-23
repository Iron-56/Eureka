"use client";
import Router, { useRouter } from "next/navigation";
import Image from "next/image";
import { Bell, Pencil, House, User } from "lucide-react";
import Link from "next/link";
import Dashboard from "./dashboard/page";

export default function Home() {
  const router = useRouter();
  return (
    <main className="font-sans">
      <div className="topbar w-full h-[10vh] flex items-center justify-between px-6 bg-white shadow-md">
        <div className="flex items-center gap-2">
          <Image
            src="/wmremove-transformed.png"
            alt="CollabIdeas Logo"
            width={200}
            height={50}
          />
        </div>
        <div className="flex items-center gap-8 mt-4 text-gray-500">
          <button
            className="flex flex-col justify-around items-center  hover:text-black"
            onClick={() => {
              router.push("/dashboard");
            }}
          >
            <Pencil className="w-6 h-6 text-gray-700 cursor-pointer" />
            <h1 className="text-md  font-bold mb-4">Dashboard</h1>
          </button>
          <button
            className="flex flex-col justify-around items-center  hover:text-black"
            onClick={() => {
              router.push("/dashboard");
            }}>
            <User className="w-6 h-6 text-gray-700 cursor-pointer" />
            <h1 className="text-md  font-bold mb-4">Login</h1>
          </button>
        </div>
      </div>
      <section className="hero h-[80vh] flex flex-col items-center justify-center text-center bg-gradient-to-r from-blue-500 to-purple-600 text-white">
        <h1 className="text-5xl font-bold mb-4">
          Unite Innovators and Creators
        </h1>
        <p className="text-xl mb-6">
          Share ideas, find collaborators, and bring projects to life.
        </p>
        <Link className="px-6 py-3 bg-white text-blue-600 font-semibold rounded-full shadow-md hover:bg-gray-100" href="/dashboard">
          Get Started
        </Link>
      </section>

      <section className="features py-12 bg-gray-100 text-black">
        <div className="container mx-auto text-center">
          <h2 className="text-3xl text-black font-bold mb-8">Platform Features</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="feature-item">
              <Pencil className="w-12 h-12 mx-auto text-blue-600 mb-4" />
              <h3 className="text-xl  font-semibold mb-2">Share Your Ideas</h3>
              <p >Post and categorize your innovative concepts to attract collaborators.</p>
            </div>
            <div className="feature-item">
              <User className="w-12 h-12  mx-auto text-blue-600 mb-4" />
              <h3 className="text-xl  font-semibold mb-2">Find Projects</h3>
              <p className="text-black">Explore projects that align with your skills and interests.</p>
            </div>
            <div className="feature-item">
              <Bell className="w-12 h-12 mx-auto text-blue-600 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Stay Updated</h3>
              <p>
                Receive notifications about project updates and new
                opportunities.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="how-it-works py-12">
        <div className="container mx-auto text-center">
          <h2 className="text-3xl font-bold mb-8">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="step-item">
              <div className="step-number text-4xl font-bold text-blue-600 mb-4">
                1
              </div>
              <h3 className="text-xl font-semibold mb-2">Sign Up</h3>
              <p>Create an account to join the community.</p>
            </div>
            <div className="step-item">
              <div className="step-number text-4xl font-bold text-blue-600 mb-4">
                2
              </div>
              <h3 className="text-xl font-semibold mb-2">
                Share or Explore Ideas
              </h3>
              <p>Post your own ideas or find projects that interest you.</p>
            </div>
            <div className="step-item">
              <div className="step-number text-4xl font-bold text-blue-600 mb-4">
                3
              </div>
              <h3 className="text-xl font-semibold mb-2">Collaborate</h3>
              <p>Connect with others and start working together.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="cta py-12 bg-blue-600 text-white text-center">
        <div className="container mx-auto">
          <h2 className="text-3xl font-bold mb-4">Ready to Collaborate?</h2>
          <p className="mb-6">
            Join CollabIdeas today and turn your ideas into reality.
          </p>
          <Link className="px-6 py-3 bg-white text-blue-600 font-semibold rounded-full shadow-md hover:bg-gray-100" href="/navigate">
          Join Now!
        </Link>
        </div>
      </section>
    </main>
  );
}
