-- Database setup for Health Check App
-- Run this script in MySQL to create the necessary tables

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS health_check;
USE health_check;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create health_data table with user_id foreign key
CREATE TABLE IF NOT EXISTS health_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    name VARCHAR(255),
    age INT,
    height DECIMAL(5,2),
    weight DECIMAL(5,2),
    systolic INT,
    diastolic INT,
    spo2 INT,
    bmi DECIMAL(4,2),
    weight_category VARCHAR(50),
    blood_category VARCHAR(100),
    spo2_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert sample data (optional)
INSERT INTO users (name, email, password) VALUES
('Admin User', 'admin@healthcheck.com', '$2b$10$example.hash.here'); -- This will be replaced with actual hashed password

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_health_data_user_id ON health_data(user_id);
CREATE INDEX idx_health_data_created_at ON health_data(created_at);
