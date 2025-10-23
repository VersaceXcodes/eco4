-- Create tables with basic primitives and foreign key constraints
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    title VARCHAR(255) NOT NULL,
    content TEXT,
    image_url VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    post_id INTEGER NOT NULL REFERENCES posts(id),
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed users with plain text passwords
INSERT INTO users (username, email, password_hash) VALUES
('john_doe', 'john@example.com', 'password123'),
('jane_smith', 'jane@example.com', 'user123'),
('admin_user', 'admin@example.com', 'admin123'),
('sarah_connor', 'sarah@example.com', 'sarah123'),
('mike_tyson', 'mike@example.com', 'mike123');

-- Seed posts with random image URLs from picsum.photos
INSERT INTO posts (user_id, title, content, image_url) VALUES
(1, 'The Future of Technology', 'Exploring AI advancements...', 'https://picsum.photos/seed/post1/600/400'),
(1, 'Travel Diaries', 'Exploring new destinations...', 'https://picsum.photos/seed/post2/600/400'),
(2, 'Cooking Adventures', 'Mastering new recipes...', 'https://picsum.photos/seed/post3/600/400'),
(3, 'Admin Dashboard Tips', 'Optimizing backend systems...', 'https://picsum.photos/seed/post4/600/400'),
(4, 'Fitness Journey', 'Tracking progress...', 'https://picsum.photos/seed/post5/600/400'),
(5, 'Gaming Reviews', 'Latest game analysis...', 'https://picsum.photos/seed/post6/600/400');

-- Seed comments with varied content
INSERT INTO comments (user_id, post_id, content) VALUES
(1, 1, 'Great insights on AI development!'),
(2, 1, 'Would love to see more technical details'),
(3, 2, 'Your travel photos are amazing!'),
(4, 3, 'Pro tip: Try adding garlic to that recipe'),
(5, 4, 'Admin, your tips are always spot-on'),
(1, 5, 'Need more protein in your diet?'),
(2, 6, 'Just finished this game - 9/10!'),
(3, 5, 'Keep up the fitness motivation!'),
(4, 2, 'Next destination should be Japan'),
(5, 3, 'Can we get a video tutorial?');

-- Add additional relationships and sample engagement
INSERT INTO comments (user_id, post_id, content) VALUES
(1, 3, 'This recipe changed my life!'),
(2, 4, 'Database optimization is crucial'),
(3, 5, 'Gains looking good!'),
(4, 6, 'Game review saved me $60'),
(5, 1, 'AI will revolutionize everything'),
(1, 2, 'Bookmarked for future trips'),
(2, 3, 'Can''t wait for the next post!'),
(3, 4, 'Admin, you''re a legend'),
(4, 5, 'Motivation level: 100%'),
(5, 6, 'Game of the year contender');