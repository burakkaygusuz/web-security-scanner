#!/bin/bash
#
# Setup script for installing Git hooks for Java code formatting
# Run this script to install pre-commit and pre-push hooks
#

echo "🔧 Setting up Git hooks for Google Java Format..."

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Error: This script must be run from the root of a Git repository"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
#
# Git pre-commit hook for Java code formatting validation
# This hook checks if Java files are properly formatted before commit
#

echo "Checking Java code formatting..."

# Run format check
if mvn com.spotify.fmt:fmt-maven-plugin:check -q; then
    echo "✅ All Java files are properly formatted!"
    exit 0
else
    echo "❌ Some Java files are not properly formatted!"
    echo ""
    echo "🔧 To fix formatting issues, run:"
    echo "   mvn com.spotify.fmt:fmt-maven-plugin:format"
    echo ""
    echo "Then add the changes and commit again:"
    echo "   git add -u"
    echo "   git commit"
    echo ""
    exit 1
fi
EOF

# Create pre-push hook
cat > .git/hooks/pre-push << 'EOF'
#!/bin/sh
#
# Git pre-push hook for automatic Java code formatting
# This hook runs Google Java Format before pushing to remote repository
#

echo "Running Google Java Format..."

# Run the formatter
mvn com.spotify.fmt:fmt-maven-plugin:format -q

# Check if any files were modified by the formatter
if ! git diff --quiet; then
    echo "Code was automatically formatted. Committing changes..."
    
    # Add all modified Java files to staging
    git add -u
    
    # Automatically commit the formatted code
    git commit -m "chore: auto-format Java code with Google Java Format"
    
    echo "✅ Code formatting completed and committed automatically!"
    echo "📝 Formatted code has been committed with message: 'chore: auto-format Java code with Google Java Format'"
    echo "🚀 Continuing with push..."
    echo ""
else
    echo "✅ Code is already properly formatted!"
fi

exit 0
EOF

# Make hooks executable
chmod +x .git/hooks/pre-commit
chmod +x .git/hooks/pre-push

echo "✅ Git hooks installed successfully!"
echo ""
echo "📋 Hooks installed:"
echo "   - pre-commit: Validates code formatting before commits"
echo "   - pre-push: Automatically formats and commits code before pushes"
echo ""
echo "🎯 Usage:"
echo "   - Commit as usual: git commit -m 'message'"
echo "   - Push as usual: git push origin main"
echo ""
echo "💡 To manually format code:"
echo "   mvn com.spotify.fmt:fmt-maven-plugin:format"
echo ""
echo "🔍 To check formatting:"
echo "   mvn com.spotify.fmt:fmt-maven-plugin:check"
