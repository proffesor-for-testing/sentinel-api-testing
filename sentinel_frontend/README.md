# Sentinel Frontend - Enhanced Reporting UI

This is the React-based frontend for the Sentinel API Testing Platform, providing comprehensive reporting and analysis capabilities for Phase 3 enhanced features.

## Features

### Phase 3 Enhanced Reporting
- **Advanced Dashboard**: Real-time analytics with charts and statistics
- **Detailed Test Run Analysis**: Comprehensive failure analysis and insights
- **Agent-Specific Insights**: Specialized reporting for different agent types
- **Interactive Test Case Browser**: Filter and analyze generated test cases
- **Enhanced Failure Analysis**: Detailed breakdown of negative and stateful test results

### Key Components

#### Dashboard (`/`)
- System overview with key metrics
- Agent distribution charts
- Recent test runs visualization
- Success rate tracking
- Phase 3 feature highlights

#### Test Runs (`/test-runs`)
- Complete test execution history
- Filtering and search capabilities
- Success rate visualization
- Quick access to detailed results

#### Test Run Details (`/test-runs/:id`)
- Comprehensive test result analysis
- Request/response inspection
- Failure analysis with agent-specific insights
- Test type categorization (BVA, Negative, Stateful, Positive)
- Enhanced error reporting

#### Specifications (`/specifications`)
- API specification management
- Upload interface for OpenAPI specs
- Quick test execution
- Phase 3 agent integration

#### Test Cases (`/test-cases`)
- Browse all generated test cases
- Filter by agent type and specification
- Detailed test case inspection
- Agent-specific insights and strategies

## Technology Stack

- **React 18**: Modern React with hooks and functional components
- **React Router**: Client-side routing
- **Tailwind CSS**: Utility-first CSS framework
- **Recharts**: Data visualization and charts
- **Lucide React**: Modern icon library
- **Axios**: HTTP client for API communication

## Getting Started

### Prerequisites
- Node.js 16+ and npm
- Sentinel backend services running on `http://localhost:8080`

### Installation

1. Install dependencies:
```bash
cd sentinel_frontend
npm install
```

2. Start the development server:
```bash
npm start
```

3. Open [http://localhost:3000](http://localhost:3000) in your browser

### Environment Configuration

Create a `.env` file in the root directory to customize the API URL:

```env
REACT_APP_API_URL=http://localhost:8080
```

## Phase 3 Enhanced Features

### Advanced Test Analysis
- **Boundary Value Analysis (BVA)**: Visual indicators and insights for boundary tests
- **Negative Testing**: Enhanced failure analysis for invalid input validation
- **Stateful Testing**: Multi-step workflow visualization and state management insights
- **Test Type Classification**: Automatic categorization with visual indicators

### Enhanced Reporting
- **Failure Analysis**: Detailed breakdown of why tests failed
- **Agent Insights**: Specialized reporting based on agent type
- **Test Strategy Visualization**: Clear indication of testing approaches
- **Interactive Details**: Expandable test case and result inspection

### User Experience Improvements
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Updates**: Live data refresh capabilities
- **Intuitive Navigation**: Clear information architecture
- **Visual Feedback**: Loading states, error handling, and success indicators

## API Integration

The frontend communicates with the Sentinel backend through a comprehensive API service layer:

- **Specifications**: Upload, list, and manage OpenAPI specs
- **Test Generation**: Trigger test case generation with multiple agents
- **Test Execution**: Run tests and monitor progress
- **Results Analysis**: Fetch and display detailed test results
- **Dashboard Analytics**: Aggregate statistics and insights

## Development

### Project Structure
```
src/
├── components/          # Reusable UI components
│   └── Layout.js       # Main application layout
├── pages/              # Page components
│   ├── Dashboard.js    # Main dashboard
│   ├── TestRuns.js     # Test runs list
│   ├── TestRunDetail.js # Detailed test results
│   ├── Specifications.js # API spec management
│   └── TestCases.js    # Test case browser
├── services/           # API integration
│   └── api.js         # API service layer
├── App.js             # Main application component
├── index.js           # Application entry point
└── index.css          # Global styles and Tailwind imports
```

### Styling
The application uses Tailwind CSS with custom utility classes defined in `index.css`:
- Custom color palette for consistent branding
- Reusable component classes (cards, buttons, badges)
- Responsive design utilities
- Animation and transition classes

### Build and Deployment

Build for production:
```bash
npm run build
```

The build artifacts will be in the `build/` directory, ready for deployment to any static hosting service.

## Phase 3 Completion

This frontend completes the Phase 3 implementation by providing:

✅ **Enhanced Reporting UI** with detailed failure analysis
✅ **Agent-Specific Insights** for all three agent types
✅ **Interactive Test Result Exploration** with expandable details
✅ **Comprehensive Dashboard** with real-time analytics
✅ **Advanced Filtering and Search** capabilities
✅ **Responsive Design** for all device types

The enhanced reporting UI provides the visibility and insights needed to understand the advanced testing capabilities introduced in Phase 3, including boundary value analysis, creative negative testing, and stateful workflow validation.
