const WORKFLOW_STEPS = [
  {
    title: 'Cost Analysis',
    body: 'Analyze AWS billing data to identify major cost drivers.',
  },
  {
    title: 'Targeted Collection',
    body: 'Collect relevant resource, utilization, configuration, and activity data.',
  },
  {
    title: 'Cost Reconciliation',
    body: 'Match billing records with resources and identify historical or unmatched costs.',
  },
  {
    title: 'Evidence-Based Analysis',
    body: 'Evaluate collected evidence to identify potential optimization opportunities.',
  },
  {
    title: 'Recommendations',
    body: 'Present actionable optimizations with supporting evidence and estimated savings.',
  },
]

const PRINCIPLES = [
  'Evidence before recommendations.',
  'No assumptions about resource usage or potential savings.',
  'Billing costs must be reconciled with resource data.',
  'Incomplete evidence and historical resources must be clearly identified.',
]

export default function AboutPage() {
  return (
    <div className="about-page">
      <div className="header-row">
        <div className="headline">
          <div className="eyebrow">/ About</div>
        </div>
      </div>

      <section className="panel section-gap about-intro">
        <h2 className="panel-title">
          CostLensAWS
          <span className="about-subtitle">
            AWS Cost Optimization and Intelligent Recommendation System
          </span>
        </h2>

        <p>
          CostLensAWS analyzes AWS spending, investigates the resources
          behind costs, and provides evidence-based recommendations to
          optimize cloud expenditure without compromising reliability.
        </p>
      </section>

      <div className="about-columns section-gap">
        <section className="panel about-workflow">
          <h2 className="panel-title">How It Works</h2>

          <ol className="about-steps">
            {WORKFLOW_STEPS.map((step, index) => (
              <li className="about-step" key={step.title}>
                <span className="about-step-index">{index + 1}</span>
                <div>
                  <strong>{step.title}</strong>
                  <p>{step.body}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section className="panel about-principle">
          <h2 className="panel-title">Core Principles</h2>

          <p className="about-principle-statement">
            Evidence before recommendation.
          </p>

          <ul className="about-principle-list">
            {PRINCIPLES.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel section-gap about-intro about-aws-native">
        <h2 className="panel-title">AWS-Native Insights</h2>

        <p>
          CostLensAWS also displays recommendations from AWS Cost Explorer
          and Compute Optimizer, complementing its own analysis with
          AWS-generated insights.
        </p>
      </section>
    </div>
  )
}