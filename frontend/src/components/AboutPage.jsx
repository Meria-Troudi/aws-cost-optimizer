const WORKFLOW_STEPS = [
  {
    title: 'Billing Data',
    body: 'AWS Cost Explorer provides billing and usage data used to identify relevant cost drivers.',
  },
  {
    title: 'Cost-Driven Collection',
    body: 'The system determines which AWS resources require investigation based on the observed costs.',
  },
  {
    title: 'Evidence Collection',
    body: 'Only the utilization, configuration, dependencies, topology, and activity evidence required for analysis is collected.',
  },
  {
    title: 'Cost Reconciliation',
    body: 'Billing records are matched with discovered resources whenever possible, while historical and unmatched costs are identified.',
  },
  {
    title: 'Analysis Engine',
    body: 'Service-specific analyzers evaluate the collected evidence against defined cost conditions.',
  },
  {
    title: 'Findings',
    body: 'Potential cost optimization conditions are identified and supported by collected evidence.',
  },
  {
    title: 'Recommendations',
    body: 'Optimization actions are generated from supported findings, with evidence and financial context where available.',
  },
]

const PRINCIPLES = [
  'Do not optimize a resource simply because it exists.',
  'Do not assume low utilization without utilization evidence.',
  'Do not assume a resource is unused without checking relevant activity.',
  'Reconcile billing data with resource evidence.',
  'Distinguish current resources from historical billing resources.',
  'Do not treat estimated savings as guaranteed savings.',
  'Report incomplete evidence instead of presenting unsupported conclusions.',
]

export default function AboutPage() {
  return (
    <div className="about-page">
      <div className="header-row">
        <div className="headline">
          <div className="eyebrow">/ About</div>
          <h1>Explain CostLensAWS</h1>
          <div className="sub">What is this system and how does it work?</div>
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
          CostLensAWS is an evidence-based AWS cost analysis platform designed to identify
          cost drivers, investigate the resources responsible for AWS expenditure, detect
          potential optimization conditions, and generate actionable recommendations.
        </p>
      </section>

      {/* Workflow and Core Principle sit side-by-side: the steps explain
          *how* the system works, the principles explain *why* it's
          trustworthy while doing it — reading them together makes the
          case better than stacking them as two unrelated panels. */}
      <div className="about-columns section-gap">

        <section className="panel about-workflow">
          <h2 className="panel-title">How CostLensAWS works</h2>

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
          <h2 className="panel-title">Core principle</h2>

          <p className="about-principle-statement">Evidence before recommendation.</p>

          <ul className="about-principle-list">
            {PRINCIPLES.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>

      </div>

      <section className="panel section-gap about-intro about-aws-native">
        <h2 className="panel-title">AWS-native recommendations</h2>

        <p>
          CostLensAWS also surfaces read-only recommendations from AWS Cost
          Explorer and AWS Compute Optimizer alongside its own findings.
          These are external, AWS-generated optimization signals — an
          additional decision input, not something CostLensAWS's analyzer
          produced or verified.
        </p>
      </section>
    </div>
  )
}
