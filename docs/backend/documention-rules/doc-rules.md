# Back-end Documentation Rules

**Created at:** 15 May 2024 | **Updated at:** [Date]

## Introduction

This Document is a document of how the Back end team is going to continue working with documentation, rules, suggestion and templates are going to be here.

## Types of Documentation

1. **Document of the code** - Which is for other people who are going to need your piece of code or responsible for making change
2. **System view** - Which has the flow data and input and output of the entire system
3. **Design document** - Which explain why a certain decision was made and what is the trade off
4. **Postmortem** - Which suggests why we had a failure and what is the step we are going to make to prevent it from happening
5. **Flowcharts for the flow of algorithm** - Visual representation of algorithm flow
6. **Tutorials** - Which are for learning
7. **Change document of algorithm** - Which we record changes that we made and the reason behind those changes (this is not a type its something we need to do in all documents)
8. **Idea/Plan Documentation** - Documentation of proposed ideas or plans

## Documentation Requirements

Each of these documents should go through these steps:

- Have internal policies or rules to be followed
- Be placed under source control
- Have clear ownership responsible for maintaining the docs
- Be periodically evaluated (tested, in some respect)

## Some Suggestions About Documentation Process

- **Centralized:** It's better for these documents to be centralized and easy to access
- **Structure:** It's good for documents to have some kind of structure like a normal essay writing
- **Template Standardization:** Templates for each type of documentation to ensure consistency across different documents
- **Version Control Integration:** Integrating documentation repository with version control systems like Git to track changes, revisions, and updates more effectively
- **Collaborative Editing:** Use tools or platforms that allow for collaborative editing and review of documents
- **Regular Audits and Reviews:** Schedule regular audits and reviews of documentation to ensure accuracy, relevance, and adherence to internal policies

## Structure of Document

- Document should have different paragraphs
- It should be simple and easy to read
- It should have the right balance between completeness and simpleness
- Each document should answer these questions: **WHO, WHAT, WHEN, WHY**
  - **Who:** This shows who is the audience
  - **What:** Defines the purpose of document
  - **When:** Identifies when this document was created, reviewed, or updated
  - **Why:** Says the purpose of document

## Template of Documents

### System View

**Title:** [Title of the Document]

**Audience:** System architects, developers, stakeholders

**Purpose:** To provide an overview of the entire system, including its data flow, input/output mechanisms, and overall architecture.

**Structure:**

1. **Introduction**
   - Overview of the system
   - The goal and purpose of the system

2. **System Architecture**
   - High-level architecture diagram
   - Description of components and their interactions

3. **Data Flow**
   - Explanation of how data flows through the system
   - Input and output specifications

4. **Dependencies**
   - External dependencies and integrations

5. **References**
   - Links to detailed design documents or specifications
   - It should have reference to design documents

---

### Design Document

**Title:** [Title of the Document]

**Audience:** Developers, stakeholders

**Purpose:** To explain the rationale behind design decisions, including trade-offs, considerations, and implications.

**Structure:**

1. **Introduction**
   - Overview of the design document
   - Purpose and scope

2. **Design Decisions**
   - Explanation of key design decisions
   - Trade-offs and considerations

3. **Architecture Overview**
   - High-level architecture diagram / flowchart
   - Component interactions

4. **Implementation Details**
   - Technologies used
   - Design patterns and principles applied

5. **Future Considerations**
   - Potential areas for improvement or expansion

6. **References**
   - Links to related documents
   - It should have reference to system view
   - It could have reference to flowcharts

---

### Postmortem

**Title:** [Title of the Document]

**Audience:** Development team, stakeholders

**Purpose:** To analyze the causes of a failure, identify preventive measures, and improve system reliability.

**Structure:**

1. **Introduction**
   - Overview of the incident
   - Purpose of the postmortem

2. **Incident Timeline**
   - Sequence of events leading up to the failure

3. **Root Cause Analysis**
   - Identification of underlying causes

4. **Lessons Learned**
   - Key takeaways from the incident
   - Areas for improvement

5. **Preventive Measures**
   - Steps we should take to prevent similar incidents in the future

6. **References**
   - Links to incident reports, logs, or related documents
   - It should have reference to design or flowchart

---

### Flowcharts for the Flow of Algorithm

**Title:** [Title of the Flowchart]

**Audience:** Developers, data scientists, or anyone needing a visual representation of algorithm flow

**Purpose:** To illustrate the flow of the algorithm, including input, processing steps, and output.

**Structure:**

1. **Flowchart Overview**
   - Brief description of the algorithm

2. **Flowchart Diagram**
   - Visual representation of the algorithm flow

3. **Explanation**
   - Detailed explanation of each step in the flowchart

4. **Inputs and Outputs**
   - Description of input data and expected output

5. **Decision Points**
   - Explanation of decision points and branching logic

6. **References**
   - Links to related documentation or resources
   - It can have reference to design document

---

### Tutorials

**Title:** [Title of the Tutorial]

**Audience:** Beginners, learners, or anyone seeking guidance on using or understanding a specific topic or tool

**Purpose:** To provide step-by-step instructions and explanations for learning a particular subject or skill.

**Structure:**

1. **Introduction**
   - Overview of the tutorial
   - Learning objectives

2. **Prerequisites**
   - Required knowledge or skills

3. **Tutorial Steps**
   - Step-by-step instructions with screenshots or code snippets
   - Explanation of each step

4. **Examples**
   - Additional examples or exercises for practice

5. **Troubleshooting**
   - Common issues and solutions

6. **References**
   - Links to related resources or further reading
   - It can have reference to system design or idea

---

### Idea/Plan Documentation

**Title:** [Title of the Idea/Plan]

**Audience:** Team members, stakeholders

**Purpose:** To document proposed ideas or plans, track their implementation, and evaluate their success or failure.

**Structure:**

1. **Introduction**
   - Overview of the idea or plan
   - Background information or context

2. **Objectives**
   - Clear and measurable objectives or goals

3. **Implementation Plan**
   - Steps or actions required to execute the idea or plan
   - Timeline and deadlines

4. **Resources**
   - Required resources such as budget, manpower, tools, etc.

5. **Risk Analysis**
   - Potential risks or challenges and mitigation strategies

6. **Evaluation Criteria**
   - Criteria for evaluating the success or failure of the idea/plan
   - Assessment of the outcomes against the defined objectives and success metrics

7. **Lessons Learned**
   - Key takeaways from the implementation

8. **Recommendations**
   - Recommendations for future actions or improvements based on the outcomes

9. **References**
   - Links to related documents, research, or data supporting the idea/plan
   - Can have reference to system view
   - Can have reference to design

---

## Changes After Review

**Document of code has been deleted.** This decision was made based on other documents that we have and the ability we have to write a self documented code or use comments or readme files throughout the project itself. (This itself can be a design document)

## Comments for Edit

### System View Discussion

- Terminology considerations should be discussed and standardized

---

## Additional Rules

- **Timely Documentation:** Documentation should be created alongside the completion of tasks whenever necessary. This ensures that the information is accurate and up-to-date.
- **Review and Confirmation:** Every piece of documentation must be reviewed and confirmed by team leaders to ensure its accuracy and completeness.
- **Decision Making:** The need for documentation should be determined collaboratively by team members, based on the significance and complexity of the task.
- **Database Documentation:** In case of database updates, the ER Diagram and collection detail should be updated. (ERD link)
- **Clarity and Simplicity:** Each part of the documentation should be clear, simple, and easy to understand. Avoid jargon and ensure that the content is accessible to its intended audience.
