# Contributing to Shadow SSO

We appreciate your interest in contributing to Shadow SSO! This document outlines the process and guidelines for making contributions. By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1.  **Fork the Repository:**
    Click the "Fork" button at the top right of the repository's page on GitHub. This will create a copy of the repository under your GitHub account.

2.  **Clone Your Fork:**
    Clone your forked repository to your local machine:

    ```bash
    git clone https://github.com/your-username/shadow-sso.git
    ```

3.  **Set Up the Development Environment:**
    -   Make sure you have Go installed on your machine (`go version` to check if installed, instructions for downloading the binary can be found on official page at https://go.dev/dl/).
    -   Ensure that your `$GOPATH` environment variable is properly setup. If this is your first time using Golang the folder path must be created `mkdir -p $HOME/go/src`. The full path must be appended to environment variables of your OS by `export GOPATH=$HOME/go` or any preferred location. More can be found at [https://go.dev/doc/code#GOPATH](https://go.dev/doc/code#GOPATH) .
    - You also must check for `/bin` directory to `$PATH` environment variable (as same explained above, in the case of MacOs the `$HOME/go/bin` or alternative location should be specified for future use with packages) `export PATH=$PATH:$GOPATH/bin` .
    - Navigate to the project directory `cd shadow-sso`.
    - Make sure all the package dependencies are retrieved correctly running: `go mod tidy`.
4.  **Create a Branch:**
    Create a new branch for your changes:
     ```bash
     git checkout -b feature/your-feature-name
     ```

    Use descriptive branch names (e.g., `fix/typo-in-readme`, `feat/add-pkce-support`). This makes clear which area you intend to work in for quick approval from maintainers.

## Types of Contributions

We welcome various contributions:

-   **Bug Fixes:** Submit a fix for any discovered errors by creating and sending pull requests containing well-commented code that aims to solve current known bugs or future possible security vulnerabilities.
-   **Feature Requests and Implementations:** Have an exciting new feature in mind or want an existing feature extended? Feel free to create an issue with the feature implementation discussion/description or implementation request. In case an idea was accepted a clear feature implementation with documentation explaining in which area such features could have its best integration can help maintainers with analysis and code merge acceptance, remember code must adhere all formatting rules used across project codebase.
-   **Documentation:** Fix documentation bugs or clarify parts of the user manual, create some helpful sample implementations with code samples to be inserted as snippets to README files. You are very welcome to add valuable help improving project comprehensibility and usage to the average programmer or project leader to achieve desired project aims.
-   **Testing**: The code will only be as much reliable and tested with comprehensive testing implementations. Help with improving our automated tests suite can improve Shadow SSO package use scenarios for different needs and use cases. Any form of contribution using mocks, fake calls to external components or more comprehensive and efficient data setup testing flows.
-  **Security Research**: Found any possibility for better performance/scalability improvement or even more subtle implementation bug or logic problem? Create a research issue on a problem or provide proof-of-concept fixes. We treat any kind of research/proof seriously in order to keep this project a valuable and reliable library that can solve different problems from common software development environments.
-   **Code Reviews**:  Even if you don't know the code or intend to code you are very welcome to provide code quality review or analysis on code submitted via pull requests. Just try to point out improvements on code formatting or variable names or alternative implementations. We take suggestions from the community seriously and your opinion and ideas may matter and even provide insights.

## Development Process

1.  **Make Your Changes:**
    Implement your changes on your created branch with all required formatting. If needed create sub packages or restructure existing packages when is requested (in issue's details) during an idea discussion or feature proposal by maintainers, that's part of project implementation process too. Be thorough on this task, this package serves not only development use but also some form of integration and system architecture security decisions.

2.  **Test Your Changes:**
    Please make sure to create some reliable tests to your solution ensuring full security during any project evolution. This avoids many breaking changes after some time and guarantees robustness to future implementations, that was mentioned in test case submissions previously. Use testing techniques or different methodologies in the process of solving your problem in the most correct and suitable way to specific needs to the current development project, since we provide freedom on architecture decisions, as the final result meets quality assurance and best use. You can even create a small guide explaining better its approach on your documentation on pull request comments and descriptions when opening.

3. **Use Linter**: Shadow SSO utilizes Golang `golangci-lint` tool to make consistent the code base of project and all commits should adhere this rule when using any code quality rules used by default configurations in your setup/machine or even specific ones configured in CI workflows. Remember always check your solution to maintain coding quality before starting your merge. For installing or executing this tooling you can simply refer to official documentation [https://golangci-lint.run/](https://golangci-lint.run/) or you can also execute by CLI tool by using installed libraries to this kind of checks. Check by yourself what is most convenient method.

    ```bash
      # checking for erros before sending PR. Check linter rules and standards on current repo before committing the solution for compliance reasons.
      golangci-lint run
      # it is common during tests, create mocks/stubs before merging
      go install github.com/golang/mock/mockgen@latest
    ```

4.  **Commit Your Changes:**
    Commit your changes with descriptive messages, also consider add details of each stage to `commit` messages explaining your contribution with a meaningful explanation, in a similar style and syntax to [https://conventionalcommits.org/](https://conventionalcommits.org/):

    ```bash
        git add .
        git commit -m "fix(repository): Correctly store sessions."
    ```

5. **Update Documentation**: Make sure that any change applied by implementation is fully described and documented either on code and sample README sections. Explain main parts with good wording to new devs or other contributors.
6.  **Push to Your Fork:**
    Push your changes to your fork:

    ```bash
    git push origin feature/your-feature-name
    ```

7.  **Submit a Pull Request (PR):**
    - Go to the original repository on GitHub.
    - You will see a "Compare & pull request" button. Click on it to create a PR.
    - Add all additional informations of your intentions and goals on solution of presented bug or the features introduced, what methods you are planning to add and also some testing information. Add any questions if necessary on all steps used.
    - Be very descriptive and informative in all information added in each Pull request, any code added is the product and explanation is important part of solution to deliver the real desired solution or improvements.

8. **Get Code Reviews**: It is very common during some parts of development there are many suggestions or possible new improvement changes, try keep reviewing feedback seriously, try also to keep communications open during the discussions as part of PR review cycle until get code accepted as best possible outcome of review requests.

## Pull Request Guidelines

-   Keep PRs focused on a single logical change, this enhances the ability to review codes more efficiently from other teammates and reduces time required.
-   Provide a clear and concise description of your changes. The description must provide as much informations as required to correctly understanding implementation details of your changes, including what is the new behaviour added in specific area.
-   If your PR is solving any problem add it the associated issue or research case created on issue list or board projects (use keywords for cross-references #issueNumber). If such doesn't exist try always creating before any pull request if there is no such intention to make some important structural changes.
-   Ensure tests cover your changes by writing efficient test cases. Each code added to codebase must be covered and also validated using unit tests, testing mocks to external resources are useful here too if you don't want to execute on live instances of databases etc.. Use always good design patterns and always maintain code understandable, easy and concise to allow another developer contribute in case of necessary maintenance without effort in debugging implementation and understand which part they must make the needed code adjustment.
-   Address any review feedback you receive in your commit log. Remember to provide concise explanation of why the requests are being ignored during coding solution. Use a "fixup commit" and squash on the next PR update request or as an answer to request or feedback of any project maintainer involved to validate the pull requests during workflow review steps of coding cycle.
-   Use clear code styles, indentation with no spaces at ends of line or too much newlines. All guidelines must follow coding style as `golangci-lint` requirements that were specified above on development process step explanations on commit messages descriptions in markdown form of the project and in documentation pages, as best practices are requested and adopted here.

## Code of Conduct

This project and everyone participating in it is governed by the [Code of Conduct](CODE_OF_CONDUCT.md), also check for our best behaviors we strive to make this code base a professional community project on github.  By participating, you are expected to uphold this code. Please report any violations or misconduct to project maintainers.

## Contact

For specific issues, questions, or comments regarding your PRs or contributions send an email message directly to maintainers (`gyula@pilab.hu`) .  Join the community discussion channel too! Reach for the invite link to our Discord community. Your feedback is always valuable and most appreciated.

Thank you for your contributions! We look forward to your submissions and the new experiences!
