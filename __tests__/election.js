/* eslint-disable no-undef */
const request = require("supertest");
const cheerio = require("cheerio");
const db = require("../models/index");
const app = require("../app");
// eslint-disable-next-line no-unused-vars
const { response } = require("../app");

let server, agent;

function extractCsrfToken(res) {
  var $ = cheerio.load(res.text);
  return $("[name=_csrf]").val();
}

const login = async (agent, username, password) => {
  let res = await agent.get("/login");
  let csrfToken = extractCsrfToken(res);
  res = await agent.post("/session").send({
    email: username,
    password: password,
    _csrf: csrfToken,
  });
};

describe("Online Voting application test suite", function () {
  beforeAll(async () => {
    server = app.listen(5000, () => {});
    agent = request.agent(server);
  });

  afterAll(async () => {
    try {
      await db.sequelize.close();
      await server.close();
    } catch (error) {
      console.log(error);
    }
  });

  test("New User Sign up", async () => {
    res = await agent.get("/signup");
    const csrfToken = extractCsrfToken(res);
    res = await agent.post("/admin").send({
      firstName: "Rohit",
      lastName: "Avadhanula",
      email: "rohit@test.com",
      password: "12345678",
      _csrf: csrfToken,
    });
    expect(res.statusCode).toBe(302);
  });
  test("Existing User login", async () => {
    res = await agent.get("/elections");
    expect(res.statusCode).toBe(200);
    await login(agent, "rohit@test.com", "12345678");
    res = await agent.get("/elections");
    expect(res.statusCode).toBe(200);
  });
  test("Signout your account", async () => {
    let res = await agent.get("/elections");
    expect(res.statusCode).toBe(200);
    res = await agent.get("/signout");
    expect(res.statusCode).toBe(302);
    res = await agent.get("/elections");
    expect(res.statusCode).toBe(302);
  });
  test("Create New  election", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    const res = await agent.get("/addquestion");
    const csrfToken = extractCsrfToken(res);
    const response = await agent.post("/elections").send({
      electionName: "new_election",
      publicurl: "election-url1",
      _csrf: csrfToken,
    });
    expect(response.statusCode).toBe(302);
  });
 test("Adding New question in MANAGE QUESTION", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "vote your leader",
      publicurl: "election-url2",
      _csrf: csrfToken,
    });
    const groupedResponse = await agent
      .get("/elections")
      .set("Accept", "Application/json");
    const parsedResponse = JSON.parse(groupedResponse.text);
    console.log(parsedResponse);
    const electionCount = parsedResponse.elections_list.length;
    const latestElection = parsedResponse.elections_list[electionCount - 1];
    res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    res = await agent.post(`/createquestions/${latestElection.id}`).send({
      questionname: "CHOOSE YOUR CLASS LEADER",
      description: "VOTE",
      _csrf: csrfToken,
    });
    expect(res.statusCode).toBe(302);
  });
 test("Deleting question", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "FAVOURATE SPORTS",
      publicurl: "election-url3",
      _csrf: csrfToken,
    });
    const ElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "Application/json");
    const parsedResponse = JSON.parse(ElectionsResponse.text);
    const electionCount = parsedResponse.elections_list.length;
    const latestElection = parsedResponse.elections_list[electionCount - 1];
    res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/createquestions/${latestElection.id}`).send({
      questionname: "Monitoring",
      description: "players",
      _csrf: csrfToken,
    });
   res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/createquestions/${latestElection.id}`).send({
      question: "Best",
      description: "Fit",
      _csrf: csrfToken,
    });
   const groupedResponse = await agent
      .get(`/questions/${latestElection.id}`)
      .set("Accept", "application/json");
    const parsedquestionsGroupedResponse = JSON.parse(groupedResponse.text);
    const questionCount = parsedquestionsGroupedResponse.questions1.length;
    const latestQuestion =
      parsedquestionsGroupedResponse.questions1[questionCount - 1];
    res = await agent.get(`/questions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    const deleteResponse = await agent
      .delete(`/deletequestion/${latestQuestion.id}`)
      .send({
        _csrf: csrfToken,
      });
    console.log(deleteResponse.text);
    const parsedDeleteResponse = JSON.parse(deleteResponse.text);
    expect(parsedDeleteResponse.success).toBe(true);
    res = await agent.get(`/questions/${latestQuestion.id}`);
    csrfToken = extractCsrfToken(res);
    const deleteResponse2 = await agent
      .delete(`/deletequestion/${latestElection.id}`)
      .send({
        _csrf: csrfToken,
      });
    const parsedDeleteResponse2 = JSON.parse(deleteResponse2.text).success;
    expect(parsedDeleteResponse2).toBe(false);
  });
 test("Update Your question", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "vote for teacher",
      publicurl: "election-url4",
      _csrf: csrfToken,
    });
    const groupedResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedGroupedResponse = JSON.parse(groupedResponse.text);
    const electionCount = parsedGroupedResponse.elections_list.length;
    const latestElection =
      parsedGroupedResponse.elections_list[electionCount - 1];
    res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/createquestions/${latestElection.id}`).send({
      questionname: "Vote_for_teacher",
      description: "Select favourate faculty",
      _csrf: csrfToken,
    });
   const QuestionsResponse = await agent
      .get(`/questions/${latestElection.id}`)
      .set("Accept", "application/json");
    const parsedquestionGroupedResponse = JSON.parse(QuestionsResponse.text);
    const questionCount = parsedquestionGroupedResponse.questions1.length;
    const latestQuestion =
      parsedquestionGroupedResponse.questions1[questionCount - 1];
     res = await agent.get(
      `/elections/${latestElection.id}/questions/${latestQuestion.id}/edit`
    );
    csrfToken = extractCsrfToken(res);
    res = await agent
      .post(
        `/elections/${latestElection.id}/questions/${latestQuestion.id}/edit`
      )
      .send({
        _csrf: csrfToken,
        questionname: "Select_Your_Class",
        description: "3rd year",
      });
    expect(res.statusCode).toBe(302);
  });
 test("Adding New option", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "Election",
      publicurl: "election-url5",
      _csrf: csrfToken,
    });
    const ElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedGroupedResponse = JSON.parse(ElectionsResponse.text);
    const electionCount = parsedGroupedResponse.elections_list.length;
    const latestElection =
      parsedGroupedResponse.elections_list[electionCount - 1];
     res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/createquestions/${latestElection.id}`).send({
      questionname: "Who Will be in First Place.?",
      description: "who wins..",
      _csrf: csrfToken,
    });

    const QuestionsResponse = await agent
      .get(`/questions/${latestElection.id}`)
      .set("Accept", "application/json");
    const parsedquestionsGroupedResponse = JSON.parse(QuestionsResponse.text);
    const questionCount = parsedquestionsGroupedResponse.questions1.length;
    const latestQuestion =
      parsedquestionsGroupedResponse.questions1[questionCount - 1];
     res = await agent.get(
      `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
    );
    csrfToken = extractCsrfToken(res);
     res = await agent
      .post(
        `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
      )
      .send({
        _csrf: csrfToken,
        optionname: "YOUR-OPTION",
      });
    expect(res.statusCode).toBe(302);
  });
  test("Delete Option", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "NAME",
      publicurl: "election-url6",
      _csrf: csrfToken,
    });
    const Election6Response = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedElectionsResponse = JSON.parse(ElectionsResponse.text);
    const electionCount = parsedElectionsResponse.elections_list.length;
    const latestElection =
      parsedElectionsResponse.elections_list[electionCount - 1];
    res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/createquestions/${latestElection.id}`).send({
      questionname: "DELETE-OPTION",
      description: "CHOOSE-OPTION",
      _csrf: csrfToken,
    });
   const QuestionsResponse = await agent
      .get(`/questions/${latestElection.id}`)
      .set("Accept", "application/json");
    const parsedGroupedResponse = JSON.parse(QuestionsResponse.text);
    const questionCount = parsedGroupedResponse.questions1.length;
    const latestQuestion = parsedGroupedResponse.questions1[questionCount - 1];
    res = await agent.get(
      `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
    );
    csrfToken = extractCsrfToken(res);
    res = await agent
      .post(
        `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
      )
      .send({
        _csrf: csrfToken,
        optionname: "Done",
      });
    const OptionsResponse = await agent
      .get(
        `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
      )
      .set("Accept", "application/json");
    const parsedoptionGroupedResponse = JSON.parse(OptionsResponse.text);
    console.log(parsedoptionGroupedResponse);
    const optionsCount = parsedoptionGroupedResponse.option.length;
    const latestOption = parsedoptionGroupedResponse.option[optionsCount - 1];
    res = await agent.get(
      `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
    );
    csrfToken = extractCsrfToken(res);
    const deleteResponse = await agent
      .delete(`/${latestOption.id}/deleteoptions`)
      .send({
        _csrf: csrfToken,
      });
    const DeleteResponse = JSON.parse(deleteResponse.text).success;
    expect(DeleteResponse).toBe(true);
   res = await agent.get(
      `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
    );
    csrfToken = extractCsrfToken(res);
    const deleteResponse2 = await agent
      .delete(`/${latestOption.id}/deleteoptions`)
      .send({
        _csrf: csrfToken,
      });
    const DeleteResponse2 = JSON.parse(deleteResponse2.text).success;
    expect(DeleteResponse2).toBe(false);
  });
test("Updating Option", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "VOTEOPTION",
      publicurl: "election-url7",
      _csrf: csrfToken,
    });
    const ElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedElectionsResponse = JSON.parse(ElectionsResponse.text);
    const electionCount = parsedElectionsResponse.elections_list.length;
    const latestElection =
      parsedElectionsResponse.elections_list[electionCount - 1];
    res = await agent.get(`/createquestions/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/createquestions/${latestElection.id}`).send({
      questionname: "WHICH IS BEST CRICKET TEAM?",
      description: "IN IPL",
      _csrf: csrfToken,
    });
    const QuestionsResponse = await agent
      .get(`/questions/${latestElection.id}`)
      .set("Accept", "application/json");
    const parsedGroupedResponse = JSON.parse(QuestionsResponse.text);
    const questionCount = parsedGroupedResponse.questions1.length;
    const latestQuestion = parsedGroupedResponse.questions1[questionCount - 1];
    res = await agent.get(
      `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
    );
    csrfToken = extractCsrfToken(res);
    res = await agent
      .post(
        `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
    )
      .send({
        _csrf: csrfToken,
        optionname: "HYDERABAD",
      });
const OptionsResponse = await agent
      .get(
        `/getelections/addoption/${latestElection.id}/${latestQuestion.id}/options`
      )
      .set("Accept", "application/json");
    const parsedoptionGroupedResponse = JSON.parse(OptionsResponse.text);
    console.log(parsedoptionGroupedResponse);
    const optionsCount = parsedoptionGroupedResponse.option.length;
    const latestOption = parsedoptionGroupedResponse.option[optionsCount - 1];
    res = await agent.get(
      `/elections/${latestElection.id}/questions/${latestQuestion.id}/options/${latestOption.id}/edit`
    );
    csrfToken = extractCsrfToken(res);
    res = await agent
      .post(
        `/elections/${latestElection.id}/questions/${latestQuestion.id}/options/${latestOption.id}/edit`
      )
      .send({
        _csrf: csrfToken,
        optionname: "Jack",
      });
    expect(res.statusCode).toBe(302);
  });
test("Adding New voter", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "New_Voter_Add",
      publicurl: "election-url8",
      _csrf: csrfToken,
    });
    const groupedResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedResponse = JSON.parse(groupedResponse.text);
    const electionCount = parsedResponse.elections_list.length;
    const latestElection = parsedResponse.elections_list[electionCount - 1];
    res = await agent.get(`/newvoter/${latestElection.id}`);
    csrfToken = extractCsrfToken(res);
    let response = await agent.post(`/newvoter/${latestElection.id}`).send({
      voterid: "Rohit",
      password: "rohit@test.com",
      electionID: latestElection.id,
      _csrf: csrfToken,
    });
    expect(response.statusCode).toBe(302);
  });

  test("Preview election", async () => {
    const agent = request.agent(server);
    await login(agent, "rohit@test.com", "12345678");
    let res = await agent.get("/addquestion");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "MANAGE_ELECTIONS",
      publicurl: "election-url9",
      _csrf: csrfToken,
    });
    const ElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedElectionsResponse = JSON.parse(ElectionsResponse.text);
    const electionCount = parsedElectionsResponse.elections_list.length;
    const latestElection =
      parsedElectionsResponse.elections_list[electionCount - 1];
    res = await agent.get(`/election/${latestElection.id}/previewelection`);
    csrfToken = extractCsrfToken(res);
    expect(res.statusCode).toBe(200);
  });
});
