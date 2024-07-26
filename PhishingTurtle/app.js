var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var {api_url, file_path, server_url, m_host, host} = require('./config');

var indexRouter = require('./routes/index');
var app = express();

const httpProxy = require('http-proxy');
const proxy = httpProxy.createProxyServer({});

global.api_url = api_url;
global.file_path = file_path;
global.server_url = server_url;

global.m_host = m_host;
global.host = host;

const domainMiddleware = (req, res, next) => {
    const host = req.get('host'); // Full host info including port
    req.host = host; // Attach the host to the request object
        switch (host) {
                case host:
                        next();
                break;
                case m_host:
                        console.log("모바일 도메인 : http://localhost:4000 포워딩");
                        proxy.web(req, res, { target: 'http://3.39.214.111:3030' });
                break;
                default:
                        next(createError(404));
                break;
        }
};


app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

//app.use(domainMiddleware);
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const profile = require("./middlewares/profile");
var time = require('./middlewares/seoultime');
const sha256 = require("js-sha256");
const {encryptResponse, decryptRequest, decryptEnc} = require('./middlewares/crypt');
const axios = require("axios");
const checkCookie2 = function (req, res, next) {
        try {
                console.log("쿠키 체크");
                console.log(req.cookies.Token);
          req.cookies.Token = decryptEnc(req.cookies.Token);
          next();
        } catch (e) {
                console.error(e)
          return res.send(
                "<script>alert('로그인을 해주세요'); location.href = \"/event/login\";</script>"
          );
        }
  };
app.get('/event', checkCookie2, async (req, res) => {
    console.log("잘 도착했어요");
    const cookie = req.cookies.Token;
    profile(cookie).then((data) => {
        const en_data = encryptResponse(JSON.stringify({username:data.data.username}));
        axios({          // 송금 페이지를 위한 api로 req
            method: "post",
            url: api_url + "/api/beneficiary/account",
            headers: {"authorization": "1 " + cookie},
            data: en_data
        }).then((data2) => {
            var d = decryptRequest((data2.data));
            var results = d.data.accountdata;

            var html_data = `
                <select class="form-control form-control-user mb-3" name="from_account" aria-label="Large select example" style="width: 100%;">
                    <option selected>이벤트 참여 계좌</option>`;

            // results가 배열인지 확인
            if (Array.isArray(results)) {
                results.forEach(function (a) {
                    html_data += `<option value="${a}">${a}</option>`;
                });
            } else {
                console.error('results is not an array:', results);
            }

            html_data += `</datalist><br>`;
            html_data += `<input type="text" class="form-control form-control-user mb-3" id="to_account" name="to_account" placeholder="받는 계좌" style="display: none;" value="999999"> `
            res.render("event", {pending: data, html: html_data, select: "send"});
        }).catch((error) => {
            console.error('Error in axios request:', error);
            res.redirect("/event/login");
        });
    }).catch((error) => {
        console.error('Error in profile request:', error);
        res.redirect("/event/login");
    });
});


        // res.sendFile(path.join(__dirname, 'views', 'event.ejs'));
// });
app.get('/event/login', (req, res) => {
        res.render("login");
        // res.sendFile(path.join(__dirname, 'views', 'login.ejs'));
});
app.post('/event/login', (req, res) => {
        const {username, password} = req.body;
    const sha256Pass = sha256(password)
    const baseData = `{"username": "${username}", "password": "${sha256Pass}"}`
    const enData = encryptResponse(baseData);

        console.error("로그인 시도");
    axios({          // 입력받은 로그인 값들을 검증하기 위한 api에 req
        method: "post",
        url: api_url + "/api/user/login",
        data: enData
    }).then((data) => {
                console.error("로그인 완료");
        let result = decryptRequest(data.data);
        if (result.status.code == 200) {          // 로그인에 성공하여 jwt가 생성된 경우
                        res.cookie('Token', data.data.enc_data, { maxAge: 3600 * 1000, path: '/', httpOnly: true });
            res.redirect('/event');
        } else {         // 로그인에 실패한 경우
            res.redirect('/event/login');
        }

    }).catch((err)=>{
                console.error(err);
        })
});
app.post('/event/join', checkCookie2, function (req, res, next) {
        console.error("로오오오그인")
        const cookie = req.cookies.Token;
    profile(cookie).then((data) => {
        let json_data = {};
        let result = {};
        const { from_account, to_account, amount, accountPW } = req.body;

        json_data['from_account'] = parseInt(from_account);
        json_data['to_account'] = parseInt(to_account);   //데이터가 숫자로 들어가야 동작함
        json_data['amount'] = parseInt(amount);
        json_data['sendtime'] = time.seoultime;
        json_data['accountPW'] = sha256(accountPW);
        json_data['username'] = data.data.username;
        json_data['membership'] = data.data.membership;
        json_data['is_admin'] = data.data.is_admin;

                console.log("json_data");
                console.log(json_data);

        const en_data = encryptResponse(JSON.stringify(json_data));// 객체를 문자열로 반환 후 암호화

        axios({          // 송금을 위한 api로 req
            method: "post",
            url: api_url + "/api/balance/check_pw",
            headers: {"authorization": "1 " + cookie},
            data: en_data
        }).then((data) => {
                        console.error("로오오오그인")
            result = decryptRequest(data.data);
            statusCode = result.status.code;
            message = result.status.message;
            if(statusCode == 200) {          // 성공하면, 성공 메시지
                axios({          // 송금을 위한 api로 req
                    method: "post",
                    url: api_url + "/api/balance/transfer",
                    headers: {"authorization": "1 " + cookie},
                    data: en_data
                }).then((data) => {
                    result = decryptRequest(data.data);
                    statusCode = result.data.status;
                    message = result.data.message;
                    if(statusCode != 200) {          // 성공하면, 성공 메시지
                        console.error(message);
                        res.send(`<script>
                        alert("${"이벤트 참여가 완료되었습니다."}");
                        location.href=\"http://turtle-bank.com/\";
                        </script>`);
                    } else {          // 실패하면, 실패 메시지
                        res.send(`<script>
                        alert("${"입력하신 정보가 맞지 않습니다."}");
                        location.href=\"/event\";
                        </script>`);
                    }
                });
            } else {          // 실패하면, 실패 메시지
                res.send(`<script>
                alert("${"입력정보가 맞지 않습니다."}");
                location.href=\"/event\";
                </script>`);
            }
        });
    });
});

app.use('/', indexRouter);

app.use(function (req, res, next) {
        next(createError(404));
});

app.use(function (err, req, res, next) {
        res.locals.message = err.message;
        res.locals.error = req.app.get('env') === 'development' ? err : {};

        res.status(err.status || 500);
        res.render('error');
});


module.exports = app;