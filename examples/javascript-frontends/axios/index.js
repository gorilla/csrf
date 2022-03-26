// make GET request to backend on page load in order to obtain
// a CSRF Token and load it into the Axios instance's headers
// https://github.com/axios/axios#creating-an-instance
const initializeAxiosInstance = async (url) => {
    try {
        let resp = await axios.get(url, {withCredentials: true});
        console.log(resp);
        document.getElementById("get-request-full-response").innerHTML = JSON.stringify(resp);

        let csrfToken = parseCSRFToken(resp);
        console.log(csrfToken);
        document.getElementById("get-response-csrf-token").innerHTML = csrfToken;

        return axios.create({
            // withCredentials must be true to in order for the browser
            // to send cookies, which are necessary for CSRF verification
            withCredentials: true,
            headers: {"X-CSRF-Token": csrfToken}
        });
    } catch (err) {
        console.log(err);
    }
};

const post = async (axiosInstance, url) => {
    try {
        let resp = await axiosInstance.post(url);
        console.log(resp);
        document.getElementById("post-request-full-response").innerHTML = JSON.stringify(resp);
    } catch (err) {
        console.log(err);
    }
};

const parseCSRFToken = (resp) => {
    let csrfToken = resp.headers[csrfTokenHeader];
    if (!csrfToken) {
        csrfToken = resp.headers[csrfTokenHeader.toLowerCase()];
    }
    return csrfToken
}

const url = "http://localhost:8080/api";
const csrfTokenHeader = "X-CSRF-Token";
initializeAxiosInstance(url)
    .then(axiosInstance => {
        post(axiosInstance, url);
    });
