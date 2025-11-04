import axios from "axios";

const baseURL = "http://127.0.0.1:8000/api/"; // change if backend host/port different

const api = axios.create({ baseURL });

api.interceptors.request.use(config => {
  const token = localStorage.getItem("intrudex_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default api;

