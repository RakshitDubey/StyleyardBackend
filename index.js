import express from "express";
import { dbConnection } from "./Database/dbConnection.js";
import { bootstrap } from "./src/bootstrap.js";
import dotenv from "dotenv";
import morgan from "morgan";
import cors from 'cors'
import { createOnlineOrder } from "./src/modules/order/order.controller.js";
import cookieParser from "cookie-parser";

dotenv.config();
const app = express();
app.use(cors())

const port = 3000;
app.post('/webhook', express.raw({type: 'application/json'}),createOnlineOrder );
app.use(express.json());
app.use(cookieParser())
app.use(morgan("dev"));
app.use(express.static("uploads"));

app.get('/working', (req, res) => {
  res.send("working");
});



bootstrap(app);
dbConnection();
app.listen(process.env.PORT || port, () => console.log(`Example app listening on port ${port}!`));
