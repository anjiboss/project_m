// import { NextFunction, Request, Response } from "express";

// export const registerInputValidate = (
// 	req: Request,
// 	res: Response,
// 	next: NextFunction
// ) => {
// 	const {username, email, password,repassword, firstname, lastname} = req.body
// 	if (!username || !email || !password ){
// 		return res.status(400).json({
// 			success: false,
// 			error: {
// 				message: "Input error! Fill in all required field",
// 				code: 0
// 			}
// 		})
// 	}
// 	const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
// 	if (!emailRegex.test(email)){
// 		return res.status(400).json({
// 			success: false,
// 			error: {
// 				message: "Provided Email Is Invalid",
// 				code: 1
// 			}
// 		})
// 	}
// 	if (password !== repassword){
// 		return res.status(400).json({
// 			success: false,
// 			error: {
// 				message: "Repeat Password Is Different From Password",
// 				code: 2
// 			}
// 		})
// 	}

// }
