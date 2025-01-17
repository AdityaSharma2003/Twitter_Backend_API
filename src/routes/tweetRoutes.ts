import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";


const router = Router();
const prisma = new PrismaClient();

const JWT_SECRET = "Super Secret";



//tweet route

//create tweet
router.post("/", async(req,res) => {
    const {content,image} = req.body;

    // @ts-ignore
    const user = req.user;

    try{
        const result = await prisma.tweet.create({
            data:{
                content,
                image,
                userId: user.id,
            }
        });
        res.json(result);
    } catch (e){
        res.status(400).json({error: "unable to create a tweet"});
    }
});

//list tweets
router.get("/", async(req,res) => {
    const allTweet = await prisma.tweet.findMany({
        include: {
            user: {
                select: {
                    id: true,
                    name: true,
                    username: true,
                    image: true
                }
            }
        }
    });
    res.json(allTweet);
});
//list one tweet
router.get("/:id", async(req,res) => {
    const {id} = req.params;
    const tweet = await prisma.tweet.findUnique({where: {id: Number(id)}, include: {user: true}});
    if(!tweet){
        return res.status(404).json({error: "tweet not found"});
    }
    res.json(tweet);
});

//update tweet
router.put("/:id", async(req,res) => {
    const {id} = req.params;
    const {content,image} = req.body;
    try{
        const result = await prisma.tweet.update({
            where: {id: Number(id)},
            data: {
                content,
                image
            }
        });
        res.json(result);
    } catch(e) {
        res.status(400).json({error: 'Failed to update the tweet'});
    }
});

//delete tweet
router.delete("/:id", async(req,res) => {
    const {id} = req.params;
    await prisma.tweet.delete({where: {id: Number(id)}});
    res.sendStatus(200);
});



export default router;