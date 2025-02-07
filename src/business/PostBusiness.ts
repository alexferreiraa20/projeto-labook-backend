import { PostsDatabase } from "../database/PostsDataBase"
import { UsersDatabase } from "../database/UsersDatabase"
import { LikesDislikesInputDTO } from "../dtos/LikesDislikesDTO"
import { CreatePostInputDTO, DeletePostInputDTO, EditPostInputDTO, GetPostInputDTO, GetPostOutputDTO, PostDTO } from "../dtos/PostDTO"
import { BadRequestError } from "../errors/BadRequestError"
import { NotFoundError } from "../errors/NotFoundError"
import { Post } from "../models/Post"
import { IdGenerator } from "../services/IdGenerator"
import { TokenManager } from "../services/TokenManager"
import { LikeDislikeDB, PostDB, PostWithCreatorDB, POST_LIKE, USER_ROLES } from "../types"

export class PostBusiness {
    constructor(
        private postsDatabase: PostsDatabase,
        private idGenerator: IdGenerator,
        private usersDatabase: UsersDatabase,
        private tokenManager: TokenManager
    ){}

    public getPosts = async (input: GetPostInputDTO): Promise<GetPostOutputDTO> => {

        const { token } = input

        if (token === undefined) {
            throw new BadRequestError("'token' indisponivel")
        }

        const payload = this.tokenManager.getPayload(token)

        if (payload === null) {
            throw new BadRequestError("'token'inválido")
        }

        const postsWithCreatorDB: PostWithCreatorDB[] = await this.postsDatabase.getPostWithCreator()


        const posts = postsWithCreatorDB.map((postWithCreatorDB) => {
            const post = new Post(
                postWithCreatorDB.id,
                postWithCreatorDB.content,
                postWithCreatorDB.likes,
                postWithCreatorDB.dislikes,
                postWithCreatorDB.created_at,
                postWithCreatorDB.updated_at,
                postWithCreatorDB.creator_id,
                postWithCreatorDB.creator_name
            )
            return post.toBusinessModel()
        }
        )
        const output: GetPostOutputDTO = posts
        return output
    }

    public createPost = async (input: CreatePostInputDTO): Promise<void> => {

        const { content, tokenUser } = input

        if (tokenUser === undefined) {
            throw new BadRequestError("'token' indisponivel")
        }

        if (typeof tokenUser !== "string") {
            throw new BadRequestError("'token' deve ser uma string")
        }

        if (tokenUser === null) {
            throw new BadRequestError("deve ser informado um 'token'")
        }

        const payload = this.tokenManager.getPayload(tokenUser)

        if (payload === null) {
            throw new BadRequestError("token inválido")
        }

        const id = this.idGenerator.generate()

        const creatorId = payload.id
        const creatorName = payload.name
        let newLikes = 0
        let newDislikes = 0

        const newPost = new Post(
            id,
            content,
            newLikes,
            newDislikes,
            new Date().toISOString(),
            new Date().toISOString(),
            creatorId,
            creatorName
        )
        const newPostDB = newPost.toDBModel()
        await this.postsDatabase.insertPost(newPostDB)
    }

    public editPost = async (input: EditPostInputDTO): Promise<void> => {

        const { idToEdit, content, token } = input

        if (token === undefined) {
            throw new BadRequestError("'token' indisponivel")
        }

        if (typeof token !== "string") {
            throw new BadRequestError("'token' deve ser uma string")
        }

        if (token === null) {
            throw new BadRequestError("'token' deve ser informado")
        }

        const postDB = await this.postsDatabase.findPostById(idToEdit)

        if (!postDB) {
            throw new NotFoundError("'id' não identificado")
        }

        const payload = this.tokenManager.getPayload(token)

        if (payload === null) {
            throw new BadRequestError("token inválido")
        }

        const creatorId = payload.id

        if (postDB.creator_id !== creatorId) {
            throw new BadRequestError("apenas o usuário original pode editar esse post")
        }

        const creatorName = payload.name

        const newPost = new Post(
            postDB.id,
            postDB.content,
            postDB.likes,
            postDB.dislikes,
            postDB.created_at,
            postDB.updated_at,
            creatorId,
            creatorName
        )

        newPost.setContent(content)
        newPost.setUpdatedAt(new Date().toISOString())

        const newPostDB = newPost.toDBModel()

        await this.postsDatabase.updatePostById(idToEdit, newPostDB)
    }

    public deletePost = async (input: DeletePostInputDTO): Promise<void> => {

        const { idToDelete, token } = input

        if (token === undefined) {
            throw new BadRequestError("'token' indisponivel")
        }

        if (typeof token !== "string") {
            throw new BadRequestError("'token' deve ser uma string")
        }

        if (token === null) {
            throw new BadRequestError("'token' deve ser informado")
        }

        const payload = this.tokenManager.getPayload(token)

        if (payload === null) {
            throw new BadRequestError("token inválido")
        }

        const postDB = await this.postsDatabase.findPostById(idToDelete)

        if (!postDB) {

            throw new NotFoundError("Id não localizado")
        }

        const creatorId = payload.id

        if (
            payload.role !== USER_ROLES.ADMIN &&
            postDB.creator_id !== creatorId) {
            throw new BadRequestError("apenas o usuário original pode deletar o post")
        }

        await this.postsDatabase.deletePostById(idToDelete)

    }

    public likeOrDislikePost = async (input: LikesDislikesInputDTO): Promise<void> => {

        const { idToLikeDislike, token, like } = input

        if (token === undefined) {
            throw new BadRequestError("'token' indisponivel")
        }

        if (typeof token !== "string") {
            throw new BadRequestError("'token' deve ser uma string")
        }

        if (token === null) {
            throw new BadRequestError("'token' deve ser informado")
        }

        const payload = this.tokenManager.getPayload(token)

        if (payload === null) {
            throw new BadRequestError("token inválido")
        }

        if (typeof like !== "boolean") {
            throw new BadRequestError("'like' deve ser um valor booleano")
        }

        const postWithCreatorDB = await this.postsDatabase.findPostWithCreatorById(idToLikeDislike)


        if (!postWithCreatorDB) {
            throw new NotFoundError("Id não localizado")
        }

        const userId = payload.id
        const likeSQLite = like ? 1 : 0

        const likeDislikeDB: LikeDislikeDB = {
            user_id: userId,
            post_id: postWithCreatorDB.id,
            like: likeSQLite
        }

        const post = new Post(
            postWithCreatorDB.id,
            postWithCreatorDB.content,
            postWithCreatorDB.likes,
            postWithCreatorDB.dislikes,
            postWithCreatorDB.created_at,
            postWithCreatorDB.updated_at,
            postWithCreatorDB.creator_id,
            postWithCreatorDB.creator_name
        )

        const likeDislikeExist = await this.postsDatabase
            .findLikeDislike(likeDislikeDB)

        if (likeDislikeExist === POST_LIKE.ALREADY_LIKED) {
            if (like) {
                await this.postsDatabase.removeLikeDislike(likeDislikeDB)
                post.removeLike()
            } else {
                await this.postsDatabase.updateLikeDislike(likeDislikeDB)
                post.removeLike()
                post.addDislike()
            }
        } else if (likeDislikeExist === POST_LIKE.ALREADY_DISLIKED) {
            if (like) {
                await this.postsDatabase.updateLikeDislike(likeDislikeDB)
                post.removeDislike()
                post.addLike()
            } else {
                await this.postsDatabase.removeLikeDislike(likeDislikeDB)
                post.removeDislike()
            }
        } else {
            await this.postsDatabase.likeOrDislikePost(likeDislikeDB)
            like ? post.addLike() : post.addDislike()
        }
        const updatePostDB = post.toDBModel()
        await this.postsDatabase.updatePostById(idToLikeDislike, updatePostDB)
    }
}