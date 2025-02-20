export const config = {

    jwt: {
      secret: process.env.jWT_SECRET,
      expiresIn: '1h',
    }};