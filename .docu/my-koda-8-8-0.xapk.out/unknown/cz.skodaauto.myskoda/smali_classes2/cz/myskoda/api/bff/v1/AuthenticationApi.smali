.class public interface abstract Lcz/myskoda/api/bff/v1/AuthenticationApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008f\u0018\u00002\u00020\u0001J*\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ*\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\u000c\u0010\rJ*\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\u000f\u0010\r\u00a8\u0006\u0010\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/AuthenticationApi;",
        "",
        "",
        "tokenType",
        "Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;",
        "authorizationCodeExchangeDto",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff/v1/AuthenticationDto;",
        "exchangeAuthorizationCode",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/RefreshTokenDto;",
        "refreshTokenDto",
        "refreshToken",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/RefreshTokenDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Llx0/b0;",
        "revokeToken",
        "bff-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract exchangeAuthorizationCode(Ljava/lang/String;Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "tokenType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/AuthenticationDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/authentication/exchange-authorization-code"
    .end annotation
.end method

.method public abstract refreshToken(Ljava/lang/String;Lcz/myskoda/api/bff/v1/RefreshTokenDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "tokenType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/RefreshTokenDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/RefreshTokenDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/AuthenticationDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/authentication/refresh-token"
    .end annotation
.end method

.method public abstract revokeToken(Ljava/lang/String;Lcz/myskoda/api/bff/v1/RefreshTokenDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "tokenType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/RefreshTokenDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/RefreshTokenDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/authentication/revoke-token"
    .end annotation
.end method
