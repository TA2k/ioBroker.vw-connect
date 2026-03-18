.class public interface abstract Lfg/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J0\u0010\u0008\u001a\u0018\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0005`\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ0\u0010\u000c\u001a\u0018\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000b`\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\u000c\u0010\rJ0\u0010\u0010\u001a\u0018\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000f`\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u000eH\u00a7@\u00a2\u0006\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012\u00c0\u0006\u0003"
    }
    d2 = {
        "Lfg/d;",
        "",
        "Leg/l;",
        "body",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "Leg/o;",
        "Ltb/c;",
        "Lcariad/charging/multicharge/kitten/remoteauthorization/network/BffResponse;",
        "a",
        "(Leg/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Leg/c;",
        "Leg/f;",
        "b",
        "(Leg/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Leg/r;",
        "Leg/u;",
        "c",
        "(Leg/r;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "kitten-remote-authorization_release"
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
.method public abstract a(Leg/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Leg/l;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Leg/l;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Leg/o;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "remote_authorization/overview"
    .end annotation
.end method

.method public abstract b(Leg/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Leg/c;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Leg/c;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Leg/f;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "headless/connectors/evseIdLookup"
    .end annotation
.end method

.method public abstract c(Leg/r;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Leg/r;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Leg/r;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Leg/u;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "remote_authorization/start"
    .end annotation
.end method
