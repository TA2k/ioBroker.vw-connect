.class public interface abstract Lqd/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008`\u0018\u00002\u00020\u0001J0\u0010\u0008\u001a\u0018\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0005`\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ0\u0010\r\u001a\u0018\u0012\u0004\u0012\u00020\u000c\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000c`\u00072\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\r\u0010\u000e\u00a8\u0006\u000f\u00c0\u0006\u0003"
    }
    d2 = {
        "Lqd/d;",
        "",
        "Lpd/v;",
        "request",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "Lpd/b0;",
        "Ltb/c;",
        "Lcariad/charging/multicharge/kitten/chargingstatistics/network/BffResponse;",
        "b",
        "(Lpd/v;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "recordId",
        "Lpd/o0;",
        "a",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "kitten-chargingstatistics_release"
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
.method public abstract a(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "recordId"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lpd/o0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "charging_statistics/{recordId}/power-curve"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation
.end method

.method public abstract b(Lpd/v;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lpd/v;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lpd/v;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lpd/b0;",
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
        value = "charging_statistics"
    .end annotation
.end method
