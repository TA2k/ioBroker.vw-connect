.class public interface abstract Led/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000N\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010 \n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J2\u0010\u0008\u001a\u0018\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0005`\u00072\n\u0008\u0001\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ0\u0010\r\u001a\u0018\u0012\u0004\u0012\u00020\u000c\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000c`\u00072\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\r\u0010\u000eJ0\u0010\u0012\u001a\u0018\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0011`\u00072\u0008\u0008\u0001\u0010\u0010\u001a\u00020\u000fH\u00a7@\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J^\u0010\u001a\u001a\u0018\u0012\u0004\u0012\u00020\u0019\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0019`\u00072\u0008\u0008\u0001\u0010\u0014\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0015\u001a\u00020\u00022\u0010\u0008\u0001\u0010\u0017\u001a\n\u0012\u0004\u0012\u00020\u000f\u0018\u00010\u00162\u0010\u0008\u0001\u0010\u0018\u001a\n\u0012\u0004\u0012\u00020\u000f\u0018\u00010\u0016H\u00a7@\u00a2\u0006\u0004\u0008\u001a\u0010\u001b\u00a8\u0006\u001c\u00c0\u0006\u0003"
    }
    d2 = {
        "Led/f;",
        "",
        "Lgz0/p;",
        "lastRecordCreatedAt",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "Ldd/c;",
        "Ltb/c;",
        "Lcariad/charging/multicharge/kitten/charginghistory/network/BffResponse;",
        "d",
        "(Lgz0/p;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcd/o;",
        "request",
        "Lcd/r;",
        "b",
        "(Lcd/o;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "id",
        "Lcd/c;",
        "c",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "startDate",
        "endDate",
        "",
        "rfidCardsIds",
        "stationId",
        "Ljava/io/File;",
        "a",
        "(Lgz0/p;Lgz0/p;Ljava/util/List;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "kitten-charginghistory_release"
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
.method public abstract a(Lgz0/p;Lgz0/p;Ljava/util/List;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lgz0/p;
        .annotation runtime Lretrofit2/http/Query;
            value = "startDate"
        .end annotation
    .end param
    .param p2    # Lgz0/p;
        .annotation runtime Lretrofit2/http/Query;
            value = "endDate"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lretrofit2/http/Query;
            value = "rfidCardsIds"
        .end annotation
    .end param
    .param p4    # Ljava/util/List;
        .annotation runtime Lretrofit2/http/Query;
            value = "stationId"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lgz0/p;",
            "Lgz0/p;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "+",
            "Ljava/io/File;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "charging_history/home"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation
.end method

.method public abstract b(Lcd/o;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcd/o;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcd/o;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lcd/r;",
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
        value = "charging_history/home"
    .end annotation
.end method

.method public abstract c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lcd/c;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "charging_history/home/{id}"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 2"
        }
    .end annotation
.end method

.method public abstract d(Lgz0/p;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lgz0/p;
        .annotation runtime Lretrofit2/http/Query;
            value = "lastRecordCreatedAt"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lgz0/p;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Ldd/c;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "charging_history/public"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 2"
        }
    .end annotation
.end method
