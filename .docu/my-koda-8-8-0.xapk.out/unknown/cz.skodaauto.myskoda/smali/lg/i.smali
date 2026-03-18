.class public interface abstract Llg/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000L\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008f\u0018\u00002\u00020\u0001J2\u0010\u0008\u001a\u0018\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0005`\u00072\n\u0008\u0001\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ0\u0010\r\u001a\u0018\u0012\u0004\u0012\u00020\u000c\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000c`\u00072\u0008\u0008\u0001\u0010\u000b\u001a\u00020\nH\u00a7@\u00a2\u0006\u0004\u0008\r\u0010\u000eJ2\u0010\u0010\u001a\u0018\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000f`\u00072\n\u0008\u0001\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0010\u0010\tJ2\u0010\u0012\u001a\u0018\u0012\u0004\u0012\u00020\u0011\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0011`\u00072\n\u0008\u0001\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0012\u0010\tJ0\u0010\u0015\u001a\u0018\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000f`\u00072\u0008\u0008\u0001\u0010\u0014\u001a\u00020\u0013H\u00a7@\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J2\u0010\u0017\u001a\u0018\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u000f`\u00072\n\u0008\u0001\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0017\u0010\tJ0\u0010\u001a\u001a\u0018\u0012\u0004\u0012\u00020\u0019\u0012\u0004\u0012\u00020\u00060\u0004j\u0008\u0012\u0004\u0012\u00020\u0019`\u00072\u0008\u0008\u0001\u0010\u0018\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u001a\u0010\t\u00a8\u0006\u001b\u00c0\u0006\u0003"
    }
    d2 = {
        "Llg/i;",
        "",
        "",
        "vin",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "Lkg/a0;",
        "Ltb/c;",
        "Lcariad/charging/multicharge/kitten/subscription/network/BffResponse;",
        "c",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lkg/u;",
        "completeSubscriptionRequest",
        "Llx0/b0;",
        "g",
        "(Lkg/u;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lkg/d0;",
        "d",
        "Lkg/g0;",
        "e",
        "Lkg/m0;",
        "completeSubscriptionUpgradeOrFollowUpRequest",
        "a",
        "(Lkg/m0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "b",
        "tariffId",
        "Ljava/io/File;",
        "f",
        "kitten-subscription_release"
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
.method public abstract a(Lkg/m0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lkg/m0;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkg/m0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lkg/d0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 4"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "subscriptions/edit/upgrade_or_follow_up/complete"
    .end annotation
.end method

.method public abstract b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lkg/d0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 2"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "subscriptions/edit/cancel_auto_renewal"
    .end annotation
.end method

.method public abstract c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lkg/a0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "subscription/init"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 3"
        }
    .end annotation
.end method

.method public abstract d(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lkg/d0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "subscriptions"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation
.end method

.method public abstract e(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lkg/g0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "subscriptions/edit/upgrade_or_follow_up/init"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 4"
        }
    .end annotation
.end method

.method public abstract f(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "tariff"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
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
        value = "resources/tariff-details-pdf"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 1"
        }
    .end annotation
.end method

.method public abstract g(Lkg/u;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lkg/u;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkg/u;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Llx0/b0;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 3"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "subscription/complete"
    .end annotation
.end method
