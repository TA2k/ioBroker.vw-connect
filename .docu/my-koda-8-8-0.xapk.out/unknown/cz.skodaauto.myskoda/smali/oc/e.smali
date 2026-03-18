.class public interface abstract Loc/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J&\u0010\u0006\u001a\u0018\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00040\u0002j\u0008\u0012\u0004\u0012\u00020\u0003`\u0005H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J0\u0010\u000b\u001a\u0018\u0012\u0004\u0012\u00020\n\u0012\u0004\u0012\u00020\u00040\u0002j\u0008\u0012\u0004\u0012\u00020\n`\u00052\u0008\u0008\u0001\u0010\t\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ0\u0010\u0010\u001a\u0018\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00040\u0002j\u0008\u0012\u0004\u0012\u00020\u000f`\u00052\u0008\u0008\u0001\u0010\u000e\u001a\u00020\rH\u00a7@\u00a2\u0006\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012\u00c0\u0006\u0003"
    }
    d2 = {
        "Loc/e;",
        "",
        "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;",
        "Lnc/t;",
        "Ltb/c;",
        "Lcariad/charging/multicharge/common/presentation/payment/network/BffResponse;",
        "a",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lnc/n;",
        "paymentAddOrReplaceInitRequest",
        "Lnc/q;",
        "b",
        "(Lnc/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lnc/h;",
        "paymentAddOrReplaceCompleteRequest",
        "Lnc/k;",
        "c",
        "(Lnc/h;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "common-presentation_release"
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
.method public abstract a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lnc/t;",
            "Ltb/c;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "payment/available-payment-providers"
    .end annotation

    .annotation runtime Lretrofit2/http/Headers;
        value = {
            "X-Api-Version: 2"
        }
    .end annotation
.end method

.method public abstract b(Lnc/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lnc/n;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lnc/n;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lnc/q;",
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
        value = "payment/edit/add-or-replace/init"
    .end annotation
.end method

.method public abstract c(Lnc/h;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lnc/h;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lnc/h;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse<",
            "Lnc/k;",
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
        value = "payment/edit/add-or-replace/complete"
    .end annotation
.end method
