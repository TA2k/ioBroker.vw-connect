.class public interface abstract Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J<\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\t0\u00082\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u00042\u0010\u0008\u0003\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0006H\u00a7@\u00a2\u0006\u0004\u0008\n\u0010\u000b\u00a8\u0006\u000c\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi;",
        "",
        "Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;",
        "feedback",
        "Ld01/e0;",
        "logs",
        "",
        "images",
        "Lretrofit2/Response;",
        "Llx0/b0;",
        "createFeedback",
        "(Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;Ld01/e0;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
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


# direct methods
.method public static synthetic createFeedback$default(Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi;Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;Ld01/e0;Ljava/util/List;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p6, :cond_1

    .line 2
    .line 3
    and-int/lit8 p5, p5, 0x4

    .line 4
    .line 5
    if-eqz p5, :cond_0

    .line 6
    .line 7
    const/4 p3, 0x0

    .line 8
    :cond_0
    invoke-interface {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_feedbacks/v2/FeedbacksApi;->createFeedback(Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;Ld01/e0;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 14
    .line 15
    const-string p1, "Super calls with default arguments not supported in this target, function: createFeedback"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public abstract createFeedback(Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;Ld01/e0;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;
        .annotation runtime Lretrofit2/http/Part;
            value = "feedback"
        .end annotation
    .end param
    .param p2    # Ld01/e0;
        .annotation runtime Lretrofit2/http/Part;
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lretrofit2/http/Part;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_feedbacks/v2/FeedbackDto;",
            "Ld01/e0;",
            "Ljava/util/List<",
            "Ld01/e0;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/Multipart;
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/feedbacks"
    .end annotation
.end method
