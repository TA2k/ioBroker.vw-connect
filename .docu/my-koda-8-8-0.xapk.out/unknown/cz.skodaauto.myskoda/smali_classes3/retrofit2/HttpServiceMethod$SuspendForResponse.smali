.class final Lretrofit2/HttpServiceMethod$SuspendForResponse;
.super Lretrofit2/HttpServiceMethod;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/HttpServiceMethod;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "SuspendForResponse"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<ResponseT:",
        "Ljava/lang/Object;",
        ">",
        "Lretrofit2/HttpServiceMethod<",
        "TResponseT;",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field public final d:Lretrofit2/CallAdapter;


# direct methods
.method public constructor <init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;Lretrofit2/CallAdapter;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lretrofit2/HttpServiceMethod;-><init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lretrofit2/HttpServiceMethod$SuspendForResponse;->d:Lretrofit2/CallAdapter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c(Lretrofit2/Call;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lretrofit2/HttpServiceMethod$SuspendForResponse;->d:Lretrofit2/CallAdapter;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lretrofit2/CallAdapter;->e(Lretrofit2/Call;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lretrofit2/Call;

    .line 8
    .line 9
    array-length p1, p2

    .line 10
    const/4 v0, 0x1

    .line 11
    sub-int/2addr p1, v0

    .line 12
    aget-object p1, p2, p1

    .line 13
    .line 14
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 15
    .line 16
    :try_start_0
    new-instance p2, Lvy0/l;

    .line 17
    .line 18
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-direct {p2, v0, v1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2}, Lvy0/l;->q()V

    .line 26
    .line 27
    .line 28
    new-instance v0, Lretrofit2/KotlinExtensions$awaitResponse$2$1;

    .line 29
    .line 30
    invoke-direct {v0, p0}, Lretrofit2/KotlinExtensions$awaitResponse$2$1;-><init>(Lretrofit2/Call;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p2, v0}, Lvy0/l;->s(Lay0/k;)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Lretrofit2/KotlinExtensions$awaitResponse$2$2;

    .line 37
    .line 38
    invoke-direct {v0, p2}, Lretrofit2/KotlinExtensions$awaitResponse$2$2;-><init>(Lvy0/l;)V

    .line 39
    .line 40
    .line 41
    invoke-interface {p0, v0}, Lretrofit2/Call;->g(Lretrofit2/Callback;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    sget-object p1, Lqx0/a;->d:Lqx0/a;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 49
    .line 50
    return-object p0

    .line 51
    :catch_0
    move-exception p0

    .line 52
    invoke-static {p0, p1}, Lretrofit2/KotlinExtensions;->c(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V

    .line 53
    .line 54
    .line 55
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    return-object p0
.end method
