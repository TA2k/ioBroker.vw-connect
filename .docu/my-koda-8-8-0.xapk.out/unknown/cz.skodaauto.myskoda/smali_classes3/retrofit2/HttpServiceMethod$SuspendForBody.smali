.class final Lretrofit2/HttpServiceMethod$SuspendForBody;
.super Lretrofit2/HttpServiceMethod;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/HttpServiceMethod;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "SuspendForBody"
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

.field public final e:Z


# direct methods
.method public constructor <init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;Lretrofit2/CallAdapter;Z)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lretrofit2/HttpServiceMethod;-><init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lretrofit2/HttpServiceMethod$SuspendForBody;->d:Lretrofit2/CallAdapter;

    .line 5
    .line 6
    iput-boolean p5, p0, Lretrofit2/HttpServiceMethod$SuspendForBody;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c(Lretrofit2/Call;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lretrofit2/HttpServiceMethod$SuspendForBody;->d:Lretrofit2/CallAdapter;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lretrofit2/CallAdapter;->e(Lretrofit2/Call;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lretrofit2/Call;

    .line 8
    .line 9
    array-length v0, p2

    .line 10
    add-int/lit8 v0, v0, -0x1

    .line 11
    .line 12
    aget-object p2, p2, v0

    .line 13
    .line 14
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 15
    .line 16
    :try_start_0
    iget-boolean p0, p0, Lretrofit2/HttpServiceMethod$SuspendForBody;->e:Z

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    const-string p0, "null cannot be cast to non-null type retrofit2.Call<kotlin.Unit?>"

    .line 21
    .line 22
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1, p2}, Lretrofit2/KotlinExtensions;->b(Lretrofit2/Call;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    invoke-static {p1, p2}, Lretrofit2/KotlinExtensions;->a(Lretrofit2/Call;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/VirtualMachineError; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/ThreadDeath; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/LinkageError; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    return-object p0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    invoke-static {p0, p2}, Lretrofit2/KotlinExtensions;->c(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 40
    .line 41
    return-object p0

    .line 42
    :catch_0
    move-exception p0

    .line 43
    throw p0
.end method
