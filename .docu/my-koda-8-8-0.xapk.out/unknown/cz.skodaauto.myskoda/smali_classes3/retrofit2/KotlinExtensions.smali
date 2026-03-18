.class public final Lretrofit2/KotlinExtensions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0002\n\u0000\u00a8\u0006\u0000"
    }
    d2 = {
        "retrofit"
    }
    k = 0x2
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final a(Lretrofit2/Call;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lvy0/l;

    .line 2
    .line 3
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1, p1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvy0/l;->q()V

    .line 12
    .line 13
    .line 14
    new-instance p1, Lretrofit2/KotlinExtensions$await$2$1;

    .line 15
    .line 16
    invoke-direct {p1, p0}, Lretrofit2/KotlinExtensions$await$2$1;-><init>(Lretrofit2/Call;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, p1}, Lvy0/l;->s(Lay0/k;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lretrofit2/KotlinExtensions$await$2$2;

    .line 23
    .line 24
    invoke-direct {p1, v0}, Lretrofit2/KotlinExtensions$await$2$2;-><init>(Lvy0/l;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p0, p1}, Lretrofit2/Call;->g(Lretrofit2/Callback;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    return-object p0
.end method

.method public static final b(Lretrofit2/Call;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lvy0/l;

    .line 2
    .line 3
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1, p1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvy0/l;->q()V

    .line 12
    .line 13
    .line 14
    new-instance p1, Lretrofit2/KotlinExtensions$await$4$1;

    .line 15
    .line 16
    invoke-direct {p1, p0}, Lretrofit2/KotlinExtensions$await$4$1;-><init>(Lretrofit2/Call;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, p1}, Lvy0/l;->s(Lay0/k;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lretrofit2/KotlinExtensions$await$4$2;

    .line 23
    .line 24
    invoke-direct {p1, v0}, Lretrofit2/KotlinExtensions$await$4$2;-><init>(Lvy0/l;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p0, p1}, Lretrofit2/Call;->g(Lretrofit2/Callback;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    return-object p0
.end method

.method public static final c(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V
    .locals 4

    .line 1
    instance-of v0, p1, Lretrofit2/KotlinExtensions$suspendAndThrow$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;

    .line 7
    .line 8
    iget v1, v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->e:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->e:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-eq v1, v2, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iput v2, v0, Lretrofit2/KotlinExtensions$suspendAndThrow$1;->e:I

    .line 53
    .line 54
    sget-object p1, Lvy0/p0;->a:Lcz0/e;

    .line 55
    .line 56
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    new-instance v2, Lretrofit2/KotlinExtensions$suspendAndThrow$2$1;

    .line 61
    .line 62
    invoke-direct {v2, p0, v0}, Lretrofit2/KotlinExtensions$suspendAndThrow$2$1;-><init>(Ljava/lang/Throwable;Lkotlin/coroutines/Continuation;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, v1, v2}, Lcz0/h;->T(Lpx0/g;Ljava/lang/Runnable;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method
