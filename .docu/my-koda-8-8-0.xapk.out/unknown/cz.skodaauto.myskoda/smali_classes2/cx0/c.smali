.class public final Lcx0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/ktor/utils/io/t;


# instance fields
.field public final b:Lnz0/b;

.field public c:Lio/ktor/utils/io/j0;

.field public final d:Lnz0/a;

.field public final e:Lvy0/k1;

.field public final f:Lpx0/g;


# direct methods
.method public constructor <init>(Lnz0/b;Lpx0/g;)V
    .locals 1

    .line 1
    const-string v0, "parent"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcx0/c;->b:Lnz0/b;

    .line 10
    .line 11
    new-instance p1, Lnz0/a;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lcx0/c;->d:Lnz0/a;

    .line 17
    .line 18
    sget-object p1, Lvy0/h1;->d:Lvy0/h1;

    .line 19
    .line 20
    invoke-interface {p2, p1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Lvy0/i1;

    .line 25
    .line 26
    new-instance v0, Lvy0/k1;

    .line 27
    .line 28
    invoke-direct {v0, p1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lcx0/c;->e:Lvy0/k1;

    .line 32
    .line 33
    invoke-interface {p2, v0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    new-instance p2, Lvy0/a0;

    .line 38
    .line 39
    const-string v0, "RawSourceChannel"

    .line 40
    .line 41
    invoke-direct {p2, v0}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {p1, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iput-object p1, p0, Lcx0/c;->f:Lpx0/g;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/Throwable;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcx0/c;->c:Lio/ktor/utils/io/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const-string v1, "Channel was cancelled"

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    move-object v0, v1

    .line 15
    :cond_1
    invoke-static {v0, p1}, Lvy0/e0;->a(Ljava/lang/String;Ljava/lang/Throwable;)Ljava/util/concurrent/CancellationException;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object v2, p0, Lcx0/c;->e:Lvy0/k1;

    .line 20
    .line 21
    invoke-virtual {v2, v0}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lcx0/c;->b:Lnz0/b;

    .line 25
    .line 26
    invoke-virtual {v0}, Lnz0/b;->close()V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lio/ktor/utils/io/j0;

    .line 30
    .line 31
    new-instance v2, Ljava/io/IOException;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    if-nez v3, :cond_2

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    move-object v1, v3

    .line 41
    :goto_0
    invoke-direct {v2, v1, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 42
    .line 43
    .line 44
    invoke-direct {v0, v2}, Lio/ktor/utils/io/j0;-><init>(Ljava/lang/Throwable;)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lcx0/c;->c:Lio/ktor/utils/io/j0;

    .line 48
    .line 49
    return-void
.end method

.method public final d()Ljava/lang/Throwable;
    .locals 1

    .line 1
    iget-object p0, p0, Lcx0/c;->c:Lio/ktor/utils/io/j0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lio/ktor/utils/io/i0;->d:Lio/ktor/utils/io/i0;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/j0;->a(Lay0/k;)Ljava/lang/Throwable;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public final e()Lnz0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcx0/c;->d:Lnz0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f(ILrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lcx0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcx0/b;

    .line 7
    .line 8
    iget v1, v0, Lcx0/b;->g:I

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
    iput v1, v0, Lcx0/b;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcx0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcx0/b;-><init>(Lcx0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcx0/b;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcx0/b;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget p1, v0, Lcx0/b;->d:I

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p2, p0, Lcx0/c;->c:Lio/ktor/utils/io/j0;

    .line 54
    .line 55
    if-eqz p2, :cond_3

    .line 56
    .line 57
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 58
    .line 59
    return-object p0

    .line 60
    :cond_3
    new-instance p2, La50/a;

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    invoke-direct {p2, p0, p1, v2}, La50/a;-><init>(Lcx0/c;ILkotlin/coroutines/Continuation;)V

    .line 64
    .line 65
    .line 66
    iput p1, v0, Lcx0/b;->d:I

    .line 67
    .line 68
    iput v3, v0, Lcx0/b;->g:I

    .line 69
    .line 70
    iget-object v2, p0, Lcx0/c;->f:Lpx0/g;

    .line 71
    .line 72
    invoke-static {v2, p2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    return-object v1

    .line 79
    :cond_4
    :goto_1
    iget-object p0, p0, Lcx0/c;->d:Lnz0/a;

    .line 80
    .line 81
    invoke-static {p0}, Ljp/hb;->c(Lnz0/i;)J

    .line 82
    .line 83
    .line 84
    move-result-wide v0

    .line 85
    int-to-long p0, p1

    .line 86
    cmp-long p0, v0, p0

    .line 87
    .line 88
    if-ltz p0, :cond_5

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    const/4 v3, 0x0

    .line 92
    :goto_2
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

.method public final g()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcx0/c;->c:Lio/ktor/utils/io/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcx0/c;->d:Lnz0/a;

    .line 6
    .line 7
    invoke-virtual {p0}, Lnz0/a;->Z()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method
