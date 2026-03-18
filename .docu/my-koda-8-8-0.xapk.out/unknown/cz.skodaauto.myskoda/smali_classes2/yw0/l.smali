.class public final Lyw0/l;
.super Lyw0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ljava/util/List;

.field public final f:Lyw0/k;

.field public g:Ljava/lang/Object;

.field public final h:[Lkotlin/coroutines/Continuation;

.field public i:I

.field public j:I


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "initial"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "context"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "blocks"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, p2}, Lyw0/e;-><init>(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iput-object p3, p0, Lyw0/l;->e:Ljava/util/List;

    .line 20
    .line 21
    new-instance p2, Lyw0/k;

    .line 22
    .line 23
    invoke-direct {p2, p0}, Lyw0/k;-><init>(Lyw0/l;)V

    .line 24
    .line 25
    .line 26
    iput-object p2, p0, Lyw0/l;->f:Lyw0/k;

    .line 27
    .line 28
    iput-object p1, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 29
    .line 30
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    new-array p1, p1, [Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    iput-object p1, p0, Lyw0/l;->h:[Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    const/4 p1, -0x1

    .line 39
    iput p1, p0, Lyw0/l;->i:I

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lyw0/l;->j:I

    .line 3
    .line 4
    iget-object v0, p0, Lyw0/l;->e:Ljava/util/List;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    return-object p1

    .line 13
    :cond_0
    const-string v0, "<set-?>"

    .line 14
    .line 15
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 19
    .line 20
    iget p1, p0, Lyw0/l;->i:I

    .line 21
    .line 22
    if-gez p1, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, p2}, Lyw0/l;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "Already started"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public final b()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lyw0/l;->j:I

    .line 2
    .line 3
    iget-object v1, p0, Lyw0/l;->e:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget v1, p0, Lyw0/l;->i:I

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    add-int/2addr v1, v2

    .line 22
    iput v1, p0, Lyw0/l;->i:I

    .line 23
    .line 24
    iget-object v3, p0, Lyw0/l;->h:[Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    aput-object v0, v3, v1

    .line 27
    .line 28
    invoke-virtual {p0, v2}, Lyw0/l;->e(Z)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    iget v0, p0, Lyw0/l;->i:I

    .line 35
    .line 36
    if-ltz v0, :cond_1

    .line 37
    .line 38
    add-int/lit8 v1, v0, -0x1

    .line 39
    .line 40
    iput v1, p0, Lyw0/l;->i:I

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    aput-object v1, v3, v0

    .line 44
    .line 45
    iget-object p0, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "No more continuations to resume"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 57
    .line 58
    :goto_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 59
    .line 60
    if-ne p0, v0, :cond_3

    .line 61
    .line 62
    const-string v0, "frame"

    .line 63
    .line 64
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_3
    return-object p0
.end method

.method public final d(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-virtual {p0, p2}, Lyw0/l;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final e(Z)Z
    .locals 5

    .line 1
    :cond_0
    iget v0, p0, Lyw0/l;->j:I

    .line 2
    .line 3
    iget-object v1, p0, Lyw0/l;->e:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const/4 v3, 0x0

    .line 10
    if-ne v0, v2, :cond_2

    .line 11
    .line 12
    if-nez p1, :cond_1

    .line 13
    .line 14
    iget-object p1, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lyw0/l;->f(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return v3

    .line 20
    :cond_1
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_2
    add-int/lit8 v2, v0, 0x1

    .line 23
    .line 24
    iput v2, p0, Lyw0/l;->j:I

    .line 25
    .line 26
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lay0/o;

    .line 31
    .line 32
    :try_start_0
    iget-object v1, p0, Lyw0/l;->g:Ljava/lang/Object;

    .line 33
    .line 34
    iget-object v2, p0, Lyw0/l;->f:Lyw0/k;

    .line 35
    .line 36
    const-string v4, "interceptor"

    .line 37
    .line 38
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v4, "subject"

    .line 42
    .line 43
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v4, "continuation"

    .line 47
    .line 48
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const/4 v4, 0x3

    .line 52
    invoke-static {v4, v0}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-interface {v0, p0, v1, v2}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sget-object v1, Lqx0/a;->d:Lqx0/a;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    if-ne v0, v1, :cond_0

    .line 62
    .line 63
    return v3

    .line 64
    :catchall_0
    move-exception p1

    .line 65
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-virtual {p0, p1}, Lyw0/l;->f(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    return v3
.end method

.method public final f(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget v0, p0, Lyw0/l;->i:I

    .line 2
    .line 3
    if-ltz v0, :cond_1

    .line 4
    .line 5
    iget-object v1, p0, Lyw0/l;->h:[Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    aget-object v0, v1, v0

    .line 8
    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget v2, p0, Lyw0/l;->i:I

    .line 13
    .line 14
    add-int/lit8 v3, v2, -0x1

    .line 15
    .line 16
    iput v3, p0, Lyw0/l;->i:I

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    aput-object p0, v1, v2

    .line 20
    .line 21
    instance-of p0, p1, Llx0/n;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    invoke-interface {v0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :try_start_0
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    .line 38
    .line 39
    :catchall_0
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-interface {v0, p0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "No more continuations to resume"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lyw0/l;->f:Lyw0/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyw0/k;->getContext()Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
