.class public final Lyw0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/coroutines/Continuation;
.implements Lrx0/d;


# instance fields
.field public d:I

.field public final synthetic e:Lyw0/l;


# direct methods
.method public constructor <init>(Lyw0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyw0/k;->e:Lyw0/l;

    .line 5
    .line 6
    const/high16 p1, -0x80000000

    .line 7
    .line 8
    iput p1, p0, Lyw0/k;->d:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final getCallerFrame()Lrx0/d;
    .locals 5

    .line 1
    sget-object v0, Lyw0/j;->d:Lyw0/j;

    .line 2
    .line 3
    iget v1, p0, Lyw0/k;->d:I

    .line 4
    .line 5
    iget-object v2, p0, Lyw0/k;->e:Lyw0/l;

    .line 6
    .line 7
    const/high16 v3, -0x80000000

    .line 8
    .line 9
    if-ne v1, v3, :cond_0

    .line 10
    .line 11
    iget v1, v2, Lyw0/l;->i:I

    .line 12
    .line 13
    iput v1, p0, Lyw0/k;->d:I

    .line 14
    .line 15
    :cond_0
    iget v1, p0, Lyw0/k;->d:I

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    if-gez v1, :cond_1

    .line 19
    .line 20
    iput v3, p0, Lyw0/k;->d:I

    .line 21
    .line 22
    move-object v0, v4

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    :try_start_0
    iget-object v2, v2, Lyw0/l;->h:[Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    aget-object v2, v2, v1

    .line 27
    .line 28
    if-nez v2, :cond_2

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_2
    add-int/lit8 v1, v1, -0x1

    .line 32
    .line 33
    iput v1, p0, Lyw0/k;->d:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    move-object v0, v2

    .line 36
    :catchall_0
    :goto_0
    instance-of p0, v0, Lrx0/d;

    .line 37
    .line 38
    if-eqz p0, :cond_3

    .line 39
    .line 40
    move-object v4, v0

    .line 41
    check-cast v4, Lrx0/d;

    .line 42
    .line 43
    :cond_3
    return-object v4
.end method

.method public final getContext()Lpx0/g;
    .locals 3

    .line 1
    iget-object v0, p0, Lyw0/k;->e:Lyw0/l;

    .line 2
    .line 3
    iget-object v1, v0, Lyw0/l;->h:[Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    iget v0, v0, Lyw0/l;->i:I

    .line 6
    .line 7
    aget-object v2, v1, v0

    .line 8
    .line 9
    if-eq v2, p0, :cond_0

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    invoke-interface {v2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 19
    .line 20
    :goto_0
    if-ltz v0, :cond_2

    .line 21
    .line 22
    add-int/lit8 v2, v0, -0x1

    .line 23
    .line 24
    aget-object v0, v1, v0

    .line 25
    .line 26
    if-eq v0, p0, :cond_1

    .line 27
    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_1
    move v0, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string v0, "Not started"

    .line 40
    .line 41
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 1

    .line 1
    instance-of v0, p1, Llx0/n;

    .line 2
    .line 3
    iget-object p0, p0, Lyw0/k;->e:Lyw0/l;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1}, Lyw0/l;->f(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    const/4 p1, 0x0

    .line 23
    invoke-virtual {p0, p1}, Lyw0/l;->e(Z)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method
