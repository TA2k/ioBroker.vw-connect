.class public final Lg1/w2;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:J

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lp3/t;


# direct methods
.method public constructor <init>(Lp3/t;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/w2;->h:Lp3/t;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lg1/w2;

    .line 2
    .line 3
    iget-object p0, p0, Lg1/w2;->h:Lp3/t;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lg1/w2;-><init>(Lp3/t;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lg1/w2;->g:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lg1/w2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/w2;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/w2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lg1/w2;->f:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget-wide v3, p0, Lg1/w2;->e:J

    .line 11
    .line 12
    iget-object v1, p0, Lg1/w2;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Lp3/i0;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, Lg1/w2;->g:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p1, Lp3/i0;

    .line 34
    .line 35
    iget-object v1, p0, Lg1/w2;->h:Lp3/t;

    .line 36
    .line 37
    iget-wide v3, v1, Lp3/t;->b:J

    .line 38
    .line 39
    invoke-virtual {p1}, Lp3/i0;->f()Lw3/h2;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    const-wide/16 v5, 0x28

    .line 47
    .line 48
    add-long/2addr v5, v3

    .line 49
    move-object v1, p1

    .line 50
    move-wide v3, v5

    .line 51
    :cond_2
    iput-object v1, p0, Lg1/w2;->g:Ljava/lang/Object;

    .line 52
    .line 53
    iput-wide v3, p0, Lg1/w2;->e:J

    .line 54
    .line 55
    iput v2, p0, Lg1/w2;->f:I

    .line 56
    .line 57
    const/4 p1, 0x3

    .line 58
    invoke-static {v1, p0, p1}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    if-ne p1, v0, :cond_3

    .line 63
    .line 64
    return-object v0

    .line 65
    :cond_3
    :goto_0
    check-cast p1, Lp3/t;

    .line 66
    .line 67
    iget-wide v5, p1, Lp3/t;->b:J

    .line 68
    .line 69
    cmp-long v5, v5, v3

    .line 70
    .line 71
    if-ltz v5, :cond_2

    .line 72
    .line 73
    return-object p1
.end method
