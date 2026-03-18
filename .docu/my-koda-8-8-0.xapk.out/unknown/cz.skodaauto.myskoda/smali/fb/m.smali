.class public final Lfb/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Throwable;

.field public synthetic f:J


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Throwable;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->longValue()J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 12
    .line 13
    new-instance p3, Lfb/m;

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    invoke-direct {p3, v0, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    iput-object p2, p3, Lfb/m;->e:Ljava/lang/Throwable;

    .line 20
    .line 21
    iput-wide p0, p3, Lfb/m;->f:J

    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {p3, p0}, Lfb/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lfb/m;->d:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object p1, p0, Lfb/m;->e:Ljava/lang/Throwable;

    .line 26
    .line 27
    iget-wide v3, p0, Lfb/m;->f:J

    .line 28
    .line 29
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    sget-object v5, Lfb/n;->a:Ljava/lang/String;

    .line 34
    .line 35
    const-string v6, "Cannot check for unfinished work"

    .line 36
    .line 37
    invoke-virtual {v1, v5, v6, p1}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    const/16 p1, 0x7530

    .line 41
    .line 42
    int-to-long v5, p1

    .line 43
    mul-long/2addr v3, v5

    .line 44
    sget-wide v5, Lfb/n;->b:J

    .line 45
    .line 46
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 47
    .line 48
    .line 49
    move-result-wide v3

    .line 50
    iput v2, p0, Lfb/m;->d:I

    .line 51
    .line 52
    invoke-static {v3, v4, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    if-ne p0, v0, :cond_2

    .line 57
    .line 58
    return-object v0

    .line 59
    :cond_2
    :goto_0
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 60
    .line 61
    return-object p0
.end method
