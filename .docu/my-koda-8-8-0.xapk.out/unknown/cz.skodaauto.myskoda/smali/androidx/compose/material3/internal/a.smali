.class public abstract Landroidx/compose/material3/internal/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Li2/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Li2/i;

    .line 7
    .line 8
    iget v1, v0, Li2/i;->e:I

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
    iput v1, v0, Li2/i;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li2/i;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Li2/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li2/i;->e:I

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
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Li2/e; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    :try_start_1
    new-instance p2, Lg1/i;

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    const/4 v4, 0x1

    .line 55
    invoke-direct {p2, p0, p1, v2, v4}, Lg1/i;-><init>(Lay0/a;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    iput v3, v0, Li2/i;->e:I

    .line 59
    .line 60
    invoke-static {p2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0
    :try_end_1
    .catch Li2/e; {:try_start_1 .. :try_end_1} :catch_0

    .line 64
    if-ne p0, v1, :cond_3

    .line 65
    .line 66
    return-object v1

    .line 67
    :catch_0
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0
.end method

.method public static final b(Lx2/s;Li2/p;Lay0/n;)Lx2/s;
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/material3/internal/DraggableAnchorsElement;

    .line 4
    .line 5
    invoke-direct {v0, p1, p2}, Landroidx/compose/material3/internal/DraggableAnchorsElement;-><init>(Li2/p;Lay0/n;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public static final c(Lg1/q;Lay0/n;)Lx2/s;
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;

    .line 4
    .line 5
    invoke-direct {v0, p0, p1}, Landroidx/compose/material3/internal/DraggableAnchorsElementV2;-><init>(Lg1/q;Lay0/n;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method
