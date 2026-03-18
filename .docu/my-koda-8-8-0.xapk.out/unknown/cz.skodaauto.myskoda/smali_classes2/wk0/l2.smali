.class public final Lwk0/l2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Luk0/b0;

.field public final i:Lro0/e;

.field public final j:Luk0/f0;

.field public final k:Luk0/x;

.field public final l:Luk0/f;

.field public final m:Luk0/l0;

.field public final n:Lro0/a;

.field public final o:Ljn0/c;

.field public final p:Lsf0/a;

.field public final q:Lvy0/i0;


# direct methods
.method public constructor <init>(Luk0/b0;Lro0/e;Luk0/f0;Luk0/x;Luk0/f;Luk0/l0;Lro0/a;Ljn0/c;Lsf0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lwk0/h2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lwk0/h2;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lwk0/l2;->h:Luk0/b0;

    .line 11
    .line 12
    iput-object p2, p0, Lwk0/l2;->i:Lro0/e;

    .line 13
    .line 14
    iput-object p3, p0, Lwk0/l2;->j:Luk0/f0;

    .line 15
    .line 16
    iput-object p4, p0, Lwk0/l2;->k:Luk0/x;

    .line 17
    .line 18
    iput-object p5, p0, Lwk0/l2;->l:Luk0/f;

    .line 19
    .line 20
    iput-object p6, p0, Lwk0/l2;->m:Luk0/l0;

    .line 21
    .line 22
    iput-object p7, p0, Lwk0/l2;->n:Lro0/a;

    .line 23
    .line 24
    iput-object p8, p0, Lwk0/l2;->o:Ljn0/c;

    .line 25
    .line 26
    iput-object p9, p0, Lwk0/l2;->p:Lsf0/a;

    .line 27
    .line 28
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    new-instance p2, Lwk0/g2;

    .line 33
    .line 34
    const/4 p3, 0x2

    .line 35
    const/4 p4, 0x0

    .line 36
    invoke-direct {p2, p0, p4, p3}, Lwk0/g2;-><init>(Lwk0/l2;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    const/4 p3, 0x3

    .line 40
    invoke-static {p1, p4, p2, p3}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iput-object p1, p0, Lwk0/l2;->q:Lvy0/i0;

    .line 45
    .line 46
    new-instance p1, Lwk0/g2;

    .line 47
    .line 48
    const/4 p2, 0x0

    .line 49
    invoke-direct {p1, p0, p4, p2}, Lwk0/g2;-><init>(Lwk0/l2;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 53
    .line 54
    .line 55
    new-instance p1, Lwk0/g2;

    .line 56
    .line 57
    const/4 p2, 0x1

    .line 58
    invoke-direct {p1, p0, p4, p2}, Lwk0/g2;-><init>(Lwk0/l2;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public static final h(Lwk0/l2;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Lwk0/j2;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Lwk0/j2;

    .line 10
    .line 11
    iget v1, v0, Lwk0/j2;->g:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lwk0/j2;->g:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lwk0/j2;

    .line 24
    .line 25
    invoke-direct {v0, p0, p2}, Lwk0/j2;-><init>(Lwk0/l2;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p2, v0, Lwk0/j2;->e:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lwk0/j2;->g:I

    .line 33
    .line 34
    const/4 v3, 0x1

    .line 35
    const/4 v4, 0x2

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v3, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    iget-object p1, v0, Lwk0/j2;->d:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object p2, p0, Lwk0/l2;->l:Luk0/f;

    .line 64
    .line 65
    invoke-static {p2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    iget-object p2, p0, Lwk0/l2;->n:Lro0/a;

    .line 69
    .line 70
    iput-object p1, v0, Lwk0/j2;->d:Ljava/lang/String;

    .line 71
    .line 72
    iput v3, v0, Lwk0/j2;->g:I

    .line 73
    .line 74
    invoke-virtual {p2, p1}, Lro0/a;->b(Ljava/lang/String;)Lne0/n;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    if-ne p2, v1, :cond_4

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    :goto_1
    check-cast p2, Lyy0/i;

    .line 82
    .line 83
    iget-object v2, p0, Lwk0/l2;->p:Lsf0/a;

    .line 84
    .line 85
    const/4 v3, 0x0

    .line 86
    invoke-static {p2, v2, v3}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    new-instance v2, Ltr0/e;

    .line 91
    .line 92
    const/16 v5, 0x1d

    .line 93
    .line 94
    invoke-direct {v2, v5, p0, p1, v3}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 95
    .line 96
    .line 97
    iput-object v3, v0, Lwk0/j2;->d:Ljava/lang/String;

    .line 98
    .line 99
    iput v4, v0, Lwk0/j2;->g:I

    .line 100
    .line 101
    invoke-static {v2, v0, p2}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_5

    .line 106
    .line 107
    :goto_2
    return-object v1

    .line 108
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0
.end method

.method public static final j(Lwk0/l2;Lwk0/h2;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lwk0/k2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lwk0/k2;

    .line 7
    .line 8
    iget v1, v0, Lwk0/k2;->g:I

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
    iput v1, v0, Lwk0/k2;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwk0/k2;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lwk0/k2;-><init>(Lwk0/l2;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lwk0/k2;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwk0/k2;->g:I

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
    iget-object p1, v0, Lwk0/k2;->d:Lwk0/h2;

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
    iget-object p0, p0, Lwk0/l2;->q:Lvy0/i0;

    .line 54
    .line 55
    iput-object p1, v0, Lwk0/k2;->d:Lwk0/h2;

    .line 56
    .line 57
    iput v3, v0, Lwk0/k2;->g:I

    .line 58
    .line 59
    invoke-virtual {p0, v0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-ne p2, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    new-instance p1, Lwk0/h2;

    .line 76
    .line 77
    invoke-direct {p1, p0}, Lwk0/h2;-><init>(Z)V

    .line 78
    .line 79
    .line 80
    return-object p1
.end method
