.class public final Lpp0/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lml0/i;

.field public final b:Lfg0/d;

.field public final c:Lpp0/c0;


# direct methods
.method public constructor <init>(Lml0/i;Lfg0/d;Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/k1;->a:Lml0/i;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/k1;->b:Lfg0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/k1;->c:Lpp0/c0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lqp0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lpp0/k1;->d(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lpp0/g1;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lpp0/g1;

    .line 11
    .line 12
    iget v3, v2, Lpp0/g1;->f:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lpp0/g1;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lpp0/g1;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lpp0/g1;-><init>(Lpp0/k1;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lpp0/g1;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lpp0/g1;->f:I

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v4, :cond_2

    .line 37
    .line 38
    if-ne v4, v5, :cond_1

    .line 39
    .line 40
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw v0

    .line 52
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object v0, v0, Lpp0/k1;->b:Lfg0/d;

    .line 56
    .line 57
    invoke-virtual {v0}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    check-cast v0, Lyy0/i;

    .line 62
    .line 63
    iput v5, v2, Lpp0/g1;->f:I

    .line 64
    .line 65
    invoke-static {v0, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    if-ne v1, v3, :cond_3

    .line 70
    .line 71
    return-object v3

    .line 72
    :cond_3
    :goto_1
    check-cast v1, Lgg0/a;

    .line 73
    .line 74
    if-eqz v1, :cond_4

    .line 75
    .line 76
    new-instance v2, Lqp0/b0;

    .line 77
    .line 78
    new-instance v6, Lxj0/f;

    .line 79
    .line 80
    iget-wide v3, v1, Lgg0/a;->a:D

    .line 81
    .line 82
    iget-wide v0, v1, Lgg0/a;->b:D

    .line 83
    .line 84
    invoke-direct {v6, v3, v4, v0, v1}, Lxj0/f;-><init>(DD)V

    .line 85
    .line 86
    .line 87
    const/16 v17, 0x0

    .line 88
    .line 89
    const/16 v16, 0x0

    .line 90
    .line 91
    const/4 v3, 0x0

    .line 92
    const/4 v4, 0x0

    .line 93
    sget-object v5, Lqp0/h0;->a:Lqp0/h0;

    .line 94
    .line 95
    const/4 v7, 0x0

    .line 96
    const/4 v8, 0x0

    .line 97
    const/4 v9, 0x0

    .line 98
    const/4 v10, 0x0

    .line 99
    const/4 v11, 0x0

    .line 100
    const/4 v12, 0x0

    .line 101
    const/4 v13, 0x0

    .line 102
    const/4 v14, 0x0

    .line 103
    const/4 v15, 0x0

    .line 104
    const/16 v18, 0x0

    .line 105
    .line 106
    invoke-direct/range {v2 .. v18}, Lqp0/b0;-><init>(Ljava/lang/String;Ljava/lang/String;Lqp0/t0;Lxj0/f;Lbl0/a;Lqr0/d;Lmy0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lmy0/c;Lqp0/a0;Ljava/lang/String;Lqp0/z;Ljava/lang/Boolean;Ljava/lang/Boolean;Lqp0/n;)V

    .line 107
    .line 108
    .line 109
    return-object v2

    .line 110
    :cond_4
    const/4 v0, 0x0

    .line 111
    return-object v0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lpp0/i1;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lpp0/i1;

    .line 11
    .line 12
    iget v3, v2, Lpp0/i1;->f:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lpp0/i1;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lpp0/i1;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lpp0/i1;-><init>(Lpp0/k1;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lpp0/i1;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lpp0/i1;->f:I

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v4, :cond_2

    .line 37
    .line 38
    if-ne v4, v5, :cond_1

    .line 39
    .line 40
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw v0

    .line 52
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object v0, v0, Lpp0/k1;->a:Lml0/i;

    .line 56
    .line 57
    invoke-virtual {v0}, Lml0/i;->invoke()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    check-cast v0, Lyy0/i;

    .line 62
    .line 63
    new-instance v1, Lhg/q;

    .line 64
    .line 65
    const/16 v4, 0x19

    .line 66
    .line 67
    invoke-direct {v1, v0, v4}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 68
    .line 69
    .line 70
    iput v5, v2, Lpp0/i1;->f:I

    .line 71
    .line 72
    invoke-static {v1, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    if-ne v1, v3, :cond_3

    .line 77
    .line 78
    return-object v3

    .line 79
    :cond_3
    :goto_1
    check-cast v1, Loo0/d;

    .line 80
    .line 81
    if-eqz v1, :cond_4

    .line 82
    .line 83
    new-instance v2, Lqp0/b0;

    .line 84
    .line 85
    iget-object v6, v1, Loo0/d;->d:Lxj0/f;

    .line 86
    .line 87
    const/16 v17, 0x0

    .line 88
    .line 89
    const/16 v16, 0x0

    .line 90
    .line 91
    const/4 v3, 0x0

    .line 92
    const/4 v4, 0x0

    .line 93
    sget-object v5, Lqp0/s0;->a:Lqp0/s0;

    .line 94
    .line 95
    const/4 v7, 0x0

    .line 96
    const/4 v8, 0x0

    .line 97
    const/4 v9, 0x0

    .line 98
    const/4 v10, 0x0

    .line 99
    const/4 v11, 0x0

    .line 100
    const/4 v12, 0x0

    .line 101
    const/4 v13, 0x0

    .line 102
    const/4 v14, 0x0

    .line 103
    const/4 v15, 0x0

    .line 104
    const/16 v18, 0x0

    .line 105
    .line 106
    invoke-direct/range {v2 .. v18}, Lqp0/b0;-><init>(Ljava/lang/String;Ljava/lang/String;Lqp0/t0;Lxj0/f;Lbl0/a;Lqr0/d;Lmy0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lmy0/c;Lqp0/a0;Ljava/lang/String;Lqp0/z;Ljava/lang/Boolean;Ljava/lang/Boolean;Lqp0/n;)V

    .line 107
    .line 108
    .line 109
    return-object v2

    .line 110
    :cond_4
    const/4 v0, 0x0

    .line 111
    return-object v0
.end method

.method public final d(Lqp0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lpp0/j1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lpp0/j1;

    .line 7
    .line 8
    iget v1, v0, Lpp0/j1;->g:I

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
    iput v1, v0, Lpp0/j1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/j1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lpp0/j1;-><init>(Lpp0/k1;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lpp0/j1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/j1;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p1, v0, Lpp0/j1;->d:Lqp0/b0;

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    iget-object p1, v0, Lpp0/j1;->d:Lqp0/b0;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object p1, v0, Lpp0/j1;->d:Lqp0/b0;

    .line 63
    .line 64
    iput v4, v0, Lpp0/j1;->g:I

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Lpp0/k1;->c(Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    if-ne p2, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p2, Lqp0/b0;

    .line 74
    .line 75
    if-nez p2, :cond_6

    .line 76
    .line 77
    iput-object p1, v0, Lpp0/j1;->d:Lqp0/b0;

    .line 78
    .line 79
    iput v3, v0, Lpp0/j1;->g:I

    .line 80
    .line 81
    invoke-virtual {p0, v0}, Lpp0/k1;->b(Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    if-ne p2, v1, :cond_5

    .line 86
    .line 87
    :goto_2
    return-object v1

    .line 88
    :cond_5
    :goto_3
    check-cast p2, Lqp0/b0;

    .line 89
    .line 90
    :cond_6
    new-instance v0, Lqp0/p;

    .line 91
    .line 92
    filled-new-array {p2, p1}, [Lqp0/b0;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-static {p1}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-direct {v0, p1}, Lqp0/p;-><init>(Ljava/util/List;)V

    .line 101
    .line 102
    .line 103
    iget-object p0, p0, Lpp0/k1;->c:Lpp0/c0;

    .line 104
    .line 105
    check-cast p0, Lnp0/b;

    .line 106
    .line 107
    iget-object p0, p0, Lnp0/b;->b:Lyy0/c2;

    .line 108
    .line 109
    invoke-virtual {p0, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    new-instance p0, Lne0/e;

    .line 113
    .line 114
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    return-object p0
.end method
