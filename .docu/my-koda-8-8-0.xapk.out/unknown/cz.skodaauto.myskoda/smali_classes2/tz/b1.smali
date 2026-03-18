.class public final Ltz/b1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final v:Lrd0/n;


# instance fields
.field public final h:Lqd0/b;

.field public final i:Lqd0/g;

.field public final j:Lqd0/k;

.field public final k:Lqd0/o;

.field public final l:Ltr0/b;

.field public final m:Lqd0/v;

.field public final n:Lqd0/g0;

.field public final o:Lqd0/f0;

.field public final p:Lqd0/t0;

.field public final q:Lkg0/d;

.field public final r:Lqd0/a;

.field public final s:Lqd0/v0;

.field public final t:Lrq0/f;

.field public final u:Lij0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lrd0/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lrd0/n;-><init>(Lqr0/a;Lrd0/c0;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltz/b1;->v:Lrd0/n;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lqd0/b;Lqd0/g;Lqd0/k;Lqd0/o;Ltr0/b;Lqd0/v;Lqd0/g0;Lqd0/f0;Lqd0/t0;Lkg0/d;Lqd0/a;Lqd0/v0;Lrq0/f;Lij0/a;)V
    .locals 13

    .line 1
    new-instance v0, Ltz/z0;

    .line 2
    .line 3
    const/16 v1, 0xfff

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    and-int/2addr v1, v2

    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    move v1, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v1, 0x0

    .line 13
    :goto_0
    const/16 v4, 0xfff

    .line 14
    .line 15
    and-int/lit8 v5, v4, 0x4

    .line 16
    .line 17
    if-eqz v5, :cond_1

    .line 18
    .line 19
    move v5, v3

    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move v5, v3

    .line 22
    move v3, v2

    .line 23
    :goto_1
    and-int/lit8 v6, v4, 0x8

    .line 24
    .line 25
    if-eqz v6, :cond_2

    .line 26
    .line 27
    move v2, v5

    .line 28
    :cond_2
    and-int/lit8 v5, v4, 0x10

    .line 29
    .line 30
    const/4 v6, 0x0

    .line 31
    if-eqz v5, :cond_3

    .line 32
    .line 33
    move-object v5, v6

    .line 34
    goto :goto_2

    .line 35
    :cond_3
    const/4 v5, 0x0

    .line 36
    :goto_2
    and-int/lit8 v7, v4, 0x20

    .line 37
    .line 38
    if-eqz v7, :cond_4

    .line 39
    .line 40
    goto :goto_3

    .line 41
    :cond_4
    const/4 v6, 0x0

    .line 42
    :goto_3
    and-int/lit16 v4, v4, 0x80

    .line 43
    .line 44
    if-eqz v4, :cond_5

    .line 45
    .line 46
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    :goto_4
    move-object v8, v4

    .line 49
    goto :goto_5

    .line 50
    :cond_5
    const/4 v4, 0x0

    .line 51
    goto :goto_4

    .line 52
    :goto_5
    const/4 v11, 0x0

    .line 53
    const/4 v12, 0x0

    .line 54
    move v4, v2

    .line 55
    const/4 v2, 0x0

    .line 56
    const v7, 0x7f120373

    .line 57
    .line 58
    .line 59
    const/4 v9, 0x1

    .line 60
    const/4 v10, 0x0

    .line 61
    invoke-direct/range {v0 .. v12}, Ltz/z0;-><init>(ZZZZLrd0/n;Ljava/lang/String;ILjava/util/List;ZZZZ)V

    .line 62
    .line 63
    .line 64
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 65
    .line 66
    .line 67
    iput-object p1, p0, Ltz/b1;->h:Lqd0/b;

    .line 68
    .line 69
    iput-object p2, p0, Ltz/b1;->i:Lqd0/g;

    .line 70
    .line 71
    move-object/from16 p1, p3

    .line 72
    .line 73
    iput-object p1, p0, Ltz/b1;->j:Lqd0/k;

    .line 74
    .line 75
    move-object/from16 p1, p4

    .line 76
    .line 77
    iput-object p1, p0, Ltz/b1;->k:Lqd0/o;

    .line 78
    .line 79
    move-object/from16 p1, p5

    .line 80
    .line 81
    iput-object p1, p0, Ltz/b1;->l:Ltr0/b;

    .line 82
    .line 83
    move-object/from16 p1, p6

    .line 84
    .line 85
    iput-object p1, p0, Ltz/b1;->m:Lqd0/v;

    .line 86
    .line 87
    move-object/from16 p1, p7

    .line 88
    .line 89
    iput-object p1, p0, Ltz/b1;->n:Lqd0/g0;

    .line 90
    .line 91
    move-object/from16 p1, p8

    .line 92
    .line 93
    iput-object p1, p0, Ltz/b1;->o:Lqd0/f0;

    .line 94
    .line 95
    move-object/from16 p1, p9

    .line 96
    .line 97
    iput-object p1, p0, Ltz/b1;->p:Lqd0/t0;

    .line 98
    .line 99
    move-object/from16 p1, p10

    .line 100
    .line 101
    iput-object p1, p0, Ltz/b1;->q:Lkg0/d;

    .line 102
    .line 103
    move-object/from16 p1, p11

    .line 104
    .line 105
    iput-object p1, p0, Ltz/b1;->r:Lqd0/a;

    .line 106
    .line 107
    move-object/from16 p1, p12

    .line 108
    .line 109
    iput-object p1, p0, Ltz/b1;->s:Lqd0/v0;

    .line 110
    .line 111
    move-object/from16 p1, p13

    .line 112
    .line 113
    iput-object p1, p0, Ltz/b1;->t:Lrq0/f;

    .line 114
    .line 115
    move-object/from16 p1, p14

    .line 116
    .line 117
    iput-object p1, p0, Ltz/b1;->u:Lij0/a;

    .line 118
    .line 119
    new-instance p1, Ltz/w0;

    .line 120
    .line 121
    const/4 p2, 0x0

    .line 122
    const/4 v0, 0x0

    .line 123
    invoke-direct {p1, p0, v0, p2}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 127
    .line 128
    .line 129
    new-instance p1, Ltz/w0;

    .line 130
    .line 131
    const/4 p2, 0x1

    .line 132
    invoke-direct {p1, p0, v0, p2}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 136
    .line 137
    .line 138
    new-instance p1, Ltz/w0;

    .line 139
    .line 140
    const/4 p2, 0x2

    .line 141
    invoke-direct {p1, p0, v0, p2}, Ltz/w0;-><init>(Ltz/b1;Lkotlin/coroutines/Continuation;I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 145
    .line 146
    .line 147
    return-void
.end method

.method public static final h(Ltz/b1;Lrx0/c;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Ltz/a1;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Ltz/a1;

    .line 11
    .line 12
    iget v3, v2, Ltz/a1;->h:I

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
    iput v3, v2, Ltz/a1;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Ltz/a1;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Ltz/a1;-><init>(Ltz/b1;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Ltz/a1;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Ltz/a1;->h:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    if-ne v4, v6, :cond_1

    .line 41
    .line 42
    iget-object v0, v2, Ltz/a1;->e:Ltz/z0;

    .line 43
    .line 44
    iget-object v2, v2, Ltz/a1;->d:Ltz/b1;

    .line 45
    .line 46
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object v7, v0

    .line 50
    move-object v0, v2

    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw v0

    .line 60
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    check-cast v1, Ltz/z0;

    .line 68
    .line 69
    iget-object v4, v0, Ltz/b1;->r:Lqd0/a;

    .line 70
    .line 71
    iput-object v0, v2, Ltz/a1;->d:Ltz/b1;

    .line 72
    .line 73
    iput-object v1, v2, Ltz/a1;->e:Ltz/z0;

    .line 74
    .line 75
    iput v6, v2, Ltz/a1;->h:I

    .line 76
    .line 77
    invoke-virtual {v4, v5, v2}, Lqd0/a;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    if-ne v2, v3, :cond_3

    .line 82
    .line 83
    return-object v3

    .line 84
    :cond_3
    move-object v7, v1

    .line 85
    move-object v1, v2

    .line 86
    :goto_1
    check-cast v1, Ljava/lang/Boolean;

    .line 87
    .line 88
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    xor-int/lit8 v16, v1, 0x1

    .line 93
    .line 94
    const/16 v19, 0x0

    .line 95
    .line 96
    const/16 v20, 0xeff

    .line 97
    .line 98
    const/4 v8, 0x0

    .line 99
    const/4 v9, 0x0

    .line 100
    const/4 v10, 0x0

    .line 101
    const/4 v11, 0x0

    .line 102
    const/4 v12, 0x0

    .line 103
    const/4 v13, 0x0

    .line 104
    const/4 v14, 0x0

    .line 105
    const/4 v15, 0x0

    .line 106
    const/16 v17, 0x0

    .line 107
    .line 108
    const/16 v18, 0x0

    .line 109
    .line 110
    invoke-static/range {v7 .. v20}, Ltz/z0;->a(Ltz/z0;ZZZZLrd0/n;Ljava/lang/String;ILjava/util/List;ZZZZI)Ltz/z0;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 115
    .line 116
    .line 117
    return-object v5
.end method
