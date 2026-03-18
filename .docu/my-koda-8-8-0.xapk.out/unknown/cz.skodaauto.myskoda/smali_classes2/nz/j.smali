.class public final Lnz/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:J

.field public B:Lqr0/q;

.field public final h:Llz/l;

.field public final i:Lkf0/e0;

.field public final j:Llz/k;

.field public final k:Lkf0/b0;

.field public final l:Lij0/a;

.field public final m:Llz/q;

.field public final n:Llz/s;

.field public final o:Lrq0/f;

.field public final p:Ljn0/c;

.field public final q:Lyt0/b;

.field public final r:Lcs0/n;

.field public final s:Llz/i;

.field public final t:Llz/e;

.field public final u:Llb0/g;

.field public final v:Lqf0/g;

.field public final w:Llz/j;

.field public final x:Lcf0/e;

.field public final y:Lkf0/v;

.field public z:Lmz/a;


# direct methods
.method public constructor <init>(Llz/l;Lkf0/e0;Llz/k;Lkf0/b0;Lij0/a;Llz/q;Llz/s;Lrq0/f;Ljn0/c;Lyt0/b;Lcs0/n;Llz/i;Llz/e;Llb0/g;Lqf0/g;Llz/j;Lcf0/e;Lkf0/v;)V
    .locals 4

    .line 1
    new-instance v0, Lnz/e;

    .line 2
    .line 3
    const/16 v1, 0x3fff

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v2, v1, v3, v3}, Lnz/e;-><init>(Ljava/lang/String;IZZ)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lnz/j;->h:Llz/l;

    .line 14
    .line 15
    iput-object p2, p0, Lnz/j;->i:Lkf0/e0;

    .line 16
    .line 17
    iput-object p3, p0, Lnz/j;->j:Llz/k;

    .line 18
    .line 19
    iput-object p4, p0, Lnz/j;->k:Lkf0/b0;

    .line 20
    .line 21
    iput-object p5, p0, Lnz/j;->l:Lij0/a;

    .line 22
    .line 23
    iput-object p6, p0, Lnz/j;->m:Llz/q;

    .line 24
    .line 25
    iput-object p7, p0, Lnz/j;->n:Llz/s;

    .line 26
    .line 27
    iput-object p8, p0, Lnz/j;->o:Lrq0/f;

    .line 28
    .line 29
    iput-object p9, p0, Lnz/j;->p:Ljn0/c;

    .line 30
    .line 31
    iput-object p10, p0, Lnz/j;->q:Lyt0/b;

    .line 32
    .line 33
    iput-object p11, p0, Lnz/j;->r:Lcs0/n;

    .line 34
    .line 35
    move-object/from16 p1, p12

    .line 36
    .line 37
    iput-object p1, p0, Lnz/j;->s:Llz/i;

    .line 38
    .line 39
    move-object/from16 p1, p13

    .line 40
    .line 41
    iput-object p1, p0, Lnz/j;->t:Llz/e;

    .line 42
    .line 43
    move-object/from16 p1, p14

    .line 44
    .line 45
    iput-object p1, p0, Lnz/j;->u:Llb0/g;

    .line 46
    .line 47
    move-object/from16 p1, p15

    .line 48
    .line 49
    iput-object p1, p0, Lnz/j;->v:Lqf0/g;

    .line 50
    .line 51
    move-object/from16 p1, p16

    .line 52
    .line 53
    iput-object p1, p0, Lnz/j;->w:Llz/j;

    .line 54
    .line 55
    move-object/from16 p1, p17

    .line 56
    .line 57
    iput-object p1, p0, Lnz/j;->x:Lcf0/e;

    .line 58
    .line 59
    move-object/from16 p1, p18

    .line 60
    .line 61
    iput-object p1, p0, Lnz/j;->y:Lkf0/v;

    .line 62
    .line 63
    sget-object p1, Lmz/a;->e:Lmz/a;

    .line 64
    .line 65
    iput-object p1, p0, Lnz/j;->z:Lmz/a;

    .line 66
    .line 67
    sget p1, Lmy0/c;->g:I

    .line 68
    .line 69
    const/16 p1, 0xa

    .line 70
    .line 71
    sget-object p2, Lmy0/e;->i:Lmy0/e;

    .line 72
    .line 73
    invoke-static {p1, p2}, Lmy0/h;->s(ILmy0/e;)J

    .line 74
    .line 75
    .line 76
    move-result-wide p1

    .line 77
    iput-wide p1, p0, Lnz/j;->A:J

    .line 78
    .line 79
    new-instance p1, Lnz/b;

    .line 80
    .line 81
    invoke-direct {p1, p0, v2, v3}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 85
    .line 86
    .line 87
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    new-instance p2, Lnz/b;

    .line 92
    .line 93
    const/4 p3, 0x1

    .line 94
    invoke-direct {p2, p0, v2, p3}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 95
    .line 96
    .line 97
    const/4 p3, 0x3

    .line 98
    invoke-static {p1, v2, v2, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 99
    .line 100
    .line 101
    new-instance p1, Lnz/b;

    .line 102
    .line 103
    const/4 p2, 0x2

    .line 104
    invoke-direct {p1, p0, v2, p2}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 108
    .line 109
    .line 110
    return-void
.end method

.method public static final h(Lnz/j;Lnz/e;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Lnz/i;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Lnz/i;

    .line 10
    .line 11
    iget v1, v0, Lnz/i;->i:I

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
    iput v1, v0, Lnz/i;->i:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lnz/i;

    .line 24
    .line 25
    invoke-direct {v0, p0, p2}, Lnz/i;-><init>(Lnz/j;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p2, v0, Lnz/i;->g:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lnz/i;->i:I

    .line 33
    .line 34
    const/4 v3, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-wide v1, v0, Lnz/i;->f:J

    .line 40
    .line 41
    iget-object p1, v0, Lnz/i;->e:Lmz/d;

    .line 42
    .line 43
    iget-object v0, v0, Lnz/i;->d:Lmz/a;

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p0, Lnz/j;->z:Lmz/a;

    .line 61
    .line 62
    iget-boolean p1, p1, Lnz/e;->i:Z

    .line 63
    .line 64
    if-eqz p1, :cond_3

    .line 65
    .line 66
    sget-object p1, Lmz/d;->d:Lmz/d;

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_3
    sget-object p1, Lmz/d;->e:Lmz/d;

    .line 70
    .line 71
    :goto_1
    iget-wide v4, p0, Lnz/j;->A:J

    .line 72
    .line 73
    iget-object v2, p0, Lnz/j;->B:Lqr0/q;

    .line 74
    .line 75
    if-nez v2, :cond_6

    .line 76
    .line 77
    iget-object v2, p0, Lnz/j;->r:Lcs0/n;

    .line 78
    .line 79
    iput-object p2, v0, Lnz/i;->d:Lmz/a;

    .line 80
    .line 81
    iput-object p1, v0, Lnz/i;->e:Lmz/d;

    .line 82
    .line 83
    iput-wide v4, v0, Lnz/i;->f:J

    .line 84
    .line 85
    iput v3, v0, Lnz/i;->i:I

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v2, v0}, Lcs0/n;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    if-ne v0, v1, :cond_4

    .line 95
    .line 96
    return-object v1

    .line 97
    :cond_4
    move-object v1, v0

    .line 98
    move-object v0, p2

    .line 99
    move-object p2, v1

    .line 100
    move-wide v1, v4

    .line 101
    :goto_2
    move-object v3, p2

    .line 102
    check-cast v3, Lqr0/q;

    .line 103
    .line 104
    iget-object p0, p0, Lnz/j;->z:Lmz/a;

    .line 105
    .line 106
    sget-object v3, Lmz/a;->f:Lmz/a;

    .line 107
    .line 108
    if-ne p0, v3, :cond_5

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_5
    const/4 p2, 0x0

    .line 112
    :goto_3
    move-object p0, p2

    .line 113
    check-cast p0, Lqr0/q;

    .line 114
    .line 115
    move-object v8, p0

    .line 116
    move-object v4, v0

    .line 117
    move-wide v5, v1

    .line 118
    :goto_4
    move-object v7, p1

    .line 119
    goto :goto_5

    .line 120
    :cond_6
    move-object v8, v2

    .line 121
    move-wide v5, v4

    .line 122
    move-object v4, p2

    .line 123
    goto :goto_4

    .line 124
    :goto_5
    new-instance v3, Lmz/b;

    .line 125
    .line 126
    invoke-direct/range {v3 .. v8}, Lmz/b;-><init>(Lmz/a;JLmz/d;Lqr0/q;)V

    .line 127
    .line 128
    .line 129
    return-object v3
.end method


# virtual methods
.method public final j(Lmz/f;Lrx0/c;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lnz/h;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lnz/h;

    .line 13
    .line 14
    iget v4, v3, Lnz/h;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lnz/h;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lnz/h;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lnz/h;-><init>(Lnz/j;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lnz/h;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lnz/h;->g:I

    .line 36
    .line 37
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    const/4 v7, 0x2

    .line 40
    const/4 v8, 0x1

    .line 41
    if-eqz v5, :cond_3

    .line 42
    .line 43
    if-eq v5, v8, :cond_2

    .line 44
    .line 45
    if-ne v5, v7, :cond_1

    .line 46
    .line 47
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-object v6

    .line 51
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    iget-object v1, v3, Lnz/h;->d:Lmz/f;

    .line 60
    .line 61
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-object v2, v1, Lmz/f;->a:Ljava/time/OffsetDateTime;

    .line 69
    .line 70
    if-eqz v2, :cond_5

    .line 71
    .line 72
    invoke-static {v2}, Lvo/a;->a(Ljava/time/OffsetDateTime;)J

    .line 73
    .line 74
    .line 75
    move-result-wide v9

    .line 76
    invoke-static {v9, v10}, Lmy0/c;->i(J)Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-eqz v2, :cond_5

    .line 81
    .line 82
    sget-object v2, Lmy0/e;->i:Lmy0/e;

    .line 83
    .line 84
    invoke-static {v8, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 85
    .line 86
    .line 87
    move-result-wide v9

    .line 88
    iput-object v1, v3, Lnz/h;->d:Lmz/f;

    .line 89
    .line 90
    iput v8, v3, Lnz/h;->g:I

    .line 91
    .line 92
    invoke-static {v9, v10, v3}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    if-ne v2, v4, :cond_4

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_4
    :goto_1
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    move-object v8, v2

    .line 104
    check-cast v8, Lnz/e;

    .line 105
    .line 106
    iget-object v2, v0, Lnz/j;->z:Lmz/a;

    .line 107
    .line 108
    iget-object v5, v0, Lnz/j;->l:Lij0/a;

    .line 109
    .line 110
    invoke-static {v5, v2, v1}, Ljp/db;->c(Lij0/a;Lmz/a;Lmz/f;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    const/16 v20, 0x0

    .line 115
    .line 116
    const/16 v21, 0x3ffd

    .line 117
    .line 118
    const/4 v9, 0x0

    .line 119
    const/4 v11, 0x0

    .line 120
    const/4 v12, 0x0

    .line 121
    const/4 v13, 0x0

    .line 122
    const/4 v14, 0x0

    .line 123
    const/4 v15, 0x0

    .line 124
    const/16 v16, 0x0

    .line 125
    .line 126
    const/16 v17, 0x0

    .line 127
    .line 128
    const/16 v18, 0x0

    .line 129
    .line 130
    const/16 v19, 0x0

    .line 131
    .line 132
    invoke-static/range {v8 .. v21}, Lnz/e;->a(Lnz/e;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLnz/d;Llf0/i;ZZZI)Lnz/e;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 137
    .line 138
    .line 139
    const/4 v2, 0x0

    .line 140
    iput-object v2, v3, Lnz/h;->d:Lmz/f;

    .line 141
    .line 142
    iput v7, v3, Lnz/h;->g:I

    .line 143
    .line 144
    invoke-virtual {v0, v1, v3}, Lnz/j;->j(Lmz/f;Lrx0/c;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    if-ne v0, v4, :cond_5

    .line 149
    .line 150
    :goto_2
    return-object v4

    .line 151
    :cond_5
    return-object v6
.end method
