.class public final Lg60/b0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final t:J

.field public static final u:J

.field public static final synthetic v:I


# instance fields
.field public final h:Lkf0/z;

.field public final i:Lml0/i;

.field public final j:Lal0/z0;

.field public final k:Lkf0/k;

.field public final l:Lcs0/l;

.field public final m:Lij0/a;

.field public final n:Lhh0/a;

.field public final o:Le60/i;

.field public final p:Lpp0/h;

.field public final q:Lrq0/d;

.field public final r:Lrq0/f;

.field public final s:Lvy0/i0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 7
    .line 8
    .line 9
    move-result-wide v1

    .line 10
    sput-wide v1, Lg60/b0;->t:J

    .line 11
    .line 12
    const/4 v1, 0x5

    .line 13
    invoke-static {v1, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    const/16 v2, 0x3b

    .line 18
    .line 19
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 20
    .line 21
    invoke-static {v2, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v2

    .line 25
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->k(JJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    sput-wide v0, Lg60/b0;->u:J

    .line 30
    .line 31
    return-void
.end method

.method public constructor <init>(Lml0/c;Lnn0/t;Lkf0/z;Lml0/i;Lal0/z0;Lkf0/k;Lcs0/l;Lij0/a;Lhh0/a;Le60/i;Lpp0/h;Lrq0/d;Lrq0/f;)V
    .locals 3

    .line 1
    new-instance v0, Lg60/q;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v2, v1}, Lg60/q;-><init>(Lg60/p;Lg60/k;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p3, p0, Lg60/b0;->h:Lkf0/z;

    .line 13
    .line 14
    iput-object p4, p0, Lg60/b0;->i:Lml0/i;

    .line 15
    .line 16
    iput-object p5, p0, Lg60/b0;->j:Lal0/z0;

    .line 17
    .line 18
    iput-object p6, p0, Lg60/b0;->k:Lkf0/k;

    .line 19
    .line 20
    iput-object p7, p0, Lg60/b0;->l:Lcs0/l;

    .line 21
    .line 22
    iput-object p8, p0, Lg60/b0;->m:Lij0/a;

    .line 23
    .line 24
    iput-object p9, p0, Lg60/b0;->n:Lhh0/a;

    .line 25
    .line 26
    iput-object p10, p0, Lg60/b0;->o:Le60/i;

    .line 27
    .line 28
    iput-object p11, p0, Lg60/b0;->p:Lpp0/h;

    .line 29
    .line 30
    iput-object p12, p0, Lg60/b0;->q:Lrq0/d;

    .line 31
    .line 32
    move-object/from16 p3, p13

    .line 33
    .line 34
    iput-object p3, p0, Lg60/b0;->r:Lrq0/f;

    .line 35
    .line 36
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 37
    .line 38
    .line 39
    move-result-object p3

    .line 40
    new-instance p4, Lg60/x;

    .line 41
    .line 42
    const/4 p5, 0x1

    .line 43
    invoke-direct {p4, p0, v2, p5}, Lg60/x;-><init>(Lg60/b0;Lkotlin/coroutines/Continuation;I)V

    .line 44
    .line 45
    .line 46
    const/4 p5, 0x3

    .line 47
    invoke-static {p3, v2, p4, p5}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 48
    .line 49
    .line 50
    move-result-object p3

    .line 51
    iput-object p3, p0, Lg60/b0;->s:Lvy0/i0;

    .line 52
    .line 53
    new-instance p3, Le60/m;

    .line 54
    .line 55
    const/16 p4, 0x1b

    .line 56
    .line 57
    invoke-direct {p3, p4, p1, p0, v2}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, p3}, Lql0/j;->b(Lay0/n;)V

    .line 61
    .line 62
    .line 63
    new-instance p1, Le60/m;

    .line 64
    .line 65
    const/16 p3, 0x1c

    .line 66
    .line 67
    invoke-direct {p1, p3, p2, p0, v2}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 71
    .line 72
    .line 73
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    new-instance p2, La7/k;

    .line 78
    .line 79
    const/16 p3, 0x18

    .line 80
    .line 81
    invoke-direct {p2, p0, v2, p3}, La7/k;-><init>(Landroidx/lifecycle/b1;Lkotlin/coroutines/Continuation;I)V

    .line 82
    .line 83
    .line 84
    invoke-static {p1, v2, v2, p2, p5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 85
    .line 86
    .line 87
    return-void
.end method

.method public static final h(Lg60/b0;JLrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    instance-of v4, v3, Lg60/a0;

    .line 11
    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    move-object v4, v3

    .line 15
    check-cast v4, Lg60/a0;

    .line 16
    .line 17
    iget v5, v4, Lg60/a0;->j:I

    .line 18
    .line 19
    const/high16 v6, -0x80000000

    .line 20
    .line 21
    and-int v7, v5, v6

    .line 22
    .line 23
    if-eqz v7, :cond_0

    .line 24
    .line 25
    sub-int/2addr v5, v6

    .line 26
    iput v5, v4, Lg60/a0;->j:I

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance v4, Lg60/a0;

    .line 30
    .line 31
    invoke-direct {v4, v0, v3}, Lg60/a0;-><init>(Lg60/b0;Lrx0/c;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget-object v3, v4, Lg60/a0;->h:Ljava/lang/Object;

    .line 35
    .line 36
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    iget v6, v4, Lg60/a0;->j:I

    .line 39
    .line 40
    const/4 v7, 0x2

    .line 41
    const/4 v8, 0x1

    .line 42
    if-eqz v6, :cond_3

    .line 43
    .line 44
    if-eq v6, v8, :cond_2

    .line 45
    .line 46
    if-ne v6, v7, :cond_1

    .line 47
    .line 48
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto/16 :goto_4

    .line 52
    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    iget-wide v1, v4, Lg60/a0;->g:J

    .line 62
    .line 63
    iget-wide v8, v4, Lg60/a0;->f:J

    .line 64
    .line 65
    iget-wide v10, v4, Lg60/a0;->e:J

    .line 66
    .line 67
    iget-wide v12, v4, Lg60/a0;->d:J

    .line 68
    .line 69
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_3
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    sget v3, Lmy0/c;->g:I

    .line 77
    .line 78
    sget-object v3, Lmy0/e;->i:Lmy0/e;

    .line 79
    .line 80
    invoke-static {v1, v2, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 81
    .line 82
    .line 83
    move-result-wide v9

    .line 84
    invoke-static {v9, v10, v3}, Lmy0/h;->t(JLmy0/e;)J

    .line 85
    .line 86
    .line 87
    move-result-wide v10

    .line 88
    invoke-static {v8, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 89
    .line 90
    .line 91
    move-result-wide v12

    .line 92
    invoke-static {v10, v11, v12, v13}, Lmy0/c;->k(JJ)J

    .line 93
    .line 94
    .line 95
    move-result-wide v12

    .line 96
    invoke-static {v12, v13, v1, v2}, Lmy0/c;->j(JJ)J

    .line 97
    .line 98
    .line 99
    move-result-wide v14

    .line 100
    sget-object v3, Lmy0/e;->h:Lmy0/e;

    .line 101
    .line 102
    invoke-static {v14, v15, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 103
    .line 104
    .line 105
    move-result-wide v14

    .line 106
    sget-wide v7, Lg60/b0;->t:J

    .line 107
    .line 108
    invoke-static {v7, v8, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 109
    .line 110
    .line 111
    move-result-wide v7

    .line 112
    cmp-long v7, v14, v7

    .line 113
    .line 114
    if-gez v7, :cond_5

    .line 115
    .line 116
    invoke-virtual {v0, v12, v13}, Lg60/b0;->l(J)V

    .line 117
    .line 118
    .line 119
    invoke-static {v14, v15, v3}, Lmy0/h;->t(JLmy0/e;)J

    .line 120
    .line 121
    .line 122
    move-result-wide v7

    .line 123
    iput-wide v1, v4, Lg60/a0;->d:J

    .line 124
    .line 125
    iput-wide v10, v4, Lg60/a0;->e:J

    .line 126
    .line 127
    iput-wide v12, v4, Lg60/a0;->f:J

    .line 128
    .line 129
    iput-wide v14, v4, Lg60/a0;->g:J

    .line 130
    .line 131
    const/4 v6, 0x1

    .line 132
    iput v6, v4, Lg60/a0;->j:I

    .line 133
    .line 134
    invoke-static {v7, v8, v4}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v3

    .line 138
    if-ne v3, v5, :cond_4

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_4
    move-wide v8, v12

    .line 142
    move-wide v12, v1

    .line 143
    move-wide v1, v14

    .line 144
    :goto_1
    move-wide v14, v1

    .line 145
    goto :goto_2

    .line 146
    :cond_5
    move-wide v8, v12

    .line 147
    move-wide v12, v1

    .line 148
    :goto_2
    iput-wide v12, v4, Lg60/a0;->d:J

    .line 149
    .line 150
    iput-wide v10, v4, Lg60/a0;->e:J

    .line 151
    .line 152
    iput-wide v8, v4, Lg60/a0;->f:J

    .line 153
    .line 154
    iput-wide v14, v4, Lg60/a0;->g:J

    .line 155
    .line 156
    const/4 v1, 0x2

    .line 157
    iput v1, v4, Lg60/a0;->j:I

    .line 158
    .line 159
    invoke-virtual {v0, v10, v11, v4}, Lg60/b0;->j(JLrx0/c;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    if-ne v0, v5, :cond_6

    .line 164
    .line 165
    :goto_3
    return-object v5

    .line 166
    :cond_6
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    return-object v0
.end method


# virtual methods
.method public final j(JLrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lg60/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lg60/y;

    .line 7
    .line 8
    iget v1, v0, Lg60/y;->g:I

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
    iput v1, v0, Lg60/y;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg60/y;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lg60/y;-><init>(Lg60/b0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lg60/y;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg60/y;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    sget-wide v4, Lg60/b0;->t:J

    .line 34
    .line 35
    const/4 v6, 0x2

    .line 36
    const/4 v7, 0x1

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v7, :cond_2

    .line 40
    .line 41
    if-ne v2, v6, :cond_1

    .line 42
    .line 43
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-object v3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-wide p1, v0, Lg60/y;->d:J

    .line 56
    .line 57
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p1, p2}, Lg60/b0;->l(J)V

    .line 65
    .line 66
    .line 67
    iput-wide p1, v0, Lg60/y;->d:J

    .line 68
    .line 69
    iput v7, v0, Lg60/y;->g:I

    .line 70
    .line 71
    invoke-static {v4, v5, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    if-ne p3, v1, :cond_4

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_4
    :goto_1
    invoke-static {p1, p2, v4, v5}, Lmy0/c;->j(JJ)J

    .line 79
    .line 80
    .line 81
    move-result-wide v4

    .line 82
    sget-object p3, Lmy0/e;->i:Lmy0/e;

    .line 83
    .line 84
    invoke-static {v4, v5, p3}, Lmy0/c;->n(JLmy0/e;)J

    .line 85
    .line 86
    .line 87
    move-result-wide v7

    .line 88
    const-wide/16 v9, 0x0

    .line 89
    .line 90
    cmp-long p3, v7, v9

    .line 91
    .line 92
    if-lez p3, :cond_6

    .line 93
    .line 94
    iput-wide p1, v0, Lg60/y;->d:J

    .line 95
    .line 96
    iput v6, v0, Lg60/y;->g:I

    .line 97
    .line 98
    invoke-virtual {p0, v4, v5, v0}, Lg60/b0;->j(JLrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-ne p0, v1, :cond_5

    .line 103
    .line 104
    :goto_2
    return-object v1

    .line 105
    :cond_5
    return-object v3

    .line 106
    :cond_6
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    move-object v4, p1

    .line 111
    check-cast v4, Lg60/q;

    .line 112
    .line 113
    const/4 v8, 0x0

    .line 114
    const/16 v9, 0xd

    .line 115
    .line 116
    const/4 v5, 0x0

    .line 117
    const/4 v6, 0x0

    .line 118
    const/4 v7, 0x0

    .line 119
    invoke-static/range {v4 .. v9}, Lg60/q;->a(Lg60/q;Lg60/p;Lg60/k;ZZI)Lg60/q;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 124
    .line 125
    .line 126
    return-object v3
.end method

.method public final k(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lg60/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lg60/z;

    .line 7
    .line 8
    iget v1, v0, Lg60/z;->f:I

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
    iput v1, v0, Lg60/z;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg60/z;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lg60/z;-><init>(Lg60/b0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lg60/z;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg60/z;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lg60/z;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lg60/b0;->k:Lkf0/k;

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    if-ne p1, v1, :cond_3

    .line 63
    .line 64
    return-object v1

    .line 65
    :cond_3
    :goto_1
    check-cast p1, Lss0/b;

    .line 66
    .line 67
    sget-object v0, Lss0/e;->r1:Lss0/e;

    .line 68
    .line 69
    invoke-static {p1, v0}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    move-object v4, v0

    .line 78
    check-cast v4, Lg60/q;

    .line 79
    .line 80
    new-instance v5, Lg60/o;

    .line 81
    .line 82
    iget-object v0, p0, Lg60/b0;->m:Lij0/a;

    .line 83
    .line 84
    invoke-static {p1, v0}, Lkp/g8;->b(Ler0/g;Lij0/a;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-static {p1, v0}, Lkp/g8;->a(Ler0/g;Lij0/a;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    sget-object v2, Ler0/g;->f:Ler0/g;

    .line 93
    .line 94
    if-ne p1, v2, :cond_4

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_4
    const/4 v3, 0x0

    .line 98
    :goto_2
    invoke-direct {v5, v1, v0, v3}, Lg60/o;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 99
    .line 100
    .line 101
    const/4 v8, 0x0

    .line 102
    const/16 v9, 0xe

    .line 103
    .line 104
    const/4 v6, 0x0

    .line 105
    const/4 v7, 0x0

    .line 106
    invoke-static/range {v4 .. v9}, Lg60/q;->a(Lg60/q;Lg60/p;Lg60/k;ZZI)Lg60/q;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 111
    .line 112
    .line 113
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0
.end method

.method public final l(J)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lg60/q;

    .line 7
    .line 8
    new-instance v3, Lg60/k;

    .line 9
    .line 10
    const/4 v0, 0x6

    .line 11
    iget-object v2, p0, Lg60/b0;->m:Lij0/a;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-static {p1, p2, v2, v4, v0}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sget-wide v5, Lg60/b0;->u:J

    .line 19
    .line 20
    invoke-static {p1, p2, v5, v6}, Lmy0/c;->c(JJ)I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-gtz p1, :cond_0

    .line 25
    .line 26
    const/4 v4, 0x1

    .line 27
    :cond_0
    invoke-direct {v3, v0, v4}, Lg60/k;-><init>(Ljava/lang/String;Z)V

    .line 28
    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    const/16 v6, 0xd

    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    invoke-static/range {v1 .. v6}, Lg60/q;->a(Lg60/q;Lg60/p;Lg60/k;ZZI)Lg60/q;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 40
    .line 41
    .line 42
    return-void
.end method
