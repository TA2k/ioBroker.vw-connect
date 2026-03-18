.class public abstract Lp1/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/q2;


# instance fields
.field public A:J

.field public final B:Lo1/i0;

.field public final C:Ll2/b1;

.field public final D:Ll2/b1;

.field public final E:Ll2/j1;

.field public final F:Ll2/j1;

.field public final G:Ll2/j1;

.field public final H:Ll2/j1;

.field public a:Z

.field public b:Lp1/o;

.field public final c:Ll2/j1;

.field public final d:Lh8/o;

.field public e:I

.field public f:I

.field public g:J

.field public h:J

.field public i:F

.field public j:F

.field public final k:Lg1/f0;

.field public final l:Z

.field public m:I

.field public n:Lo1/k0;

.field public o:Z

.field public final p:Ll2/j1;

.field public q:Lt4/c;

.field public final r:Li1/l;

.field public final s:Ll2/g1;

.field public final t:Ll2/g1;

.field public final u:Ll2/h0;

.field public final v:Lo1/l0;

.field public final w:Lg1/r;

.field public final x:Lo1/d;

.field public final y:Ll2/j1;

.field public final z:Lm1/r;


# direct methods
.method public constructor <init>(IF)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    float-to-double v0, p2

    .line 5
    const-wide/high16 v2, -0x4020000000000000L    # -0.5

    .line 6
    .line 7
    cmpg-double v2, v2, v0

    .line 8
    .line 9
    if-gtz v2, :cond_0

    .line 10
    .line 11
    const-wide/high16 v2, 0x3fe0000000000000L    # 0.5

    .line 12
    .line 13
    cmpg-double v0, v0, v2

    .line 14
    .line 15
    if-gtz v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v1, "currentPageOffsetFraction "

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, " is not within the range -0.5 to 0.5"

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    :goto_0
    new-instance v0, Ld3/b;

    .line 41
    .line 42
    const-wide/16 v1, 0x0

    .line 43
    .line 44
    invoke-direct {v0, v1, v2}, Ld3/b;-><init>(J)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    iput-object v0, p0, Lp1/v;->c:Ll2/j1;

    .line 52
    .line 53
    new-instance v0, Lh8/o;

    .line 54
    .line 55
    invoke-direct {v0, p1, p2, p0}, Lh8/o;-><init>(IFLp1/v;)V

    .line 56
    .line 57
    .line 58
    iput-object v0, p0, Lp1/v;->d:Lh8/o;

    .line 59
    .line 60
    iput p1, p0, Lp1/v;->e:I

    .line 61
    .line 62
    const-wide v0, 0x7fffffffffffffffL

    .line 63
    .line 64
    .line 65
    .line 66
    .line 67
    iput-wide v0, p0, Lp1/v;->g:J

    .line 68
    .line 69
    new-instance p2, Lp1/r;

    .line 70
    .line 71
    const/4 v0, 0x0

    .line 72
    invoke-direct {p2, p0, v0}, Lp1/r;-><init>(Lp1/v;I)V

    .line 73
    .line 74
    .line 75
    new-instance v0, Lg1/f0;

    .line 76
    .line 77
    invoke-direct {v0, p2}, Lg1/f0;-><init>(Lay0/k;)V

    .line 78
    .line 79
    .line 80
    iput-object v0, p0, Lp1/v;->k:Lg1/f0;

    .line 81
    .line 82
    const/4 p2, 0x1

    .line 83
    iput-boolean p2, p0, Lp1/v;->l:Z

    .line 84
    .line 85
    const/4 p2, -0x1

    .line 86
    iput p2, p0, Lp1/v;->m:I

    .line 87
    .line 88
    sget-object v0, Lp1/y;->b:Lp1/o;

    .line 89
    .line 90
    sget-object v1, Ll2/x0;->f:Ll2/x0;

    .line 91
    .line 92
    new-instance v2, Ll2/j1;

    .line 93
    .line 94
    invoke-direct {v2, v0, v1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 95
    .line 96
    .line 97
    iput-object v2, p0, Lp1/v;->p:Ll2/j1;

    .line 98
    .line 99
    sget-object v0, Lp1/y;->c:Lp1/x;

    .line 100
    .line 101
    iput-object v0, p0, Lp1/v;->q:Lt4/c;

    .line 102
    .line 103
    new-instance v0, Li1/l;

    .line 104
    .line 105
    invoke-direct {v0}, Li1/l;-><init>()V

    .line 106
    .line 107
    .line 108
    iput-object v0, p0, Lp1/v;->r:Li1/l;

    .line 109
    .line 110
    new-instance v0, Ll2/g1;

    .line 111
    .line 112
    invoke-direct {v0, p2}, Ll2/g1;-><init>(I)V

    .line 113
    .line 114
    .line 115
    iput-object v0, p0, Lp1/v;->s:Ll2/g1;

    .line 116
    .line 117
    new-instance p2, Ll2/g1;

    .line 118
    .line 119
    invoke-direct {p2, p1}, Ll2/g1;-><init>(I)V

    .line 120
    .line 121
    .line 122
    iput-object p2, p0, Lp1/v;->t:Ll2/g1;

    .line 123
    .line 124
    sget-object p1, Ll2/x0;->i:Ll2/x0;

    .line 125
    .line 126
    new-instance p2, Li40/a0;

    .line 127
    .line 128
    const/4 v0, 0x5

    .line 129
    invoke-direct {p2, p0, v0}, Li40/a0;-><init>(Lp1/v;I)V

    .line 130
    .line 131
    .line 132
    invoke-static {p2, p1}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    iput-object p2, p0, Lp1/v;->u:Ll2/h0;

    .line 137
    .line 138
    new-instance p2, Li40/a0;

    .line 139
    .line 140
    const/4 v0, 0x6

    .line 141
    invoke-direct {p2, p0, v0}, Li40/a0;-><init>(Lp1/v;I)V

    .line 142
    .line 143
    .line 144
    invoke-static {p2, p1}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 145
    .line 146
    .line 147
    new-instance p1, Lo1/l0;

    .line 148
    .line 149
    new-instance p2, Lp1/r;

    .line 150
    .line 151
    const/4 v0, 0x1

    .line 152
    invoke-direct {p2, p0, v0}, Lp1/r;-><init>(Lp1/v;I)V

    .line 153
    .line 154
    .line 155
    invoke-direct {p1, p2}, Lo1/l0;-><init>(Lay0/k;)V

    .line 156
    .line 157
    .line 158
    iput-object p1, p0, Lp1/v;->v:Lo1/l0;

    .line 159
    .line 160
    new-instance p1, Lg1/r;

    .line 161
    .line 162
    const/4 p2, 0x1

    .line 163
    invoke-direct {p1, p2}, Lg1/r;-><init>(I)V

    .line 164
    .line 165
    .line 166
    iput-object p1, p0, Lp1/v;->w:Lg1/r;

    .line 167
    .line 168
    new-instance p1, Lo1/d;

    .line 169
    .line 170
    invoke-direct {p1}, Lo1/d;-><init>()V

    .line 171
    .line 172
    .line 173
    iput-object p1, p0, Lp1/v;->x:Lo1/d;

    .line 174
    .line 175
    const/4 p1, 0x0

    .line 176
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    iput-object p1, p0, Lp1/v;->y:Ll2/j1;

    .line 181
    .line 182
    new-instance p1, Lm1/r;

    .line 183
    .line 184
    const/4 p2, 0x2

    .line 185
    invoke-direct {p1, p0, p2}, Lm1/r;-><init>(Lg1/q2;I)V

    .line 186
    .line 187
    .line 188
    iput-object p1, p0, Lp1/v;->z:Lm1/r;

    .line 189
    .line 190
    const/16 p1, 0xf

    .line 191
    .line 192
    const/4 p2, 0x0

    .line 193
    invoke-static {p2, p2, p1}, Lt4/b;->b(III)J

    .line 194
    .line 195
    .line 196
    move-result-wide p1

    .line 197
    iput-wide p1, p0, Lp1/v;->A:J

    .line 198
    .line 199
    new-instance p1, Lo1/i0;

    .line 200
    .line 201
    invoke-direct {p1}, Lo1/i0;-><init>()V

    .line 202
    .line 203
    .line 204
    iput-object p1, p0, Lp1/v;->B:Lo1/i0;

    .line 205
    .line 206
    invoke-static {}, Lo1/y;->h()Ll2/b1;

    .line 207
    .line 208
    .line 209
    move-result-object p1

    .line 210
    iput-object p1, p0, Lp1/v;->C:Ll2/b1;

    .line 211
    .line 212
    invoke-static {}, Lo1/y;->h()Ll2/b1;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    iput-object p1, p0, Lp1/v;->D:Ll2/b1;

    .line 217
    .line 218
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 219
    .line 220
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 221
    .line 222
    .line 223
    move-result-object p2

    .line 224
    iput-object p2, p0, Lp1/v;->E:Ll2/j1;

    .line 225
    .line 226
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 227
    .line 228
    .line 229
    move-result-object p2

    .line 230
    iput-object p2, p0, Lp1/v;->F:Ll2/j1;

    .line 231
    .line 232
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 233
    .line 234
    .line 235
    move-result-object p2

    .line 236
    iput-object p2, p0, Lp1/v;->G:Ll2/j1;

    .line 237
    .line 238
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    iput-object p1, p0, Lp1/v;->H:Ll2/j1;

    .line 243
    .line 244
    return-void
.end method

.method public static synthetic g(Lp1/v;ILrx0/i;)Ljava/lang/Object;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x7

    .line 3
    const/4 v2, 0x0

    .line 4
    invoke-static {v0, v0, v2, v1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {p0, p1, v0, p2}, Lp1/v;->f(ILc1/f1;Lrx0/c;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public static i(ZLp1/o;)I
    .locals 1

    .line 1
    iget-object v0, p1, Lp1/o;->a:Ljava/util/List;

    .line 2
    .line 3
    iget p1, p1, Lp1/o;->i:I

    .line 4
    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    add-int/lit8 p1, p1, 0x1

    .line 8
    .line 9
    if-gez p1, :cond_0

    .line 10
    .line 11
    const p0, 0x7fffffff

    .line 12
    .line 13
    .line 14
    return p0

    .line 15
    :cond_0
    invoke-static {v0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lp1/d;

    .line 20
    .line 21
    iget p0, p0, Lp1/d;->a:I

    .line 22
    .line 23
    add-int/2addr p0, p1

    .line 24
    return p0

    .line 25
    :cond_1
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lp1/d;

    .line 30
    .line 31
    iget p0, p0, Lp1/d;->a:I

    .line 32
    .line 33
    sub-int/2addr p0, p1

    .line 34
    add-int/lit8 p0, p0, -0x1

    .line 35
    .line 36
    return p0
.end method

.method public static s(Lp1/v;Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lp1/u;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lp1/u;

    .line 7
    .line 8
    iget v1, v0, Lp1/u;->i:I

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
    iput v1, v0, Lp1/u;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp1/u;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lp1/u;-><init>(Lp1/v;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lp1/u;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp1/u;->i:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Lp1/u;->d:Lp1/v;

    .line 42
    .line 43
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_4

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
    iget-object p0, v0, Lp1/u;->f:Lrx0/i;

    .line 56
    .line 57
    move-object p2, p0

    .line 58
    check-cast p2, Lay0/n;

    .line 59
    .line 60
    iget-object p1, v0, Lp1/u;->e:Le1/w0;

    .line 61
    .line 62
    iget-object p0, v0, Lp1/u;->d:Lp1/v;

    .line 63
    .line 64
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iput-object p0, v0, Lp1/u;->d:Lp1/v;

    .line 72
    .line 73
    iput-object p1, v0, Lp1/u;->e:Le1/w0;

    .line 74
    .line 75
    move-object p3, p2

    .line 76
    check-cast p3, Lrx0/i;

    .line 77
    .line 78
    iput-object p3, v0, Lp1/u;->f:Lrx0/i;

    .line 79
    .line 80
    iput v5, v0, Lp1/u;->i:I

    .line 81
    .line 82
    iget-object p3, p0, Lp1/v;->x:Lo1/d;

    .line 83
    .line 84
    invoke-virtual {p3, v0}, Lo1/d;->h(Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p3

    .line 88
    if-ne p3, v1, :cond_4

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_4
    move-object p3, v3

    .line 92
    :goto_1
    if-ne p3, v1, :cond_5

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_5
    :goto_2
    iget-object p3, p0, Lp1/v;->k:Lg1/f0;

    .line 96
    .line 97
    invoke-virtual {p3}, Lg1/f0;->a()Z

    .line 98
    .line 99
    .line 100
    move-result p3

    .line 101
    if-nez p3, :cond_6

    .line 102
    .line 103
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 104
    .line 105
    .line 106
    move-result p3

    .line 107
    iget-object v2, p0, Lp1/v;->t:Ll2/g1;

    .line 108
    .line 109
    invoke-virtual {v2, p3}, Ll2/g1;->p(I)V

    .line 110
    .line 111
    .line 112
    :cond_6
    iget-object p3, p0, Lp1/v;->k:Lg1/f0;

    .line 113
    .line 114
    iput-object p0, v0, Lp1/u;->d:Lp1/v;

    .line 115
    .line 116
    const/4 v2, 0x0

    .line 117
    iput-object v2, v0, Lp1/u;->e:Le1/w0;

    .line 118
    .line 119
    iput-object v2, v0, Lp1/u;->f:Lrx0/i;

    .line 120
    .line 121
    iput v4, v0, Lp1/u;->i:I

    .line 122
    .line 123
    invoke-virtual {p3, p1, p2, v0}, Lg1/f0;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    if-ne p1, v1, :cond_7

    .line 128
    .line 129
    :goto_3
    return-object v1

    .line 130
    :cond_7
    :goto_4
    const/4 p1, -0x1

    .line 131
    iget-object p0, p0, Lp1/v;->s:Ll2/g1;

    .line 132
    .line 133
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 134
    .line 135
    .line 136
    return-object v3
.end method

.method public static t(Lp1/v;ILrx0/i;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    new-instance v0, Lld/c;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-direct {v0, p0, p1, v1, v2}, Lld/c;-><init>(Lp1/v;ILkotlin/coroutines/Continuation;I)V

    .line 9
    .line 10
    .line 11
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 12
    .line 13
    invoke-virtual {p0, p1, v0, p2}, Lp1/v;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    if-ne p0, p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->k:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lg1/f0;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->F:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lp1/v;->s(Lp1/v;Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->E:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->k:Lg1/f0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lg1/f0;->e(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final f(ILc1/f1;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p3, Lp1/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lp1/s;

    .line 7
    .line 8
    iget v1, v0, Lp1/s;->h:I

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
    iput v1, v0, Lp1/s;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp1/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lp1/s;-><init>(Lp1/v;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lp1/s;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lp1/s;->h:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v6, :cond_2

    .line 39
    .line 40
    if-ne v2, v5, :cond_1

    .line 41
    .line 42
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v4

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
    iget p1, v0, Lp1/s;->d:I

    .line 55
    .line 56
    iget-object p2, v0, Lp1/s;->e:Lc1/f1;

    .line 57
    .line 58
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :cond_3
    move-object v10, p2

    .line 62
    goto :goto_2

    .line 63
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 67
    .line 68
    .line 69
    move-result p3

    .line 70
    if-ne p1, p3, :cond_5

    .line 71
    .line 72
    iget-object p3, p0, Lp1/v;->d:Lh8/o;

    .line 73
    .line 74
    iget-object p3, p3, Lh8/o;->d:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p3, Ll2/f1;

    .line 77
    .line 78
    invoke-virtual {p3}, Ll2/f1;->o()F

    .line 79
    .line 80
    .line 81
    move-result p3

    .line 82
    cmpg-float p3, p3, v3

    .line 83
    .line 84
    if-nez p3, :cond_5

    .line 85
    .line 86
    goto :goto_5

    .line 87
    :cond_5
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 88
    .line 89
    .line 90
    move-result p3

    .line 91
    if-nez p3, :cond_6

    .line 92
    .line 93
    goto :goto_5

    .line 94
    :cond_6
    iput-object p2, v0, Lp1/s;->e:Lc1/f1;

    .line 95
    .line 96
    iput p1, v0, Lp1/s;->d:I

    .line 97
    .line 98
    iput v6, v0, Lp1/s;->h:I

    .line 99
    .line 100
    iget-object p3, p0, Lp1/v;->x:Lo1/d;

    .line 101
    .line 102
    invoke-virtual {p3, v0}, Lo1/d;->h(Lrx0/c;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p3

    .line 106
    if-ne p3, v1, :cond_7

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_7
    move-object p3, v4

    .line 110
    :goto_1
    if-ne p3, v1, :cond_3

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :goto_2
    float-to-double p2, v3

    .line 114
    const-wide/high16 v6, -0x4020000000000000L    # -0.5

    .line 115
    .line 116
    cmpg-double v2, v6, p2

    .line 117
    .line 118
    if-gtz v2, :cond_8

    .line 119
    .line 120
    const-wide/high16 v6, 0x3fe0000000000000L    # 0.5

    .line 121
    .line 122
    cmpg-double p2, p2, v6

    .line 123
    .line 124
    if-gtz p2, :cond_8

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_8
    new-instance p2, Ljava/lang/StringBuilder;

    .line 128
    .line 129
    const-string p3, "pageOffsetFraction "

    .line 130
    .line 131
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    const-string p3, " is not within the range -0.5 to 0.5"

    .line 138
    .line 139
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    invoke-static {p2}, Lj1/b;->a(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    :goto_3
    invoke-virtual {p0, p1}, Lp1/v;->j(I)I

    .line 150
    .line 151
    .line 152
    move-result v8

    .line 153
    invoke-virtual {p0}, Lp1/v;->o()I

    .line 154
    .line 155
    .line 156
    move-result p1

    .line 157
    int-to-float p1, p1

    .line 158
    mul-float v9, v3, p1

    .line 159
    .line 160
    new-instance v6, Lp1/t;

    .line 161
    .line 162
    const/4 v11, 0x0

    .line 163
    move-object v7, p0

    .line 164
    invoke-direct/range {v6 .. v11}, Lp1/t;-><init>(Lp1/v;IFLc1/j;Lkotlin/coroutines/Continuation;)V

    .line 165
    .line 166
    .line 167
    const/4 p0, 0x0

    .line 168
    iput-object p0, v0, Lp1/s;->e:Lc1/f1;

    .line 169
    .line 170
    iput v5, v0, Lp1/s;->h:I

    .line 171
    .line 172
    sget-object p0, Le1/w0;->d:Le1/w0;

    .line 173
    .line 174
    invoke-virtual {v7, p0, v6, v0}, Lp1/v;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    if-ne p0, v1, :cond_9

    .line 179
    .line 180
    :goto_4
    return-object v1

    .line 181
    :cond_9
    :goto_5
    return-object v4
.end method

.method public final h(Lp1/o;ZZ)V
    .locals 10

    .line 1
    iget-object v0, p1, Lp1/o;->a:Ljava/util/List;

    .line 2
    .line 3
    iget v1, p1, Lp1/o;->m:I

    .line 4
    .line 5
    iget-object v2, p1, Lp1/o;->j:Lp1/d;

    .line 6
    .line 7
    iget-object v3, p1, Lp1/o;->k:Lp1/d;

    .line 8
    .line 9
    iget v4, p1, Lp1/o;->l:F

    .line 10
    .line 11
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    iget-object v6, p0, Lp1/v;->v:Lo1/l0;

    .line 16
    .line 17
    iput v5, v6, Lo1/l0;->e:I

    .line 18
    .line 19
    if-nez p2, :cond_0

    .line 20
    .line 21
    iget-boolean v5, p0, Lp1/v;->a:Z

    .line 22
    .line 23
    if-eqz v5, :cond_0

    .line 24
    .line 25
    iput-object p1, p0, Lp1/v;->b:Lp1/o;

    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    const/4 v5, 0x1

    .line 29
    if-eqz p2, :cond_1

    .line 30
    .line 31
    iput-boolean v5, p0, Lp1/v;->a:Z

    .line 32
    .line 33
    :cond_1
    iget-object p2, p0, Lp1/v;->d:Lh8/o;

    .line 34
    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz p3, :cond_2

    .line 38
    .line 39
    iget-object p2, p2, Lh8/o;->d:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p2, Ll2/f1;

    .line 42
    .line 43
    invoke-virtual {p2, v4}, Ll2/f1;->p(F)V

    .line 44
    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    if-eqz v3, :cond_3

    .line 51
    .line 52
    iget-object p3, v3, Lp1/d;->e:Ljava/lang/Object;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_3
    move-object p3, v6

    .line 56
    :goto_0
    iput-object p3, p2, Lh8/o;->e:Ljava/lang/Object;

    .line 57
    .line 58
    iget-boolean p3, p2, Lh8/o;->a:Z

    .line 59
    .line 60
    if-nez p3, :cond_4

    .line 61
    .line 62
    move-object p3, v0

    .line 63
    check-cast p3, Ljava/util/Collection;

    .line 64
    .line 65
    invoke-interface {p3}, Ljava/util/Collection;->isEmpty()Z

    .line 66
    .line 67
    .line 68
    move-result p3

    .line 69
    if-nez p3, :cond_6

    .line 70
    .line 71
    :cond_4
    iput-boolean v5, p2, Lh8/o;->a:Z

    .line 72
    .line 73
    if-eqz v3, :cond_5

    .line 74
    .line 75
    iget p3, v3, Lp1/d;->a:I

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_5
    move p3, v7

    .line 79
    :goto_1
    iget-object v3, p2, Lh8/o;->c:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v3, Ll2/g1;

    .line 82
    .line 83
    invoke-virtual {v3, p3}, Ll2/g1;->p(I)V

    .line 84
    .line 85
    .line 86
    iget-object v3, p2, Lh8/o;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v3, Lo1/g0;

    .line 89
    .line 90
    invoke-virtual {v3, p3}, Lo1/g0;->a(I)V

    .line 91
    .line 92
    .line 93
    iget-object p2, p2, Lh8/o;->d:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p2, Ll2/f1;

    .line 96
    .line 97
    invoke-virtual {p2, v4}, Ll2/f1;->p(F)V

    .line 98
    .line 99
    .line 100
    :cond_6
    iget p2, p0, Lp1/v;->m:I

    .line 101
    .line 102
    const/4 p3, -0x1

    .line 103
    if-eq p2, p3, :cond_8

    .line 104
    .line 105
    check-cast v0, Ljava/util/Collection;

    .line 106
    .line 107
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 108
    .line 109
    .line 110
    move-result p2

    .line 111
    if-nez p2, :cond_8

    .line 112
    .line 113
    iget-boolean p2, p0, Lp1/v;->o:Z

    .line 114
    .line 115
    invoke-static {p2, p1}, Lp1/v;->i(ZLp1/o;)I

    .line 116
    .line 117
    .line 118
    move-result p2

    .line 119
    iget v0, p0, Lp1/v;->m:I

    .line 120
    .line 121
    if-eq v0, p2, :cond_8

    .line 122
    .line 123
    iput p3, p0, Lp1/v;->m:I

    .line 124
    .line 125
    iget-object p2, p0, Lp1/v;->n:Lo1/k0;

    .line 126
    .line 127
    if-eqz p2, :cond_7

    .line 128
    .line 129
    invoke-interface {p2}, Lo1/k0;->cancel()V

    .line 130
    .line 131
    .line 132
    :cond_7
    iput-object v6, p0, Lp1/v;->n:Lo1/k0;

    .line 133
    .line 134
    :cond_8
    :goto_2
    iget-object p2, p0, Lp1/v;->p:Ll2/j1;

    .line 135
    .line 136
    invoke-virtual {p2, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    iget-boolean p2, p1, Lp1/o;->n:Z

    .line 140
    .line 141
    iget-object p3, p0, Lp1/v;->E:Ll2/j1;

    .line 142
    .line 143
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 144
    .line 145
    .line 146
    move-result-object p2

    .line 147
    invoke-virtual {p3, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    if-eqz v2, :cond_9

    .line 151
    .line 152
    iget p2, v2, Lp1/d;->a:I

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_9
    move p2, v7

    .line 156
    :goto_3
    if-nez p2, :cond_b

    .line 157
    .line 158
    if-eqz v1, :cond_a

    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_a
    move p2, v7

    .line 162
    goto :goto_5

    .line 163
    :cond_b
    :goto_4
    move p2, v5

    .line 164
    :goto_5
    iget-object p3, p0, Lp1/v;->F:Ll2/j1;

    .line 165
    .line 166
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 167
    .line 168
    .line 169
    move-result-object p2

    .line 170
    invoke-virtual {p3, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    if-eqz v2, :cond_c

    .line 174
    .line 175
    iget p2, v2, Lp1/d;->a:I

    .line 176
    .line 177
    iput p2, p0, Lp1/v;->e:I

    .line 178
    .line 179
    :cond_c
    iput v1, p0, Lp1/v;->f:I

    .line 180
    .line 181
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 182
    .line 183
    .line 184
    move-result-object p2

    .line 185
    if-eqz p2, :cond_d

    .line 186
    .line 187
    invoke-virtual {p2}, Lv2/f;->e()Lay0/k;

    .line 188
    .line 189
    .line 190
    move-result-object v6

    .line 191
    :cond_d
    invoke-static {p2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 192
    .line 193
    .line 194
    move-result-object p3

    .line 195
    :try_start_0
    iget-boolean v0, p0, Lp1/v;->l:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 196
    .line 197
    const/16 v1, 0x20

    .line 198
    .line 199
    const-wide v2, 0xffffffffL

    .line 200
    .line 201
    .line 202
    .line 203
    .line 204
    if-nez v0, :cond_e

    .line 205
    .line 206
    :goto_6
    invoke-static {p2, p3, v6}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 207
    .line 208
    .line 209
    goto :goto_8

    .line 210
    :cond_e
    :try_start_1
    iget v0, p1, Lp1/o;->i:I

    .line 211
    .line 212
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    if-lt v0, v4, :cond_f

    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_f
    iget v0, p0, Lp1/v;->j:F

    .line 220
    .line 221
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 222
    .line 223
    .line 224
    move-result v0

    .line 225
    const/high16 v4, 0x3f000000    # 0.5f

    .line 226
    .line 227
    cmpg-float v0, v0, v4

    .line 228
    .line 229
    if-gtz v0, :cond_10

    .line 230
    .line 231
    goto :goto_6

    .line 232
    :cond_10
    iget v0, p0, Lp1/v;->j:F

    .line 233
    .line 234
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 235
    .line 236
    .line 237
    move-result-object v4

    .line 238
    iget-object v4, v4, Lp1/o;->e:Lg1/w1;

    .line 239
    .line 240
    sget-object v8, Lg1/w1;->d:Lg1/w1;

    .line 241
    .line 242
    if-ne v4, v8, :cond_11

    .line 243
    .line 244
    invoke-static {v0}, Ljava/lang/Math;->signum(F)F

    .line 245
    .line 246
    .line 247
    move-result v0

    .line 248
    invoke-virtual {p0}, Lp1/v;->p()J

    .line 249
    .line 250
    .line 251
    move-result-wide v8

    .line 252
    and-long/2addr v8, v2

    .line 253
    long-to-int v4, v8

    .line 254
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 255
    .line 256
    .line 257
    move-result v4

    .line 258
    neg-float v4, v4

    .line 259
    invoke-static {v4}, Ljava/lang/Math;->signum(F)F

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    cmpg-float v0, v0, v4

    .line 264
    .line 265
    if-nez v0, :cond_12

    .line 266
    .line 267
    goto :goto_7

    .line 268
    :cond_11
    invoke-static {v0}, Ljava/lang/Math;->signum(F)F

    .line 269
    .line 270
    .line 271
    move-result v0

    .line 272
    invoke-virtual {p0}, Lp1/v;->p()J

    .line 273
    .line 274
    .line 275
    move-result-wide v8

    .line 276
    shr-long/2addr v8, v1

    .line 277
    long-to-int v4, v8

    .line 278
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 279
    .line 280
    .line 281
    move-result v4

    .line 282
    neg-float v4, v4

    .line 283
    invoke-static {v4}, Ljava/lang/Math;->signum(F)F

    .line 284
    .line 285
    .line 286
    move-result v4

    .line 287
    cmpg-float v0, v0, v4

    .line 288
    .line 289
    if-nez v0, :cond_12

    .line 290
    .line 291
    goto :goto_7

    .line 292
    :cond_12
    invoke-virtual {p0}, Lp1/v;->q()Z

    .line 293
    .line 294
    .line 295
    move-result v0

    .line 296
    if-eqz v0, :cond_13

    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_13
    move v5, v7

    .line 300
    :goto_7
    if-nez v5, :cond_14

    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_14
    iget v0, p0, Lp1/v;->j:F

    .line 304
    .line 305
    invoke-virtual {p0, v0, p1}, Lp1/v;->r(FLp1/o;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 306
    .line 307
    .line 308
    goto :goto_6

    .line 309
    :goto_8
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 310
    .line 311
    .line 312
    move-result p2

    .line 313
    invoke-static {p1, p2}, Lp1/y;->a(Lp1/o;I)J

    .line 314
    .line 315
    .line 316
    move-result-wide p2

    .line 317
    iput-wide p2, p0, Lp1/v;->g:J

    .line 318
    .line 319
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 320
    .line 321
    .line 322
    iget-object p2, p1, Lp1/o;->e:Lg1/w1;

    .line 323
    .line 324
    sget-object p3, Lg1/w1;->e:Lg1/w1;

    .line 325
    .line 326
    if-ne p2, p3, :cond_15

    .line 327
    .line 328
    invoke-virtual {p1}, Lp1/o;->e()J

    .line 329
    .line 330
    .line 331
    move-result-wide p2

    .line 332
    shr-long/2addr p2, v1

    .line 333
    :goto_9
    long-to-int p2, p2

    .line 334
    goto :goto_a

    .line 335
    :cond_15
    invoke-virtual {p1}, Lp1/o;->e()J

    .line 336
    .line 337
    .line 338
    move-result-wide p2

    .line 339
    and-long/2addr p2, v2

    .line 340
    goto :goto_9

    .line 341
    :goto_a
    iget-object p3, p1, Lp1/o;->o:Lh1/n;

    .line 342
    .line 343
    iget v0, p1, Lp1/o;->b:I

    .line 344
    .line 345
    iget v1, p1, Lp1/o;->f:I

    .line 346
    .line 347
    neg-int v1, v1

    .line 348
    iget p1, p1, Lp1/o;->d:I

    .line 349
    .line 350
    invoke-interface {p3, p2, v0, v1, p1}, Lh1/n;->a(IIII)I

    .line 351
    .line 352
    .line 353
    move-result p1

    .line 354
    invoke-static {p1, v7, p2}, Lkp/r9;->e(III)I

    .line 355
    .line 356
    .line 357
    move-result p1

    .line 358
    int-to-long p1, p1

    .line 359
    iput-wide p1, p0, Lp1/v;->h:J

    .line 360
    .line 361
    return-void

    .line 362
    :catchall_0
    move-exception p0

    .line 363
    invoke-static {p2, p3, v6}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 364
    .line 365
    .line 366
    throw p0
.end method

.method public final j(I)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    add-int/lit8 p0, p0, -0x1

    .line 13
    .line 14
    invoke-static {p1, v1, p0}, Lkp/r9;->e(III)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :cond_0
    return v1
.end method

.method public final k()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->d:Lh8/o;

    .line 2
    .line 3
    iget-object p0, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ll2/g1;

    .line 6
    .line 7
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final l()Lp1/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->p:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lp1/o;

    .line 8
    .line 9
    return-object p0
.end method

.method public abstract m()I
.end method

.method public final n()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/v;->p:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lp1/o;

    .line 8
    .line 9
    iget p0, p0, Lp1/o;->b:I

    .line 10
    .line 11
    return p0
.end method

.method public final o()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lp1/v;->n()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object p0, p0, Lp1/v;->p:Ll2/j1;

    .line 6
    .line 7
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lp1/o;

    .line 12
    .line 13
    iget p0, p0, Lp1/o;->c:I

    .line 14
    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final p()J
    .locals 2

    .line 1
    iget-object p0, p0, Lp1/v;->c:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ld3/b;

    .line 8
    .line 9
    iget-wide v0, p0, Ld3/b;->a:J

    .line 10
    .line 11
    return-wide v0
.end method

.method public final q()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Lp1/v;->p()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const/16 v2, 0x20

    .line 6
    .line 7
    shr-long/2addr v0, v2

    .line 8
    long-to-int v0, v0

    .line 9
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    float-to-int v0, v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Lp1/v;->p()J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    const-wide v2, 0xffffffffL

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    and-long/2addr v0, v2

    .line 26
    long-to-int p0, v0

    .line 27
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    float-to-int p0, p0

    .line 32
    if-nez p0, :cond_0

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :cond_0
    const/4 p0, 0x0

    .line 37
    return p0
.end method

.method public final r(FLp1/o;)V
    .locals 8

    .line 1
    iget-object v0, p2, Lp1/o;->a:Ljava/util/List;

    .line 2
    .line 3
    iget-boolean v1, p0, Lp1/v;->l:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    goto/16 :goto_1

    .line 8
    .line 9
    :cond_0
    move-object v1, v0

    .line 10
    check-cast v1, Ljava/util/Collection;

    .line 11
    .line 12
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_5

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    cmpl-float v1, p1, v1

    .line 20
    .line 21
    if-lez v1, :cond_1

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const/4 v1, 0x0

    .line 26
    :goto_0
    invoke-static {v1, p2}, Lp1/v;->i(ZLp1/o;)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-ltz v3, :cond_5

    .line 31
    .line 32
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-ge v3, v2, :cond_5

    .line 37
    .line 38
    iget v2, p0, Lp1/v;->m:I

    .line 39
    .line 40
    if-eq v3, v2, :cond_3

    .line 41
    .line 42
    iget-boolean v2, p0, Lp1/v;->o:Z

    .line 43
    .line 44
    if-eq v2, v1, :cond_2

    .line 45
    .line 46
    iget-object v2, p0, Lp1/v;->n:Lo1/k0;

    .line 47
    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    invoke-interface {v2}, Lo1/k0;->cancel()V

    .line 51
    .line 52
    .line 53
    :cond_2
    iput-boolean v1, p0, Lp1/v;->o:Z

    .line 54
    .line 55
    iput v3, p0, Lp1/v;->m:I

    .line 56
    .line 57
    iget-wide v4, p0, Lp1/v;->A:J

    .line 58
    .line 59
    const/4 v6, 0x1

    .line 60
    iget-object v2, p0, Lp1/v;->v:Lo1/l0;

    .line 61
    .line 62
    const/4 v7, 0x0

    .line 63
    invoke-virtual/range {v2 .. v7}, Lo1/l0;->a(IJZLay0/k;)Lo1/k0;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    iput-object v2, p0, Lp1/v;->n:Lo1/k0;

    .line 68
    .line 69
    :cond_3
    if-eqz v1, :cond_4

    .line 70
    .line 71
    invoke-static {v0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    check-cast v0, Lp1/d;

    .line 76
    .line 77
    iget v1, p2, Lp1/o;->b:I

    .line 78
    .line 79
    iget v2, p2, Lp1/o;->c:I

    .line 80
    .line 81
    add-int/2addr v1, v2

    .line 82
    iget v0, v0, Lp1/d;->l:I

    .line 83
    .line 84
    add-int/2addr v0, v1

    .line 85
    iget p2, p2, Lp1/o;->g:I

    .line 86
    .line 87
    sub-int/2addr v0, p2

    .line 88
    int-to-float p2, v0

    .line 89
    cmpg-float p1, p2, p1

    .line 90
    .line 91
    if-gez p1, :cond_5

    .line 92
    .line 93
    iget-object p0, p0, Lp1/v;->n:Lo1/k0;

    .line 94
    .line 95
    if-eqz p0, :cond_5

    .line 96
    .line 97
    invoke-interface {p0}, Lo1/k0;->a()V

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :cond_4
    invoke-static {v0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    check-cast v0, Lp1/d;

    .line 106
    .line 107
    iget p2, p2, Lp1/o;->f:I

    .line 108
    .line 109
    iget v0, v0, Lp1/d;->l:I

    .line 110
    .line 111
    sub-int/2addr p2, v0

    .line 112
    int-to-float p2, p2

    .line 113
    neg-float p1, p1

    .line 114
    cmpg-float p1, p2, p1

    .line 115
    .line 116
    if-gez p1, :cond_5

    .line 117
    .line 118
    iget-object p0, p0, Lp1/v;->n:Lo1/k0;

    .line 119
    .line 120
    if-eqz p0, :cond_5

    .line 121
    .line 122
    invoke-interface {p0}, Lo1/k0;->a()V

    .line 123
    .line 124
    .line 125
    :cond_5
    :goto_1
    return-void
.end method

.method public final u(IFZ)V
    .locals 2

    .line 1
    iget-object v0, p0, Lp1/v;->d:Lh8/o;

    .line 2
    .line 3
    iget-object v1, v0, Lh8/o;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ll2/g1;

    .line 6
    .line 7
    invoke-virtual {v1, p1}, Ll2/g1;->p(I)V

    .line 8
    .line 9
    .line 10
    iget-object v1, v0, Lh8/o;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lo1/g0;

    .line 13
    .line 14
    invoke-virtual {v1, p1}, Lo1/g0;->a(I)V

    .line 15
    .line 16
    .line 17
    iget-object p1, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Ll2/f1;

    .line 20
    .line 21
    invoke-virtual {p1, p2}, Ll2/f1;->p(F)V

    .line 22
    .line 23
    .line 24
    const/4 p1, 0x0

    .line 25
    iput-object p1, v0, Lh8/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    if-eqz p3, :cond_1

    .line 28
    .line 29
    iget-object p0, p0, Lp1/v;->y:Ll2/j1;

    .line 30
    .line 31
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    check-cast p0, Lv3/h0;

    .line 36
    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    invoke-virtual {p0}, Lv3/h0;->l()V

    .line 40
    .line 41
    .line 42
    :cond_0
    return-void

    .line 43
    :cond_1
    iget-object p0, p0, Lp1/v;->D:Ll2/b1;

    .line 44
    .line 45
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method
