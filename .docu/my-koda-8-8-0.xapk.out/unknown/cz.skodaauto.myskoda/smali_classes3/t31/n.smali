.class public final Lt31/n;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lz9/y;

.field public final g:Lz70/d;

.field public final h:Lk31/n;

.field public final i:Lk31/d;

.field public final j:Lk31/f0;

.field public final k:Lk31/l0;

.field public final l:Lk31/e0;

.field public final m:Lk31/d0;

.field public final n:Lk31/x;

.field public final o:Lk31/r;

.field public final p:Landroidx/lifecycle/s0;

.field public q:Lvy0/x1;

.field public r:Z


# direct methods
.method public constructor <init>(Lz9/y;Lz70/d;Lk31/n;Lk31/d;Lk31/f0;Lk31/l0;Lk31/e0;Lk31/d0;Lk31/x;Lk31/r;Landroidx/lifecycle/s0;)V
    .locals 10

    .line 1
    new-instance v0, Lt31/o;

    .line 2
    .line 3
    new-instance v3, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    new-instance v4, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    new-instance v5, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    new-instance v6, Ll4/v;

    .line 19
    .line 20
    const-wide/16 v1, 0x0

    .line 21
    .line 22
    const/4 v7, 0x6

    .line 23
    const-string v8, ""

    .line 24
    .line 25
    invoke-direct {v6, v1, v2, v8, v7}, Ll4/v;-><init>(JLjava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    const v7, 0x7fffffff

    .line 29
    .line 30
    .line 31
    const/4 v9, 0x0

    .line 32
    const/4 v1, 0x0

    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v8, 0x0

    .line 35
    invoke-direct/range {v0 .. v9}, Lt31/o;-><init>(ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;ILjava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    invoke-direct {p0, v0}, Lq41/b;-><init>(Lq41/a;)V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lt31/n;->f:Lz9/y;

    .line 42
    .line 43
    iput-object p2, p0, Lt31/n;->g:Lz70/d;

    .line 44
    .line 45
    iput-object p3, p0, Lt31/n;->h:Lk31/n;

    .line 46
    .line 47
    iput-object p4, p0, Lt31/n;->i:Lk31/d;

    .line 48
    .line 49
    iput-object p5, p0, Lt31/n;->j:Lk31/f0;

    .line 50
    .line 51
    move-object/from16 p1, p6

    .line 52
    .line 53
    iput-object p1, p0, Lt31/n;->k:Lk31/l0;

    .line 54
    .line 55
    move-object/from16 p1, p7

    .line 56
    .line 57
    iput-object p1, p0, Lt31/n;->l:Lk31/e0;

    .line 58
    .line 59
    move-object/from16 p1, p8

    .line 60
    .line 61
    iput-object p1, p0, Lt31/n;->m:Lk31/d0;

    .line 62
    .line 63
    move-object/from16 p1, p9

    .line 64
    .line 65
    iput-object p1, p0, Lt31/n;->n:Lk31/x;

    .line 66
    .line 67
    move-object/from16 p1, p10

    .line 68
    .line 69
    iput-object p1, p0, Lt31/n;->o:Lk31/r;

    .line 70
    .line 71
    move-object/from16 p1, p11

    .line 72
    .line 73
    iput-object p1, p0, Lt31/n;->p:Landroidx/lifecycle/s0;

    .line 74
    .line 75
    invoke-virtual {p0}, Lt31/n;->b()Z

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    iput-boolean p1, p0, Lt31/n;->r:Z

    .line 80
    .line 81
    invoke-virtual {p3}, Lk31/n;->invoke()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    check-cast p1, Li31/j;

    .line 86
    .line 87
    if-eqz p1, :cond_0

    .line 88
    .line 89
    iget-boolean p1, p1, Li31/j;->c:Z

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_0
    const/4 p1, 0x0

    .line 93
    :goto_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    new-instance p3, Lt31/l;

    .line 98
    .line 99
    const/4 p4, 0x0

    .line 100
    invoke-direct {p3, p0, p1, p4}, Lt31/l;-><init>(Lt31/n;ZLkotlin/coroutines/Continuation;)V

    .line 101
    .line 102
    .line 103
    const/4 p0, 0x3

    .line 104
    invoke-static {p2, p4, p4, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 105
    .line 106
    .line 107
    return-void
.end method


# virtual methods
.method public final b()Z
    .locals 2

    .line 1
    const-class v0, Ll31/m;

    .line 2
    .line 3
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object p0, p0, Lt31/n;->p:Landroidx/lifecycle/s0;

    .line 10
    .line 11
    invoke-static {p0, v0}, Ljp/t0;->c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ll31/m;

    .line 16
    .line 17
    iget-boolean p0, p0, Ll31/m;->a:Z

    .line 18
    .line 19
    return p0
.end method

.method public final d()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lt31/o;

    .line 6
    .line 7
    iget-boolean v0, v0, Lt31/o;->a:Z

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lt31/o;

    .line 17
    .line 18
    iget-boolean v0, v0, Lt31/o;->b:Z

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    move v0, v1

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v0, 0x0

    .line 25
    :goto_0
    iget-object v2, p0, Lt31/n;->q:Lvy0/x1;

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    invoke-virtual {v2}, Lvy0/p1;->a()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-ne v2, v1, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    iget-boolean v1, p0, Lt31/n;->r:Z

    .line 37
    .line 38
    if-eqz v1, :cond_3

    .line 39
    .line 40
    if-nez v0, :cond_2

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    iget-object v0, p0, Lt31/n;->j:Lk31/f0;

    .line 44
    .line 45
    invoke-virtual {v0}, Lk31/f0;->a()Lyy0/i;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    new-instance v1, Lrz/k;

    .line 50
    .line 51
    const/4 v2, 0x3

    .line 52
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 53
    .line 54
    .line 55
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    new-instance v1, Ls10/a0;

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    const/4 v3, 0x2

    .line 63
    invoke-direct {v1, p0, v2, v3}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 64
    .line 65
    .line 66
    new-instance v2, Lne0/n;

    .line 67
    .line 68
    const/4 v3, 0x5

    .line 69
    invoke-direct {v2, v0, v1, v3}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 70
    .line 71
    .line 72
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-static {v2, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    iput-object v0, p0, Lt31/n;->q:Lvy0/x1;

    .line 81
    .line 82
    :cond_3
    :goto_1
    return-void
.end method

.method public final f(Lt31/i;)V
    .locals 13

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lt31/b;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    sget-object v0, Lt31/p;->f:Lt31/p;

    .line 11
    .line 12
    check-cast p1, Lt31/b;

    .line 13
    .line 14
    iget v1, p1, Lt31/b;->b:I

    .line 15
    .line 16
    iget-boolean p1, p1, Lt31/b;->c:Z

    .line 17
    .line 18
    invoke-virtual {p0, v0, v1, p1}, Lt31/n;->g(Lt31/p;IZ)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    instance-of v0, p1, Lt31/e;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    sget-object v0, Lt31/p;->e:Lt31/p;

    .line 27
    .line 28
    check-cast p1, Lt31/e;

    .line 29
    .line 30
    iget v1, p1, Lt31/e;->b:I

    .line 31
    .line 32
    iget-boolean p1, p1, Lt31/e;->c:Z

    .line 33
    .line 34
    invoke-virtual {p0, v0, v1, p1}, Lt31/n;->g(Lt31/p;IZ)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_1
    instance-of v0, p1, Lt31/f;

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    sget-object v0, Lt31/p;->d:Lt31/p;

    .line 43
    .line 44
    check-cast p1, Lt31/f;

    .line 45
    .line 46
    iget v1, p1, Lt31/f;->b:I

    .line 47
    .line 48
    iget-boolean p1, p1, Lt31/f;->c:Z

    .line 49
    .line 50
    invoke-virtual {p0, v0, v1, p1}, Lt31/n;->g(Lt31/p;IZ)V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_2
    instance-of v0, p1, Lt31/c;

    .line 55
    .line 56
    iget-object v1, p0, Lq41/b;->d:Lyy0/c2;

    .line 57
    .line 58
    if-eqz v0, :cond_4

    .line 59
    .line 60
    check-cast p1, Lt31/c;

    .line 61
    .line 62
    iget-object v0, p1, Lt31/c;->a:Ll4/v;

    .line 63
    .line 64
    iget-object p1, v0, Ll4/v;->a:Lg4/g;

    .line 65
    .line 66
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 67
    .line 68
    iget-object p0, p0, Lt31/n;->l:Lk31/e0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lk31/e0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    rsub-int p0, p0, 0x5dc

    .line 79
    .line 80
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v10

    .line 84
    :cond_3
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    move-object v3, p0

    .line 89
    check-cast v3, Lt31/o;

    .line 90
    .line 91
    new-instance v9, Ll4/v;

    .line 92
    .line 93
    iget-wide v4, v0, Ll4/v;->b:J

    .line 94
    .line 95
    const/4 p1, 0x4

    .line 96
    invoke-direct {v9, v4, v5, v2, p1}, Ll4/v;-><init>(JLjava/lang/String;I)V

    .line 97
    .line 98
    .line 99
    const/4 v11, 0x0

    .line 100
    const/16 v12, 0x15f

    .line 101
    .line 102
    const/4 v4, 0x0

    .line 103
    const/4 v5, 0x0

    .line 104
    const/4 v6, 0x0

    .line 105
    const/4 v7, 0x0

    .line 106
    const/4 v8, 0x0

    .line 107
    invoke-static/range {v3 .. v12}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-virtual {v1, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-eqz p0, :cond_3

    .line 116
    .line 117
    goto/16 :goto_4

    .line 118
    .line 119
    :cond_4
    instance-of v0, p1, Lt31/a;

    .line 120
    .line 121
    const/4 v2, 0x0

    .line 122
    if-eqz v0, :cond_b

    .line 123
    .line 124
    invoke-virtual {p0}, Lt31/n;->b()Z

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    iget-object v0, p0, Lt31/n;->f:Lz9/y;

    .line 129
    .line 130
    if-eqz p1, :cond_5

    .line 131
    .line 132
    new-instance p1, Lt31/j;

    .line 133
    .line 134
    const/4 v1, 0x0

    .line 135
    invoke-direct {p1, p0, v1}, Lt31/j;-><init>(Lt31/n;I)V

    .line 136
    .line 137
    .line 138
    iget-object p0, p0, Lt31/n;->k:Lk31/l0;

    .line 139
    .line 140
    invoke-virtual {p0, p1}, Lk31/l0;->a(Lay0/k;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0}, Lz9/y;->h()Z

    .line 144
    .line 145
    .line 146
    return-void

    .line 147
    :cond_5
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    check-cast p1, Lt31/o;

    .line 152
    .line 153
    iget-object p1, p1, Lt31/o;->e:Ljava/util/List;

    .line 154
    .line 155
    check-cast p1, Ljava/lang/Iterable;

    .line 156
    .line 157
    new-instance v4, Ljava/util/ArrayList;

    .line 158
    .line 159
    const/16 v1, 0xa

    .line 160
    .line 161
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 166
    .line 167
    .line 168
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    if-eqz v3, :cond_6

    .line 177
    .line 178
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    check-cast v3, Lp31/d;

    .line 183
    .line 184
    iget-object v5, v3, Lp31/d;->a:Li31/u;

    .line 185
    .line 186
    iget-boolean v3, v3, Lp31/d;->b:Z

    .line 187
    .line 188
    new-instance v6, Li31/a0;

    .line 189
    .line 190
    invoke-direct {v6, v5, v3}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    goto :goto_0

    .line 197
    :cond_6
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    check-cast p1, Lt31/o;

    .line 202
    .line 203
    iget-object p1, p1, Lt31/o;->c:Ljava/util/List;

    .line 204
    .line 205
    check-cast p1, Ljava/lang/Iterable;

    .line 206
    .line 207
    new-instance v6, Ljava/util/ArrayList;

    .line 208
    .line 209
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 210
    .line 211
    .line 212
    move-result v3

    .line 213
    invoke-direct {v6, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 214
    .line 215
    .line 216
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 217
    .line 218
    .line 219
    move-result-object p1

    .line 220
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 221
    .line 222
    .line 223
    move-result v3

    .line 224
    if-eqz v3, :cond_7

    .line 225
    .line 226
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    check-cast v3, Lp31/h;

    .line 231
    .line 232
    iget-object v5, v3, Lp31/h;->a:Li31/h0;

    .line 233
    .line 234
    iget-boolean v3, v3, Lp31/h;->c:Z

    .line 235
    .line 236
    new-instance v7, Li31/a0;

    .line 237
    .line 238
    invoke-direct {v7, v5, v3}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    goto :goto_1

    .line 245
    :cond_7
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 246
    .line 247
    .line 248
    move-result-object p1

    .line 249
    check-cast p1, Lt31/o;

    .line 250
    .line 251
    iget-object p1, p1, Lt31/o;->d:Ljava/util/List;

    .line 252
    .line 253
    check-cast p1, Ljava/lang/Iterable;

    .line 254
    .line 255
    new-instance v7, Ljava/util/ArrayList;

    .line 256
    .line 257
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 258
    .line 259
    .line 260
    move-result v1

    .line 261
    invoke-direct {v7, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 262
    .line 263
    .line 264
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 265
    .line 266
    .line 267
    move-result-object p1

    .line 268
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 269
    .line 270
    .line 271
    move-result v1

    .line 272
    if-eqz v1, :cond_8

    .line 273
    .line 274
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    check-cast v1, Lp31/e;

    .line 279
    .line 280
    iget-object v3, v1, Lp31/e;->a:Li31/y;

    .line 281
    .line 282
    iget-boolean v1, v1, Lp31/e;->b:Z

    .line 283
    .line 284
    new-instance v5, Li31/a0;

    .line 285
    .line 286
    invoke-direct {v5, v3, v1}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    goto :goto_2

    .line 293
    :cond_8
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 294
    .line 295
    .line 296
    move-result-object p1

    .line 297
    check-cast p1, Lt31/o;

    .line 298
    .line 299
    iget-object p1, p1, Lt31/o;->f:Ll4/v;

    .line 300
    .line 301
    iget-object p1, p1, Ll4/v;->a:Lg4/g;

    .line 302
    .line 303
    iget-object v8, p1, Lg4/g;->e:Ljava/lang/String;

    .line 304
    .line 305
    new-instance v3, Lk31/c;

    .line 306
    .line 307
    const/4 v5, 0x0

    .line 308
    const/4 v9, 0x2

    .line 309
    invoke-direct/range {v3 .. v9}, Lk31/c;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/String;I)V

    .line 310
    .line 311
    .line 312
    iget-object p1, p0, Lt31/n;->i:Lk31/d;

    .line 313
    .line 314
    invoke-virtual {p1, v3}, Lk31/d;->a(Lk31/c;)V

    .line 315
    .line 316
    .line 317
    sget-object p1, Lz21/c;->f:Lz21/c;

    .line 318
    .line 319
    sget-object v1, Lz21/c;->g:Lz21/c;

    .line 320
    .line 321
    filled-new-array {p1, v1}, [Lz21/c;

    .line 322
    .line 323
    .line 324
    move-result-object p1

    .line 325
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 326
    .line 327
    .line 328
    move-result-object p1

    .line 329
    check-cast p1, Ljava/lang/Iterable;

    .line 330
    .line 331
    iget-object v1, p0, Lt31/n;->h:Lk31/n;

    .line 332
    .line 333
    invoke-static {v1}, Lkp/j;->b(Lr41/a;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    check-cast v1, Li31/j;

    .line 338
    .line 339
    if-eqz v1, :cond_9

    .line 340
    .line 341
    iget-object v2, v1, Li31/j;->a:Lz21/c;

    .line 342
    .line 343
    :cond_9
    invoke-static {p1, v2}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    move-result p1

    .line 347
    if-eqz p1, :cond_a

    .line 348
    .line 349
    new-instance p1, Ll31/j;

    .line 350
    .line 351
    const/4 v1, 0x0

    .line 352
    invoke-direct {p1, v1}, Ll31/j;-><init>(Z)V

    .line 353
    .line 354
    .line 355
    invoke-static {v0, p1}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    goto :goto_3

    .line 359
    :cond_a
    sget-object p1, Ll31/n;->INSTANCE:Ll31/n;

    .line 360
    .line 361
    invoke-static {v0, p1}, Lz9/y;->e(Lz9/y;Ljava/lang/Object;)V

    .line 362
    .line 363
    .line 364
    :goto_3
    const/4 p1, 0x1

    .line 365
    iput-boolean p1, p0, Lt31/n;->r:Z

    .line 366
    .line 367
    return-void

    .line 368
    :cond_b
    instance-of v0, p1, Lt31/d;

    .line 369
    .line 370
    if-eqz v0, :cond_d

    .line 371
    .line 372
    :cond_c
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    move-object v2, p0

    .line 377
    check-cast v2, Lt31/o;

    .line 378
    .line 379
    const/4 v10, 0x0

    .line 380
    const/16 v11, 0xff

    .line 381
    .line 382
    const/4 v3, 0x0

    .line 383
    const/4 v4, 0x0

    .line 384
    const/4 v5, 0x0

    .line 385
    const/4 v6, 0x0

    .line 386
    const/4 v7, 0x0

    .line 387
    const/4 v8, 0x0

    .line 388
    const/4 v9, 0x0

    .line 389
    invoke-static/range {v2 .. v11}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 390
    .line 391
    .line 392
    move-result-object p1

    .line 393
    invoke-virtual {v1, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 394
    .line 395
    .line 396
    move-result p0

    .line 397
    if-eqz p0, :cond_c

    .line 398
    .line 399
    :goto_4
    return-void

    .line 400
    :cond_d
    instance-of v0, p1, Lt31/g;

    .line 401
    .line 402
    if-eqz v0, :cond_e

    .line 403
    .line 404
    invoke-virtual {p0}, Lt31/n;->d()V

    .line 405
    .line 406
    .line 407
    return-void

    .line 408
    :cond_e
    instance-of p1, p1, Lt31/h;

    .line 409
    .line 410
    if-eqz p1, :cond_10

    .line 411
    .line 412
    iget-object p1, p0, Lt31/n;->q:Lvy0/x1;

    .line 413
    .line 414
    if-eqz p1, :cond_f

    .line 415
    .line 416
    invoke-virtual {p1, v2}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 417
    .line 418
    .line 419
    :cond_f
    iput-object v2, p0, Lt31/n;->q:Lvy0/x1;

    .line 420
    .line 421
    return-void

    .line 422
    :cond_10
    new-instance p0, La8/r0;

    .line 423
    .line 424
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 425
    .line 426
    .line 427
    throw p0
.end method

.method public final g(Lt31/p;IZ)V
    .locals 12

    .line 1
    :cond_0
    iget-object v0, p0, Lq41/b;->d:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Lt31/o;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-eqz v3, :cond_3

    .line 15
    .line 16
    const/4 v4, 0x1

    .line 17
    if-eq v3, v4, :cond_2

    .line 18
    .line 19
    const/4 v4, 0x2

    .line 20
    if-ne v3, v4, :cond_1

    .line 21
    .line 22
    iget-object v3, v2, Lt31/o;->e:Ljava/util/List;

    .line 23
    .line 24
    check-cast v3, Ljava/util/Collection;

    .line 25
    .line 26
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    invoke-virtual {v7, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    check-cast v3, Lp31/d;

    .line 35
    .line 36
    invoke-static {v3, p3}, Lp31/d;->a(Lp31/d;Z)Lp31/d;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual {v7, p2, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    const/4 v10, 0x0

    .line 44
    const/16 v11, 0x1ef

    .line 45
    .line 46
    const/4 v3, 0x0

    .line 47
    const/4 v4, 0x0

    .line 48
    const/4 v5, 0x0

    .line 49
    const/4 v6, 0x0

    .line 50
    const/4 v8, 0x0

    .line 51
    const/4 v9, 0x0

    .line 52
    invoke-static/range {v2 .. v11}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    goto :goto_0

    .line 57
    :cond_1
    new-instance p0, La8/r0;

    .line 58
    .line 59
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    iget-object v3, v2, Lt31/o;->d:Ljava/util/List;

    .line 64
    .line 65
    check-cast v3, Ljava/util/Collection;

    .line 66
    .line 67
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    invoke-virtual {v6, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    check-cast v3, Lp31/e;

    .line 76
    .line 77
    invoke-static {v3, p3}, Lp31/e;->a(Lp31/e;Z)Lp31/e;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    invoke-virtual {v6, p2, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    const/4 v10, 0x0

    .line 85
    const/16 v11, 0x1f7

    .line 86
    .line 87
    const/4 v3, 0x0

    .line 88
    const/4 v4, 0x0

    .line 89
    const/4 v5, 0x0

    .line 90
    const/4 v7, 0x0

    .line 91
    const/4 v8, 0x0

    .line 92
    const/4 v9, 0x0

    .line 93
    invoke-static/range {v2 .. v11}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    goto :goto_0

    .line 98
    :cond_3
    iget-object v3, v2, Lt31/o;->c:Ljava/util/List;

    .line 99
    .line 100
    check-cast v3, Ljava/util/Collection;

    .line 101
    .line 102
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    invoke-virtual {v5, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    check-cast v3, Lp31/h;

    .line 111
    .line 112
    invoke-static {v3, p3}, Lp31/h;->a(Lp31/h;Z)Lp31/h;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    invoke-virtual {v5, p2, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    const/4 v10, 0x0

    .line 120
    const/16 v11, 0x1fb

    .line 121
    .line 122
    const/4 v3, 0x0

    .line 123
    const/4 v4, 0x0

    .line 124
    const/4 v6, 0x0

    .line 125
    const/4 v7, 0x0

    .line 126
    const/4 v8, 0x0

    .line 127
    const/4 v9, 0x0

    .line 128
    invoke-static/range {v2 .. v11}, Lt31/o;->a(Lt31/o;ZZLjava/util/List;Ljava/util/List;Ljava/util/List;Ll4/v;Ljava/lang/String;ZI)Lt31/o;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    :goto_0
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    if-eqz v0, :cond_0

    .line 137
    .line 138
    return-void
.end method
