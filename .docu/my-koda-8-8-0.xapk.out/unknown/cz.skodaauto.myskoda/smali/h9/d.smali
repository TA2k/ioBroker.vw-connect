.class public final Lh9/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:Lw7/p;

.field public final b:Lo8/a0;

.field public final c:Lo8/w;

.field public final d:Lo8/y;

.field public final e:Lo8/n;

.field public f:Lo8/q;

.field public g:Lo8/i0;

.field public h:Lo8/i0;

.field public i:I

.field public j:Lt7/c0;

.field public k:J

.field public l:J

.field public m:J

.field public n:J

.field public o:I

.field public p:Lh9/f;

.field public q:Z

.field public r:Z

.field public s:J


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw7/p;

    .line 5
    .line 6
    const/16 v1, 0xa

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lh9/d;->a:Lw7/p;

    .line 12
    .line 13
    new-instance v0, Lo8/a0;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lh9/d;->b:Lo8/a0;

    .line 19
    .line 20
    new-instance v0, Lo8/w;

    .line 21
    .line 22
    invoke-direct {v0}, Lo8/w;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lh9/d;->c:Lo8/w;

    .line 26
    .line 27
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    iput-wide v0, p0, Lh9/d;->k:J

    .line 33
    .line 34
    new-instance v0, Lo8/y;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-direct {v0, v1}, Lo8/y;-><init>(I)V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lh9/d;->d:Lo8/y;

    .line 41
    .line 42
    new-instance v0, Lo8/n;

    .line 43
    .line 44
    invoke-direct {v0}, Lo8/n;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lh9/d;->e:Lo8/n;

    .line 48
    .line 49
    iput-object v0, p0, Lh9/d;->h:Lo8/i0;

    .line 50
    .line 51
    const-wide/16 v0, -0x1

    .line 52
    .line 53
    iput-wide v0, p0, Lh9/d;->n:J

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, v0}, Lh9/d;->g(Lo8/p;Z)Z

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lh9/d;->f:Lo8/q;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lh9/d;->g:Lo8/i0;

    .line 10
    .line 11
    iput-object p1, p0, Lh9/d;->h:Lo8/i0;

    .line 12
    .line 13
    iget-object p0, p0, Lh9/d;->f:Lo8/q;

    .line 14
    .line 15
    invoke-interface {p0}, Lo8/q;->m()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final d(JJ)V
    .locals 2

    .line 1
    const/4 p1, 0x0

    .line 2
    iput p1, p0, Lh9/d;->i:I

    .line 3
    .line 4
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    iput-wide v0, p0, Lh9/d;->k:J

    .line 10
    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    iput-wide v0, p0, Lh9/d;->l:J

    .line 14
    .line 15
    iput p1, p0, Lh9/d;->o:I

    .line 16
    .line 17
    iput-wide p3, p0, Lh9/d;->s:J

    .line 18
    .line 19
    iget-object p0, p0, Lh9/d;->p:Lh9/f;

    .line 20
    .line 21
    instance-of p0, p0, Lh9/b;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    throw p0
.end method

.method public final e()V
    .locals 9

    .line 1
    iget-object v0, p0, Lh9/d;->p:Lh9/f;

    .line 2
    .line 3
    instance-of v1, v0, Lh9/a;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    check-cast v0, Lh9/a;

    .line 8
    .line 9
    invoke-virtual {v0}, Lh9/a;->g()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-wide v0, p0, Lh9/d;->n:J

    .line 16
    .line 17
    const-wide/16 v2, -0x1

    .line 18
    .line 19
    cmp-long v2, v0, v2

    .line 20
    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    iget-object v2, p0, Lh9/d;->p:Lh9/f;

    .line 24
    .line 25
    invoke-interface {v2}, Lh9/f;->f()J

    .line 26
    .line 27
    .line 28
    move-result-wide v2

    .line 29
    cmp-long v0, v0, v2

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    iget-object v0, p0, Lh9/d;->p:Lh9/f;

    .line 34
    .line 35
    check-cast v0, Lh9/a;

    .line 36
    .line 37
    iget-wide v2, p0, Lh9/d;->n:J

    .line 38
    .line 39
    new-instance v1, Lh9/a;

    .line 40
    .line 41
    iget-wide v4, v0, Lh9/a;->h:J

    .line 42
    .line 43
    iget v6, v0, Lh9/a;->i:I

    .line 44
    .line 45
    iget v7, v0, Lh9/a;->j:I

    .line 46
    .line 47
    iget-boolean v8, v0, Lh9/a;->k:Z

    .line 48
    .line 49
    invoke-direct/range {v1 .. v8}, Lh9/a;-><init>(JJIIZ)V

    .line 50
    .line 51
    .line 52
    iput-object v1, p0, Lh9/d;->p:Lh9/f;

    .line 53
    .line 54
    iget-object v0, p0, Lh9/d;->f:Lo8/q;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Lh9/d;->p:Lh9/f;

    .line 60
    .line 61
    invoke-interface {v0, v1}, Lo8/q;->c(Lo8/c0;)V

    .line 62
    .line 63
    .line 64
    iget-object v0, p0, Lh9/d;->g:Lo8/i0;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    iget-object p0, p0, Lh9/d;->p:Lh9/f;

    .line 70
    .line 71
    invoke-interface {p0}, Lo8/c0;->l()J

    .line 72
    .line 73
    .line 74
    :cond_0
    return-void
.end method

.method public final f(Lo8/p;)Z
    .locals 8

    .line 1
    iget-object v0, p0, Lh9/d;->p:Lh9/f;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-interface {v0}, Lh9/f;->f()J

    .line 7
    .line 8
    .line 9
    move-result-wide v2

    .line 10
    const-wide/16 v4, -0x1

    .line 11
    .line 12
    cmp-long v0, v2, v4

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {p1}, Lo8/p;->h()J

    .line 17
    .line 18
    .line 19
    move-result-wide v4

    .line 20
    const-wide/16 v6, 0x4

    .line 21
    .line 22
    sub-long/2addr v2, v6

    .line 23
    cmp-long v0, v4, v2

    .line 24
    .line 25
    if-lez v0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    :try_start_0
    iget-object p0, p0, Lh9/d;->a:Lw7/p;

    .line 29
    .line 30
    iget-object p0, p0, Lw7/p;->a:[B

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    const/4 v2, 0x4

    .line 34
    invoke-interface {p1, p0, v0, v2, v1}, Lo8/p;->b([BIIZ)Z

    .line 35
    .line 36
    .line 37
    move-result p0
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 38
    xor-int/2addr p0, v1

    .line 39
    return p0

    .line 40
    :catch_0
    :goto_0
    return v1
.end method

.method public final g(Lo8/p;Z)Z
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    const v2, 0x8000

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/high16 v2, 0x20000

    .line 12
    .line 13
    :goto_0
    invoke-interface {v1}, Lo8/p;->e()V

    .line 14
    .line 15
    .line 16
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 17
    .line 18
    .line 19
    move-result-wide v3

    .line 20
    const-wide/16 v5, 0x0

    .line 21
    .line 22
    cmp-long v3, v3, v5

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    if-nez v3, :cond_5

    .line 26
    .line 27
    iget-object v3, v0, Lh9/d;->d:Lo8/y;

    .line 28
    .line 29
    iget-object v3, v3, Lo8/y;->d:Lw7/p;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    move v7, v4

    .line 33
    move-object v6, v5

    .line 34
    :goto_1
    :try_start_0
    iget-object v8, v3, Lw7/p;->a:[B

    .line 35
    .line 36
    const/16 v9, 0xa

    .line 37
    .line 38
    invoke-interface {v1, v8, v4, v9}, Lo8/p;->o([BII)V
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    .line 41
    invoke-virtual {v3, v4}, Lw7/p;->I(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3}, Lw7/p;->z()I

    .line 45
    .line 46
    .line 47
    move-result v8

    .line 48
    const v10, 0x494433

    .line 49
    .line 50
    .line 51
    if-eq v8, v10, :cond_1

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_1
    const/4 v8, 0x3

    .line 55
    invoke-virtual {v3, v8}, Lw7/p;->J(I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v3}, Lw7/p;->v()I

    .line 59
    .line 60
    .line 61
    move-result v8

    .line 62
    add-int/lit8 v10, v8, 0xa

    .line 63
    .line 64
    if-nez v6, :cond_2

    .line 65
    .line 66
    new-array v6, v10, [B

    .line 67
    .line 68
    iget-object v11, v3, Lw7/p;->a:[B

    .line 69
    .line 70
    invoke-static {v11, v4, v6, v4, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 71
    .line 72
    .line 73
    invoke-interface {v1, v6, v9, v8}, Lo8/p;->o([BII)V

    .line 74
    .line 75
    .line 76
    new-instance v8, Lc9/i;

    .line 77
    .line 78
    invoke-direct {v8, v5}, Lc9/i;-><init>(Lc9/g;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v8, v10, v6}, Lc9/i;->d(I[B)Lt7/c0;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    goto :goto_2

    .line 86
    :cond_2
    invoke-interface {v1, v8}, Lo8/p;->i(I)V

    .line 87
    .line 88
    .line 89
    :goto_2
    add-int/2addr v7, v10

    .line 90
    goto :goto_1

    .line 91
    :catch_0
    :goto_3
    invoke-interface {v1}, Lo8/p;->e()V

    .line 92
    .line 93
    .line 94
    invoke-interface {v1, v7}, Lo8/p;->i(I)V

    .line 95
    .line 96
    .line 97
    iput-object v6, v0, Lh9/d;->j:Lt7/c0;

    .line 98
    .line 99
    if-eqz v6, :cond_3

    .line 100
    .line 101
    iget-object v3, v0, Lh9/d;->c:Lo8/w;

    .line 102
    .line 103
    invoke-virtual {v3, v6}, Lo8/w;->b(Lt7/c0;)V

    .line 104
    .line 105
    .line 106
    :cond_3
    invoke-interface {v1}, Lo8/p;->h()J

    .line 107
    .line 108
    .line 109
    move-result-wide v5

    .line 110
    long-to-int v3, v5

    .line 111
    if-nez p2, :cond_4

    .line 112
    .line 113
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 114
    .line 115
    .line 116
    :cond_4
    move v5, v4

    .line 117
    :goto_4
    move v6, v5

    .line 118
    move v7, v6

    .line 119
    goto :goto_5

    .line 120
    :cond_5
    move v3, v4

    .line 121
    move v5, v3

    .line 122
    goto :goto_4

    .line 123
    :goto_5
    invoke-virtual/range {p0 .. p1}, Lh9/d;->f(Lo8/p;)Z

    .line 124
    .line 125
    .line 126
    move-result v8

    .line 127
    const/4 v9, 0x1

    .line 128
    if-eqz v8, :cond_7

    .line 129
    .line 130
    if-lez v6, :cond_6

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_6
    invoke-virtual {v0}, Lh9/d;->e()V

    .line 134
    .line 135
    .line 136
    new-instance v0, Ljava/io/EOFException;

    .line 137
    .line 138
    invoke-direct {v0}, Ljava/io/EOFException;-><init>()V

    .line 139
    .line 140
    .line 141
    throw v0

    .line 142
    :cond_7
    iget-object v8, v0, Lh9/d;->a:Lw7/p;

    .line 143
    .line 144
    invoke-virtual {v8, v4}, Lw7/p;->I(I)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 148
    .line 149
    .line 150
    move-result v8

    .line 151
    if-eqz v5, :cond_8

    .line 152
    .line 153
    int-to-long v10, v5

    .line 154
    const v12, -0x1f400

    .line 155
    .line 156
    .line 157
    and-int/2addr v12, v8

    .line 158
    int-to-long v12, v12

    .line 159
    const-wide/32 v14, -0x1f400

    .line 160
    .line 161
    .line 162
    and-long/2addr v10, v14

    .line 163
    cmp-long v10, v12, v10

    .line 164
    .line 165
    if-nez v10, :cond_9

    .line 166
    .line 167
    :cond_8
    invoke-static {v8}, Lo8/b;->h(I)I

    .line 168
    .line 169
    .line 170
    move-result v10

    .line 171
    const/4 v11, -0x1

    .line 172
    if-ne v10, v11, :cond_d

    .line 173
    .line 174
    :cond_9
    add-int/lit8 v5, v7, 0x1

    .line 175
    .line 176
    if-ne v7, v2, :cond_b

    .line 177
    .line 178
    if-eqz p2, :cond_a

    .line 179
    .line 180
    return v4

    .line 181
    :cond_a
    invoke-virtual {v0}, Lh9/d;->e()V

    .line 182
    .line 183
    .line 184
    new-instance v0, Ljava/io/EOFException;

    .line 185
    .line 186
    invoke-direct {v0}, Ljava/io/EOFException;-><init>()V

    .line 187
    .line 188
    .line 189
    throw v0

    .line 190
    :cond_b
    if-eqz p2, :cond_c

    .line 191
    .line 192
    invoke-interface {v1}, Lo8/p;->e()V

    .line 193
    .line 194
    .line 195
    add-int v6, v3, v5

    .line 196
    .line 197
    invoke-interface {v1, v6}, Lo8/p;->i(I)V

    .line 198
    .line 199
    .line 200
    goto :goto_6

    .line 201
    :cond_c
    invoke-interface {v1, v9}, Lo8/p;->n(I)V

    .line 202
    .line 203
    .line 204
    :goto_6
    move v6, v4

    .line 205
    move v7, v5

    .line 206
    move v5, v6

    .line 207
    goto :goto_5

    .line 208
    :cond_d
    add-int/lit8 v6, v6, 0x1

    .line 209
    .line 210
    if-ne v6, v9, :cond_e

    .line 211
    .line 212
    iget-object v5, v0, Lh9/d;->b:Lo8/a0;

    .line 213
    .line 214
    invoke-virtual {v5, v8}, Lo8/a0;->a(I)Z

    .line 215
    .line 216
    .line 217
    move v5, v8

    .line 218
    goto :goto_9

    .line 219
    :cond_e
    const/4 v8, 0x4

    .line 220
    if-ne v6, v8, :cond_10

    .line 221
    .line 222
    :goto_7
    if-eqz p2, :cond_f

    .line 223
    .line 224
    add-int/2addr v3, v7

    .line 225
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 226
    .line 227
    .line 228
    goto :goto_8

    .line 229
    :cond_f
    invoke-interface {v1}, Lo8/p;->e()V

    .line 230
    .line 231
    .line 232
    :goto_8
    iput v5, v0, Lh9/d;->i:I

    .line 233
    .line 234
    return v9

    .line 235
    :cond_10
    :goto_9
    add-int/lit8 v10, v10, -0x4

    .line 236
    .line 237
    invoke-interface {v1, v10}, Lo8/p;->i(I)V

    .line 238
    .line 239
    .line 240
    goto :goto_5
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 53

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lh9/d;->g:Lo8/i0;

    .line 6
    .line 7
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 11
    .line 12
    iget v2, v0, Lh9/d;->i:I

    .line 13
    .line 14
    const/4 v7, 0x0

    .line 15
    iget-object v8, v0, Lh9/d;->b:Lo8/a0;

    .line 16
    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    :try_start_0
    invoke-virtual {v0, v1, v7}, Lh9/d;->g(Lo8/p;Z)Z
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catch_0
    move-object v5, v8

    .line 24
    const/16 p2, 0x0

    .line 25
    .line 26
    const/4 v7, -0x1

    .line 27
    const/4 v14, -0x1

    .line 28
    const-wide/32 v16, 0xf4240

    .line 29
    .line 30
    .line 31
    goto/16 :goto_29

    .line 32
    .line 33
    :cond_0
    :goto_0
    iget-object v2, v0, Lh9/d;->p:Lh9/f;

    .line 34
    .line 35
    iget-object v9, v0, Lh9/d;->a:Lw7/p;

    .line 36
    .line 37
    const/4 v10, 0x1

    .line 38
    if-nez v2, :cond_2f

    .line 39
    .line 40
    new-instance v2, Lw7/p;

    .line 41
    .line 42
    iget v15, v8, Lo8/a0;->b:I

    .line 43
    .line 44
    invoke-direct {v2, v15}, Lw7/p;-><init>(I)V

    .line 45
    .line 46
    .line 47
    iget-object v15, v2, Lw7/p;->a:[B

    .line 48
    .line 49
    const-wide/32 v16, 0xf4240

    .line 50
    .line 51
    .line 52
    iget v3, v8, Lo8/a0;->b:I

    .line 53
    .line 54
    invoke-interface {v1, v15, v7, v3}, Lo8/p;->o([BII)V

    .line 55
    .line 56
    .line 57
    iget v3, v8, Lo8/a0;->a:I

    .line 58
    .line 59
    and-int/2addr v3, v10

    .line 60
    const/16 v4, 0x24

    .line 61
    .line 62
    const/16 v15, 0x15

    .line 63
    .line 64
    if-eqz v3, :cond_2

    .line 65
    .line 66
    iget v3, v8, Lo8/a0;->d:I

    .line 67
    .line 68
    if-eq v3, v10, :cond_1

    .line 69
    .line 70
    move v3, v4

    .line 71
    :goto_1
    const/16 p2, 0x0

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_1
    :goto_2
    move v3, v15

    .line 75
    goto :goto_1

    .line 76
    :cond_2
    iget v3, v8, Lo8/a0;->d:I

    .line 77
    .line 78
    if-eq v3, v10, :cond_3

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_3
    const/16 v3, 0xd

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :goto_3
    iget v5, v2, Lw7/p;->c:I

    .line 85
    .line 86
    const-wide/16 v18, 0x0

    .line 87
    .line 88
    add-int/lit8 v13, v3, 0x4

    .line 89
    .line 90
    const v14, 0x496e666f

    .line 91
    .line 92
    .line 93
    const-wide v20, -0x7fffffffffffffffL    # -4.9E-324

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    const v11, 0x56425249

    .line 99
    .line 100
    .line 101
    const v12, 0x58696e67

    .line 102
    .line 103
    .line 104
    if-lt v5, v13, :cond_4

    .line 105
    .line 106
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-eq v3, v12, :cond_6

    .line 114
    .line 115
    if-ne v3, v14, :cond_4

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_4
    iget v3, v2, Lw7/p;->c:I

    .line 119
    .line 120
    const/16 v5, 0x28

    .line 121
    .line 122
    if-lt v3, v5, :cond_5

    .line 123
    .line 124
    invoke-virtual {v2, v4}, Lw7/p;->I(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    if-ne v3, v11, :cond_5

    .line 132
    .line 133
    move v3, v11

    .line 134
    goto :goto_4

    .line 135
    :cond_5
    move v3, v7

    .line 136
    :cond_6
    :goto_4
    iget-object v4, v0, Lh9/d;->c:Lo8/w;

    .line 137
    .line 138
    const-wide/16 v22, 0x1

    .line 139
    .line 140
    const-wide/16 v24, -0x1

    .line 141
    .line 142
    if-eq v3, v14, :cond_7

    .line 143
    .line 144
    if-eq v3, v11, :cond_8

    .line 145
    .line 146
    if-eq v3, v12, :cond_7

    .line 147
    .line 148
    invoke-interface {v1}, Lo8/p;->e()V

    .line 149
    .line 150
    .line 151
    move-object/from16 v27, p2

    .line 152
    .line 153
    move-object v5, v8

    .line 154
    :goto_5
    move-object/from16 v37, v9

    .line 155
    .line 156
    goto/16 :goto_1a

    .line 157
    .line 158
    :cond_7
    move-object v5, v8

    .line 159
    goto/16 :goto_a

    .line 160
    .line 161
    :cond_8
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 162
    .line 163
    .line 164
    move-result-wide v11

    .line 165
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 166
    .line 167
    .line 168
    move-result-wide v13

    .line 169
    const/4 v3, 0x6

    .line 170
    invoke-virtual {v2, v3}, Lw7/p;->J(I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    iget v15, v8, Lo8/a0;->b:I

    .line 178
    .line 179
    int-to-long v6, v15

    .line 180
    add-long v32, v13, v6

    .line 181
    .line 182
    int-to-long v6, v3

    .line 183
    add-long v6, v32, v6

    .line 184
    .line 185
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    if-gtz v3, :cond_9

    .line 190
    .line 191
    move-object/from16 v27, p2

    .line 192
    .line 193
    move-object v5, v8

    .line 194
    goto/16 :goto_9

    .line 195
    .line 196
    :cond_9
    iget v15, v8, Lo8/a0;->c:I

    .line 197
    .line 198
    move-wide/from16 v27, v6

    .line 199
    .line 200
    int-to-long v5, v3

    .line 201
    iget v3, v8, Lo8/a0;->f:I

    .line 202
    .line 203
    move-wide/from16 v29, v11

    .line 204
    .line 205
    int-to-long v10, v3

    .line 206
    mul-long/2addr v5, v10

    .line 207
    sub-long v5, v5, v22

    .line 208
    .line 209
    invoke-static {v15, v5, v6}, Lw7/w;->H(IJ)J

    .line 210
    .line 211
    .line 212
    move-result-wide v5

    .line 213
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 214
    .line 215
    .line 216
    move-result v3

    .line 217
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 218
    .line 219
    .line 220
    move-result v10

    .line 221
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 222
    .line 223
    .line 224
    move-result v11

    .line 225
    const/4 v12, 0x2

    .line 226
    invoke-virtual {v2, v12}, Lw7/p;->J(I)V

    .line 227
    .line 228
    .line 229
    iget v15, v8, Lo8/a0;->b:I

    .line 230
    .line 231
    move-object/from16 v37, v8

    .line 232
    .line 233
    int-to-long v7, v15

    .line 234
    add-long/2addr v13, v7

    .line 235
    new-array v8, v3, [J

    .line 236
    .line 237
    new-array v15, v3, [J

    .line 238
    .line 239
    const/4 v7, 0x0

    .line 240
    :goto_6
    if-ge v7, v3, :cond_e

    .line 241
    .line 242
    move-wide/from16 v34, v13

    .line 243
    .line 244
    int-to-long v12, v7

    .line 245
    mul-long/2addr v12, v5

    .line 246
    move-wide/from16 v38, v5

    .line 247
    .line 248
    int-to-long v5, v3

    .line 249
    div-long/2addr v12, v5

    .line 250
    aput-wide v12, v8, v7

    .line 251
    .line 252
    aput-wide v34, v15, v7

    .line 253
    .line 254
    const/4 v5, 0x1

    .line 255
    if-eq v11, v5, :cond_d

    .line 256
    .line 257
    move v5, v7

    .line 258
    const/4 v6, 0x2

    .line 259
    if-eq v11, v6, :cond_c

    .line 260
    .line 261
    const/4 v12, 0x3

    .line 262
    if-eq v11, v12, :cond_b

    .line 263
    .line 264
    const/4 v12, 0x4

    .line 265
    if-eq v11, v12, :cond_a

    .line 266
    .line 267
    move-object/from16 v27, p2

    .line 268
    .line 269
    move-object/from16 v5, v37

    .line 270
    .line 271
    goto/16 :goto_9

    .line 272
    .line 273
    :cond_a
    invoke-virtual {v2}, Lw7/p;->A()I

    .line 274
    .line 275
    .line 276
    move-result v12

    .line 277
    goto :goto_7

    .line 278
    :cond_b
    invoke-virtual {v2}, Lw7/p;->z()I

    .line 279
    .line 280
    .line 281
    move-result v12

    .line 282
    goto :goto_7

    .line 283
    :cond_c
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 284
    .line 285
    .line 286
    move-result v12

    .line 287
    goto :goto_7

    .line 288
    :cond_d
    move v5, v7

    .line 289
    const/4 v6, 0x2

    .line 290
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 291
    .line 292
    .line 293
    move-result v12

    .line 294
    :goto_7
    int-to-long v12, v12

    .line 295
    int-to-long v6, v10

    .line 296
    mul-long/2addr v12, v6

    .line 297
    add-long v6, v12, v34

    .line 298
    .line 299
    add-int/lit8 v5, v5, 0x1

    .line 300
    .line 301
    move-wide v13, v6

    .line 302
    const/4 v12, 0x2

    .line 303
    move v7, v5

    .line 304
    move-wide/from16 v5, v38

    .line 305
    .line 306
    goto :goto_6

    .line 307
    :cond_e
    move-wide/from16 v38, v5

    .line 308
    .line 309
    move-wide/from16 v34, v13

    .line 310
    .line 311
    cmp-long v2, v29, v24

    .line 312
    .line 313
    const-string v3, ", "

    .line 314
    .line 315
    const-string v5, "VbriSeeker"

    .line 316
    .line 317
    if-eqz v2, :cond_f

    .line 318
    .line 319
    cmp-long v2, v29, v27

    .line 320
    .line 321
    if-eqz v2, :cond_f

    .line 322
    .line 323
    const-string v2, "VBRI data size mismatch: "

    .line 324
    .line 325
    move-wide/from16 v6, v29

    .line 326
    .line 327
    invoke-static {v6, v7, v2, v3}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 328
    .line 329
    .line 330
    move-result-object v2

    .line 331
    move-wide/from16 v6, v27

    .line 332
    .line 333
    invoke-virtual {v2, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v2

    .line 340
    invoke-static {v5, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    goto :goto_8

    .line 344
    :cond_f
    move-wide/from16 v6, v27

    .line 345
    .line 346
    :goto_8
    cmp-long v2, v6, v34

    .line 347
    .line 348
    if-eqz v2, :cond_10

    .line 349
    .line 350
    const-string v2, "VBRI bytes and ToC mismatch (using max): "

    .line 351
    .line 352
    invoke-static {v6, v7, v2, v3}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 353
    .line 354
    .line 355
    move-result-object v2

    .line 356
    move-wide/from16 v10, v34

    .line 357
    .line 358
    invoke-virtual {v2, v10, v11}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 359
    .line 360
    .line 361
    const-string v3, "\nSeeking will be inaccurate."

    .line 362
    .line 363
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 364
    .line 365
    .line 366
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    invoke-static {v5, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    invoke-static {v6, v7, v10, v11}, Ljava/lang/Math;->max(JJ)J

    .line 374
    .line 375
    .line 376
    move-result-wide v6

    .line 377
    :cond_10
    move-wide/from16 v34, v6

    .line 378
    .line 379
    new-instance v27, Lh9/g;

    .line 380
    .line 381
    move-object/from16 v5, v37

    .line 382
    .line 383
    iget v2, v5, Lo8/a0;->e:I

    .line 384
    .line 385
    move/from16 v36, v2

    .line 386
    .line 387
    move-object/from16 v28, v8

    .line 388
    .line 389
    move-object/from16 v29, v15

    .line 390
    .line 391
    move-wide/from16 v30, v38

    .line 392
    .line 393
    invoke-direct/range {v27 .. v36}, Lh9/g;-><init>([J[JJJJI)V

    .line 394
    .line 395
    .line 396
    :goto_9
    iget v2, v5, Lo8/a0;->b:I

    .line 397
    .line 398
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 399
    .line 400
    .line 401
    goto/16 :goto_5

    .line 402
    .line 403
    :goto_a
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 404
    .line 405
    .line 406
    move-result v6

    .line 407
    and-int/lit8 v7, v6, 0x1

    .line 408
    .line 409
    if-eqz v7, :cond_11

    .line 410
    .line 411
    invoke-virtual {v2}, Lw7/p;->A()I

    .line 412
    .line 413
    .line 414
    move-result v7

    .line 415
    goto :goto_b

    .line 416
    :cond_11
    const/4 v7, -0x1

    .line 417
    :goto_b
    and-int/lit8 v8, v6, 0x2

    .line 418
    .line 419
    if-eqz v8, :cond_12

    .line 420
    .line 421
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 422
    .line 423
    .line 424
    move-result-wide v10

    .line 425
    move-wide/from16 v34, v10

    .line 426
    .line 427
    goto :goto_c

    .line 428
    :cond_12
    move-wide/from16 v34, v24

    .line 429
    .line 430
    :goto_c
    and-int/lit8 v8, v6, 0x4

    .line 431
    .line 432
    const/4 v10, 0x4

    .line 433
    if-ne v8, v10, :cond_14

    .line 434
    .line 435
    const/16 v8, 0x64

    .line 436
    .line 437
    new-array v10, v8, [J

    .line 438
    .line 439
    const/4 v11, 0x0

    .line 440
    :goto_d
    if-ge v11, v8, :cond_13

    .line 441
    .line 442
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 443
    .line 444
    .line 445
    move-result v13

    .line 446
    move-object/from16 v37, v9

    .line 447
    .line 448
    int-to-long v8, v13

    .line 449
    aput-wide v8, v10, v11

    .line 450
    .line 451
    add-int/lit8 v11, v11, 0x1

    .line 452
    .line 453
    move-object/from16 v9, v37

    .line 454
    .line 455
    const/16 v8, 0x64

    .line 456
    .line 457
    goto :goto_d

    .line 458
    :cond_13
    move-object/from16 v36, v10

    .line 459
    .line 460
    :goto_e
    move-object/from16 v37, v9

    .line 461
    .line 462
    goto :goto_f

    .line 463
    :cond_14
    move-object/from16 v36, p2

    .line 464
    .line 465
    goto :goto_e

    .line 466
    :goto_f
    and-int/lit8 v6, v6, 0x8

    .line 467
    .line 468
    if-eqz v6, :cond_15

    .line 469
    .line 470
    const/4 v10, 0x4

    .line 471
    invoke-virtual {v2, v10}, Lw7/p;->J(I)V

    .line 472
    .line 473
    .line 474
    :cond_15
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 475
    .line 476
    .line 477
    move-result v6

    .line 478
    const/16 v8, 0x18

    .line 479
    .line 480
    if-lt v6, v8, :cond_16

    .line 481
    .line 482
    invoke-virtual {v2, v15}, Lw7/p;->J(I)V

    .line 483
    .line 484
    .line 485
    invoke-virtual {v2}, Lw7/p;->z()I

    .line 486
    .line 487
    .line 488
    move-result v2

    .line 489
    const v6, 0xfff000

    .line 490
    .line 491
    .line 492
    and-int/2addr v6, v2

    .line 493
    shr-int/lit8 v6, v6, 0xc

    .line 494
    .line 495
    and-int/lit16 v2, v2, 0xfff

    .line 496
    .line 497
    goto :goto_10

    .line 498
    :cond_16
    const/4 v2, -0x1

    .line 499
    const/4 v6, -0x1

    .line 500
    :goto_10
    int-to-long v7, v7

    .line 501
    iget v9, v5, Lo8/a0;->b:I

    .line 502
    .line 503
    iget v10, v5, Lo8/a0;->c:I

    .line 504
    .line 505
    iget v11, v5, Lo8/a0;->e:I

    .line 506
    .line 507
    iget v13, v5, Lo8/a0;->f:I

    .line 508
    .line 509
    iget v15, v4, Lo8/w;->a:I

    .line 510
    .line 511
    const/4 v14, -0x1

    .line 512
    if-eq v15, v14, :cond_17

    .line 513
    .line 514
    iget v15, v4, Lo8/w;->b:I

    .line 515
    .line 516
    if-eq v15, v14, :cond_17

    .line 517
    .line 518
    goto :goto_11

    .line 519
    :cond_17
    if-eq v6, v14, :cond_18

    .line 520
    .line 521
    if-eq v2, v14, :cond_18

    .line 522
    .line 523
    iput v6, v4, Lo8/w;->a:I

    .line 524
    .line 525
    iput v2, v4, Lo8/w;->b:I

    .line 526
    .line 527
    :cond_18
    :goto_11
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 528
    .line 529
    .line 530
    move-result-wide v28

    .line 531
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 532
    .line 533
    .line 534
    move-result-wide v14

    .line 535
    cmp-long v2, v14, v24

    .line 536
    .line 537
    if-eqz v2, :cond_1a

    .line 538
    .line 539
    cmp-long v2, v34, v24

    .line 540
    .line 541
    if-eqz v2, :cond_1a

    .line 542
    .line 543
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 544
    .line 545
    .line 546
    move-result-wide v14

    .line 547
    move v6, v13

    .line 548
    add-long v12, v28, v34

    .line 549
    .line 550
    cmp-long v14, v14, v12

    .line 551
    .line 552
    if-eqz v14, :cond_19

    .line 553
    .line 554
    new-instance v14, Ljava/lang/StringBuilder;

    .line 555
    .line 556
    const-string v15, "Data size mismatch between stream ("

    .line 557
    .line 558
    invoke-direct {v14, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 559
    .line 560
    .line 561
    move v15, v3

    .line 562
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 563
    .line 564
    .line 565
    move-result-wide v2

    .line 566
    invoke-virtual {v14, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 567
    .line 568
    .line 569
    const-string v2, ") and Xing frame ("

    .line 570
    .line 571
    invoke-virtual {v14, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 572
    .line 573
    .line 574
    invoke-virtual {v14, v12, v13}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 575
    .line 576
    .line 577
    const-string v2, "), using Xing value."

    .line 578
    .line 579
    invoke-virtual {v14, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 580
    .line 581
    .line 582
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 583
    .line 584
    .line 585
    move-result-object v2

    .line 586
    const-string v3, "Mp3Extractor"

    .line 587
    .line 588
    invoke-static {v3, v2}, Lw7/a;->s(Ljava/lang/String;Ljava/lang/String;)V

    .line 589
    .line 590
    .line 591
    goto :goto_12

    .line 592
    :cond_19
    move v15, v3

    .line 593
    goto :goto_12

    .line 594
    :cond_1a
    move v15, v3

    .line 595
    move v6, v13

    .line 596
    :goto_12
    iget v2, v5, Lo8/a0;->b:I

    .line 597
    .line 598
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 599
    .line 600
    .line 601
    const v2, 0x58696e67

    .line 602
    .line 603
    .line 604
    if-ne v15, v2, :cond_1f

    .line 605
    .line 606
    cmp-long v2, v7, v24

    .line 607
    .line 608
    if-eqz v2, :cond_1c

    .line 609
    .line 610
    cmp-long v2, v7, v18

    .line 611
    .line 612
    if-nez v2, :cond_1b

    .line 613
    .line 614
    goto :goto_13

    .line 615
    :cond_1b
    int-to-long v2, v6

    .line 616
    mul-long/2addr v7, v2

    .line 617
    sub-long v7, v7, v22

    .line 618
    .line 619
    invoke-static {v10, v7, v8}, Lw7/w;->H(IJ)J

    .line 620
    .line 621
    .line 622
    move-result-wide v2

    .line 623
    move-wide/from16 v31, v2

    .line 624
    .line 625
    goto :goto_14

    .line 626
    :cond_1c
    :goto_13
    move-wide/from16 v31, v20

    .line 627
    .line 628
    :goto_14
    cmp-long v2, v31, v20

    .line 629
    .line 630
    if-nez v2, :cond_1e

    .line 631
    .line 632
    :cond_1d
    :goto_15
    move-object/from16 v27, p2

    .line 633
    .line 634
    goto/16 :goto_1a

    .line 635
    .line 636
    :cond_1e
    new-instance v27, Lh9/h;

    .line 637
    .line 638
    move/from16 v30, v9

    .line 639
    .line 640
    move/from16 v33, v11

    .line 641
    .line 642
    invoke-direct/range {v27 .. v36}, Lh9/h;-><init>(JIJIJ[J)V

    .line 643
    .line 644
    .line 645
    goto :goto_1a

    .line 646
    :cond_1f
    move v2, v9

    .line 647
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 648
    .line 649
    .line 650
    move-result-wide v11

    .line 651
    cmp-long v3, v7, v24

    .line 652
    .line 653
    if-eqz v3, :cond_21

    .line 654
    .line 655
    cmp-long v3, v7, v18

    .line 656
    .line 657
    if-nez v3, :cond_20

    .line 658
    .line 659
    goto :goto_16

    .line 660
    :cond_20
    int-to-long v13, v6

    .line 661
    mul-long/2addr v13, v7

    .line 662
    sub-long v13, v13, v22

    .line 663
    .line 664
    invoke-static {v10, v13, v14}, Lw7/w;->H(IJ)J

    .line 665
    .line 666
    .line 667
    move-result-wide v9

    .line 668
    move-wide/from16 v43, v9

    .line 669
    .line 670
    goto :goto_17

    .line 671
    :cond_21
    :goto_16
    move-wide/from16 v43, v20

    .line 672
    .line 673
    :goto_17
    cmp-long v3, v43, v20

    .line 674
    .line 675
    if-nez v3, :cond_22

    .line 676
    .line 677
    goto :goto_15

    .line 678
    :cond_22
    cmp-long v3, v34, v24

    .line 679
    .line 680
    if-eqz v3, :cond_23

    .line 681
    .line 682
    add-long v11, v28, v34

    .line 683
    .line 684
    int-to-long v9, v2

    .line 685
    sub-long v34, v34, v9

    .line 686
    .line 687
    :goto_18
    move-wide/from16 v46, v11

    .line 688
    .line 689
    move-wide/from16 v39, v34

    .line 690
    .line 691
    goto :goto_19

    .line 692
    :cond_23
    cmp-long v3, v11, v24

    .line 693
    .line 694
    if-eqz v3, :cond_1d

    .line 695
    .line 696
    sub-long v9, v11, v28

    .line 697
    .line 698
    int-to-long v13, v2

    .line 699
    sub-long v34, v9, v13

    .line 700
    .line 701
    goto :goto_18

    .line 702
    :goto_19
    sget-object v45, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 703
    .line 704
    const-wide/32 v41, 0x7a1200

    .line 705
    .line 706
    .line 707
    invoke-static/range {v39 .. v45}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 708
    .line 709
    .line 710
    move-result-wide v9

    .line 711
    move-wide/from16 v11, v39

    .line 712
    .line 713
    move-object/from16 v3, v45

    .line 714
    .line 715
    invoke-static {v9, v10}, Llp/de;->c(J)I

    .line 716
    .line 717
    .line 718
    move-result v50

    .line 719
    invoke-static {v11, v12, v7, v8, v3}, Llp/pc;->b(JJLjava/math/RoundingMode;)J

    .line 720
    .line 721
    .line 722
    move-result-wide v6

    .line 723
    invoke-static {v6, v7}, Llp/de;->c(J)I

    .line 724
    .line 725
    .line 726
    move-result v51

    .line 727
    new-instance v45, Lh9/a;

    .line 728
    .line 729
    int-to-long v2, v2

    .line 730
    add-long v48, v28, v2

    .line 731
    .line 732
    const/16 v52, 0x0

    .line 733
    .line 734
    invoke-direct/range {v45 .. v52}, Lh9/a;-><init>(JJIIZ)V

    .line 735
    .line 736
    .line 737
    move-object/from16 v27, v45

    .line 738
    .line 739
    :goto_1a
    iget-object v2, v0, Lh9/d;->j:Lt7/c0;

    .line 740
    .line 741
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 742
    .line 743
    .line 744
    move-result-wide v6

    .line 745
    if-eqz v2, :cond_28

    .line 746
    .line 747
    iget-object v3, v2, Lt7/c0;->a:[Lt7/b0;

    .line 748
    .line 749
    array-length v8, v3

    .line 750
    const/4 v9, 0x0

    .line 751
    :goto_1b
    if-ge v9, v8, :cond_28

    .line 752
    .line 753
    aget-object v10, v3, v9

    .line 754
    .line 755
    instance-of v11, v10, Lc9/m;

    .line 756
    .line 757
    if-eqz v11, :cond_27

    .line 758
    .line 759
    check-cast v10, Lc9/m;

    .line 760
    .line 761
    iget-object v3, v10, Lc9/m;->e:[I

    .line 762
    .line 763
    if-eqz v2, :cond_25

    .line 764
    .line 765
    iget-object v2, v2, Lt7/c0;->a:[Lt7/b0;

    .line 766
    .line 767
    array-length v8, v2

    .line 768
    const/4 v9, 0x0

    .line 769
    :goto_1c
    if-ge v9, v8, :cond_25

    .line 770
    .line 771
    aget-object v11, v2, v9

    .line 772
    .line 773
    instance-of v12, v11, Lc9/o;

    .line 774
    .line 775
    if-eqz v12, :cond_24

    .line 776
    .line 777
    check-cast v11, Lc9/o;

    .line 778
    .line 779
    iget-object v12, v11, Lc9/j;->a:Ljava/lang/String;

    .line 780
    .line 781
    const-string v13, "TLEN"

    .line 782
    .line 783
    invoke-virtual {v12, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 784
    .line 785
    .line 786
    move-result v12

    .line 787
    if-eqz v12, :cond_24

    .line 788
    .line 789
    iget-object v2, v11, Lc9/o;->c:Lhr/h0;

    .line 790
    .line 791
    const/4 v8, 0x0

    .line 792
    invoke-interface {v2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 793
    .line 794
    .line 795
    move-result-object v2

    .line 796
    check-cast v2, Ljava/lang/String;

    .line 797
    .line 798
    invoke-static {v2}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 799
    .line 800
    .line 801
    move-result-wide v8

    .line 802
    invoke-static {v8, v9}, Lw7/w;->D(J)J

    .line 803
    .line 804
    .line 805
    move-result-wide v8

    .line 806
    goto :goto_1d

    .line 807
    :cond_24
    add-int/lit8 v9, v9, 0x1

    .line 808
    .line 809
    goto :goto_1c

    .line 810
    :cond_25
    move-wide/from16 v8, v20

    .line 811
    .line 812
    :goto_1d
    array-length v2, v3

    .line 813
    add-int/lit8 v11, v2, 0x1

    .line 814
    .line 815
    new-array v12, v11, [J

    .line 816
    .line 817
    new-array v11, v11, [J

    .line 818
    .line 819
    const/16 v26, 0x0

    .line 820
    .line 821
    aput-wide v6, v12, v26

    .line 822
    .line 823
    aput-wide v18, v11, v26

    .line 824
    .line 825
    move-wide/from16 v13, v18

    .line 826
    .line 827
    const/4 v15, 0x1

    .line 828
    :goto_1e
    if-gt v15, v2, :cond_26

    .line 829
    .line 830
    move/from16 v22, v2

    .line 831
    .line 832
    iget v2, v10, Lc9/m;->c:I

    .line 833
    .line 834
    add-int/lit8 v18, v15, -0x1

    .line 835
    .line 836
    aget v19, v3, v18

    .line 837
    .line 838
    add-int v2, v2, v19

    .line 839
    .line 840
    move-object/from16 v23, v3

    .line 841
    .line 842
    int-to-long v2, v2

    .line 843
    add-long/2addr v6, v2

    .line 844
    iget v2, v10, Lc9/m;->d:I

    .line 845
    .line 846
    iget-object v3, v10, Lc9/m;->f:[I

    .line 847
    .line 848
    aget v3, v3, v18

    .line 849
    .line 850
    add-int/2addr v2, v3

    .line 851
    int-to-long v2, v2

    .line 852
    add-long/2addr v13, v2

    .line 853
    aput-wide v6, v12, v15

    .line 854
    .line 855
    aput-wide v13, v11, v15

    .line 856
    .line 857
    add-int/lit8 v15, v15, 0x1

    .line 858
    .line 859
    move/from16 v2, v22

    .line 860
    .line 861
    move-object/from16 v3, v23

    .line 862
    .line 863
    goto :goto_1e

    .line 864
    :cond_26
    new-instance v2, Lh9/c;

    .line 865
    .line 866
    invoke-direct {v2, v8, v9, v12, v11}, Lh9/c;-><init>(J[J[J)V

    .line 867
    .line 868
    .line 869
    goto :goto_1f

    .line 870
    :cond_27
    add-int/lit8 v9, v9, 0x1

    .line 871
    .line 872
    goto :goto_1b

    .line 873
    :cond_28
    move-object/from16 v2, p2

    .line 874
    .line 875
    :goto_1f
    iget-boolean v3, v0, Lh9/d;->q:Z

    .line 876
    .line 877
    if-eqz v3, :cond_29

    .line 878
    .line 879
    new-instance v2, Lh9/e;

    .line 880
    .line 881
    move-wide/from16 v6, v20

    .line 882
    .line 883
    invoke-direct {v2, v6, v7}, Lo8/t;-><init>(J)V

    .line 884
    .line 885
    .line 886
    move-object v6, v2

    .line 887
    move-object/from16 v2, v37

    .line 888
    .line 889
    goto :goto_22

    .line 890
    :cond_29
    if-eqz v2, :cond_2a

    .line 891
    .line 892
    move-object/from16 v27, v2

    .line 893
    .line 894
    goto :goto_20

    .line 895
    :cond_2a
    if-eqz v27, :cond_2b

    .line 896
    .line 897
    goto :goto_20

    .line 898
    :cond_2b
    move-object/from16 v27, p2

    .line 899
    .line 900
    :goto_20
    if-eqz v27, :cond_2c

    .line 901
    .line 902
    invoke-interface/range {v27 .. v27}, Lo8/c0;->g()Z

    .line 903
    .line 904
    .line 905
    :cond_2c
    if-eqz v27, :cond_2d

    .line 906
    .line 907
    invoke-interface/range {v27 .. v27}, Lo8/c0;->g()Z

    .line 908
    .line 909
    .line 910
    move-object/from16 v6, v27

    .line 911
    .line 912
    move-object/from16 v2, v37

    .line 913
    .line 914
    goto :goto_21

    .line 915
    :cond_2d
    move-object/from16 v2, v37

    .line 916
    .line 917
    iget-object v3, v2, Lw7/p;->a:[B

    .line 918
    .line 919
    const/4 v8, 0x0

    .line 920
    const/4 v10, 0x4

    .line 921
    invoke-interface {v1, v3, v8, v10}, Lo8/p;->o([BII)V

    .line 922
    .line 923
    .line 924
    invoke-virtual {v2, v8}, Lw7/p;->I(I)V

    .line 925
    .line 926
    .line 927
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 928
    .line 929
    .line 930
    move-result v3

    .line 931
    invoke-virtual {v5, v3}, Lo8/a0;->a(I)Z

    .line 932
    .line 933
    .line 934
    new-instance v6, Lh9/a;

    .line 935
    .line 936
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 937
    .line 938
    .line 939
    move-result-wide v7

    .line 940
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 941
    .line 942
    .line 943
    move-result-wide v9

    .line 944
    iget v11, v5, Lo8/a0;->e:I

    .line 945
    .line 946
    iget v12, v5, Lo8/a0;->b:I

    .line 947
    .line 948
    const/4 v13, 0x0

    .line 949
    invoke-direct/range {v6 .. v13}, Lh9/a;-><init>(JJIIZ)V

    .line 950
    .line 951
    .line 952
    :goto_21
    iget-object v3, v0, Lh9/d;->g:Lo8/i0;

    .line 953
    .line 954
    invoke-interface {v6}, Lo8/c0;->l()J

    .line 955
    .line 956
    .line 957
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 958
    .line 959
    .line 960
    :goto_22
    iput-object v6, v0, Lh9/d;->p:Lh9/f;

    .line 961
    .line 962
    iget-object v3, v0, Lh9/d;->f:Lo8/q;

    .line 963
    .line 964
    invoke-interface {v3, v6}, Lo8/q;->c(Lo8/c0;)V

    .line 965
    .line 966
    .line 967
    new-instance v3, Lt7/n;

    .line 968
    .line 969
    invoke-direct {v3}, Lt7/n;-><init>()V

    .line 970
    .line 971
    .line 972
    const-string v6, "audio/mpeg"

    .line 973
    .line 974
    invoke-static {v6}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 975
    .line 976
    .line 977
    move-result-object v6

    .line 978
    iput-object v6, v3, Lt7/n;->l:Ljava/lang/String;

    .line 979
    .line 980
    iget-object v6, v5, Lo8/a0;->g:Ljava/io/Serializable;

    .line 981
    .line 982
    check-cast v6, Ljava/lang/String;

    .line 983
    .line 984
    invoke-static {v6}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 985
    .line 986
    .line 987
    move-result-object v6

    .line 988
    iput-object v6, v3, Lt7/n;->m:Ljava/lang/String;

    .line 989
    .line 990
    const/16 v6, 0x1000

    .line 991
    .line 992
    iput v6, v3, Lt7/n;->n:I

    .line 993
    .line 994
    iget v6, v5, Lo8/a0;->d:I

    .line 995
    .line 996
    iput v6, v3, Lt7/n;->E:I

    .line 997
    .line 998
    iget v6, v5, Lo8/a0;->c:I

    .line 999
    .line 1000
    iput v6, v3, Lt7/n;->F:I

    .line 1001
    .line 1002
    iget v6, v4, Lo8/w;->a:I

    .line 1003
    .line 1004
    iput v6, v3, Lt7/n;->H:I

    .line 1005
    .line 1006
    iget v4, v4, Lo8/w;->b:I

    .line 1007
    .line 1008
    iput v4, v3, Lt7/n;->I:I

    .line 1009
    .line 1010
    iget-object v4, v0, Lh9/d;->j:Lt7/c0;

    .line 1011
    .line 1012
    iput-object v4, v3, Lt7/n;->k:Lt7/c0;

    .line 1013
    .line 1014
    iget-object v4, v0, Lh9/d;->p:Lh9/f;

    .line 1015
    .line 1016
    invoke-interface {v4}, Lh9/f;->k()I

    .line 1017
    .line 1018
    .line 1019
    move-result v4

    .line 1020
    const v6, -0x7fffffff

    .line 1021
    .line 1022
    .line 1023
    if-eq v4, v6, :cond_2e

    .line 1024
    .line 1025
    iget-object v4, v0, Lh9/d;->p:Lh9/f;

    .line 1026
    .line 1027
    invoke-interface {v4}, Lh9/f;->k()I

    .line 1028
    .line 1029
    .line 1030
    move-result v4

    .line 1031
    iput v4, v3, Lt7/n;->h:I

    .line 1032
    .line 1033
    :cond_2e
    iget-object v4, v0, Lh9/d;->h:Lo8/i0;

    .line 1034
    .line 1035
    new-instance v6, Lt7/o;

    .line 1036
    .line 1037
    invoke-direct {v6, v3}, Lt7/o;-><init>(Lt7/n;)V

    .line 1038
    .line 1039
    .line 1040
    invoke-interface {v4, v6}, Lo8/i0;->c(Lt7/o;)V

    .line 1041
    .line 1042
    .line 1043
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1044
    .line 1045
    .line 1046
    move-result-wide v3

    .line 1047
    iput-wide v3, v0, Lh9/d;->m:J

    .line 1048
    .line 1049
    goto :goto_23

    .line 1050
    :cond_2f
    move-object v5, v8

    .line 1051
    move-object v2, v9

    .line 1052
    const/16 p2, 0x0

    .line 1053
    .line 1054
    const-wide/32 v16, 0xf4240

    .line 1055
    .line 1056
    .line 1057
    const-wide/16 v18, 0x0

    .line 1058
    .line 1059
    iget-wide v3, v0, Lh9/d;->m:J

    .line 1060
    .line 1061
    cmp-long v3, v3, v18

    .line 1062
    .line 1063
    if-eqz v3, :cond_30

    .line 1064
    .line 1065
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1066
    .line 1067
    .line 1068
    move-result-wide v3

    .line 1069
    iget-wide v6, v0, Lh9/d;->m:J

    .line 1070
    .line 1071
    cmp-long v8, v3, v6

    .line 1072
    .line 1073
    if-gez v8, :cond_30

    .line 1074
    .line 1075
    sub-long/2addr v6, v3

    .line 1076
    long-to-int v3, v6

    .line 1077
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 1078
    .line 1079
    .line 1080
    :cond_30
    :goto_23
    iget v3, v0, Lh9/d;->o:I

    .line 1081
    .line 1082
    if-nez v3, :cond_35

    .line 1083
    .line 1084
    invoke-interface {v1}, Lo8/p;->e()V

    .line 1085
    .line 1086
    .line 1087
    invoke-virtual/range {p0 .. p1}, Lh9/d;->f(Lo8/p;)Z

    .line 1088
    .line 1089
    .line 1090
    move-result v3

    .line 1091
    if-eqz v3, :cond_31

    .line 1092
    .line 1093
    goto/16 :goto_28

    .line 1094
    .line 1095
    :cond_31
    const/4 v8, 0x0

    .line 1096
    invoke-virtual {v2, v8}, Lw7/p;->I(I)V

    .line 1097
    .line 1098
    .line 1099
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 1100
    .line 1101
    .line 1102
    move-result v2

    .line 1103
    iget v3, v0, Lh9/d;->i:I

    .line 1104
    .line 1105
    int-to-long v3, v3

    .line 1106
    const v6, -0x1f400

    .line 1107
    .line 1108
    .line 1109
    and-int/2addr v6, v2

    .line 1110
    int-to-long v6, v6

    .line 1111
    const-wide/32 v8, -0x1f400

    .line 1112
    .line 1113
    .line 1114
    and-long/2addr v3, v8

    .line 1115
    cmp-long v3, v6, v3

    .line 1116
    .line 1117
    if-nez v3, :cond_32

    .line 1118
    .line 1119
    invoke-static {v2}, Lo8/b;->h(I)I

    .line 1120
    .line 1121
    .line 1122
    move-result v3

    .line 1123
    const/4 v14, -0x1

    .line 1124
    if-ne v3, v14, :cond_33

    .line 1125
    .line 1126
    :cond_32
    const/4 v7, 0x1

    .line 1127
    goto :goto_24

    .line 1128
    :cond_33
    invoke-virtual {v5, v2}, Lo8/a0;->a(I)Z

    .line 1129
    .line 1130
    .line 1131
    iget-wide v2, v0, Lh9/d;->k:J

    .line 1132
    .line 1133
    const-wide v20, -0x7fffffffffffffffL    # -4.9E-324

    .line 1134
    .line 1135
    .line 1136
    .line 1137
    .line 1138
    cmp-long v2, v2, v20

    .line 1139
    .line 1140
    if-nez v2, :cond_34

    .line 1141
    .line 1142
    iget-object v2, v0, Lh9/d;->p:Lh9/f;

    .line 1143
    .line 1144
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1145
    .line 1146
    .line 1147
    move-result-wide v3

    .line 1148
    invoke-interface {v2, v3, v4}, Lh9/f;->i(J)J

    .line 1149
    .line 1150
    .line 1151
    move-result-wide v2

    .line 1152
    iput-wide v2, v0, Lh9/d;->k:J

    .line 1153
    .line 1154
    :cond_34
    iget v2, v5, Lo8/a0;->b:I

    .line 1155
    .line 1156
    iput v2, v0, Lh9/d;->o:I

    .line 1157
    .line 1158
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1159
    .line 1160
    .line 1161
    move-result-wide v2

    .line 1162
    iget v4, v5, Lo8/a0;->b:I

    .line 1163
    .line 1164
    int-to-long v6, v4

    .line 1165
    add-long/2addr v2, v6

    .line 1166
    iput-wide v2, v0, Lh9/d;->n:J

    .line 1167
    .line 1168
    iget-object v2, v0, Lh9/d;->p:Lh9/f;

    .line 1169
    .line 1170
    instance-of v2, v2, Lh9/b;

    .line 1171
    .line 1172
    if-nez v2, :cond_36

    .line 1173
    .line 1174
    :cond_35
    const/4 v7, 0x1

    .line 1175
    goto :goto_27

    .line 1176
    :cond_36
    iget-wide v0, v0, Lh9/d;->l:J

    .line 1177
    .line 1178
    iget v2, v5, Lo8/a0;->f:I

    .line 1179
    .line 1180
    int-to-long v2, v2

    .line 1181
    add-long/2addr v0, v2

    .line 1182
    mul-long v0, v0, v16

    .line 1183
    .line 1184
    iget v2, v5, Lo8/a0;->c:I

    .line 1185
    .line 1186
    int-to-long v2, v2

    .line 1187
    div-long/2addr v0, v2

    .line 1188
    throw p2

    .line 1189
    :goto_24
    invoke-interface {v1, v7}, Lo8/p;->n(I)V

    .line 1190
    .line 1191
    .line 1192
    const/4 v8, 0x0

    .line 1193
    iput v8, v0, Lh9/d;->i:I

    .line 1194
    .line 1195
    :goto_25
    const/4 v7, 0x0

    .line 1196
    :goto_26
    const/4 v14, -0x1

    .line 1197
    goto :goto_29

    .line 1198
    :goto_27
    iget-object v2, v0, Lh9/d;->h:Lo8/i0;

    .line 1199
    .line 1200
    iget v3, v0, Lh9/d;->o:I

    .line 1201
    .line 1202
    invoke-interface {v2, v1, v3, v7}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 1203
    .line 1204
    .line 1205
    move-result v1

    .line 1206
    const/4 v14, -0x1

    .line 1207
    if-ne v1, v14, :cond_37

    .line 1208
    .line 1209
    :goto_28
    const/4 v7, -0x1

    .line 1210
    goto :goto_26

    .line 1211
    :cond_37
    iget v2, v0, Lh9/d;->o:I

    .line 1212
    .line 1213
    sub-int/2addr v2, v1

    .line 1214
    iput v2, v0, Lh9/d;->o:I

    .line 1215
    .line 1216
    if-lez v2, :cond_38

    .line 1217
    .line 1218
    goto :goto_25

    .line 1219
    :cond_38
    iget-object v6, v0, Lh9/d;->h:Lo8/i0;

    .line 1220
    .line 1221
    iget-wide v1, v0, Lh9/d;->l:J

    .line 1222
    .line 1223
    iget-wide v3, v0, Lh9/d;->k:J

    .line 1224
    .line 1225
    mul-long v1, v1, v16

    .line 1226
    .line 1227
    iget v7, v5, Lo8/a0;->c:I

    .line 1228
    .line 1229
    int-to-long v7, v7

    .line 1230
    div-long/2addr v1, v7

    .line 1231
    add-long v7, v1, v3

    .line 1232
    .line 1233
    iget v10, v5, Lo8/a0;->b:I

    .line 1234
    .line 1235
    const/4 v11, 0x0

    .line 1236
    const/4 v12, 0x0

    .line 1237
    const/4 v9, 0x1

    .line 1238
    invoke-interface/range {v6 .. v12}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 1239
    .line 1240
    .line 1241
    iget-wide v1, v0, Lh9/d;->l:J

    .line 1242
    .line 1243
    iget v3, v5, Lo8/a0;->f:I

    .line 1244
    .line 1245
    int-to-long v3, v3

    .line 1246
    add-long/2addr v1, v3

    .line 1247
    iput-wide v1, v0, Lh9/d;->l:J

    .line 1248
    .line 1249
    const/4 v8, 0x0

    .line 1250
    iput v8, v0, Lh9/d;->o:I

    .line 1251
    .line 1252
    move v7, v8

    .line 1253
    goto :goto_26

    .line 1254
    :goto_29
    if-ne v7, v14, :cond_3a

    .line 1255
    .line 1256
    iget-object v1, v0, Lh9/d;->p:Lh9/f;

    .line 1257
    .line 1258
    instance-of v2, v1, Lh9/b;

    .line 1259
    .line 1260
    if-eqz v2, :cond_3a

    .line 1261
    .line 1262
    iget-wide v2, v0, Lh9/d;->l:J

    .line 1263
    .line 1264
    iget-wide v8, v0, Lh9/d;->k:J

    .line 1265
    .line 1266
    mul-long v2, v2, v16

    .line 1267
    .line 1268
    iget v4, v5, Lo8/a0;->c:I

    .line 1269
    .line 1270
    int-to-long v4, v4

    .line 1271
    div-long/2addr v2, v4

    .line 1272
    add-long/2addr v2, v8

    .line 1273
    invoke-interface {v1}, Lo8/c0;->l()J

    .line 1274
    .line 1275
    .line 1276
    move-result-wide v4

    .line 1277
    cmp-long v1, v4, v2

    .line 1278
    .line 1279
    if-nez v1, :cond_39

    .line 1280
    .line 1281
    goto :goto_2a

    .line 1282
    :cond_39
    iget-object v0, v0, Lh9/d;->p:Lh9/f;

    .line 1283
    .line 1284
    check-cast v0, Lh9/b;

    .line 1285
    .line 1286
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1287
    .line 1288
    .line 1289
    throw p2

    .line 1290
    :cond_3a
    :goto_2a
    return v7
.end method
