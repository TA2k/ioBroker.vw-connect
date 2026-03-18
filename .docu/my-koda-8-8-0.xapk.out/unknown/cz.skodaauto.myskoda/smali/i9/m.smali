.class public final Li9/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;
.implements Lo8/c0;


# instance fields
.field public A:[Li9/l;

.field public B:[[J

.field public C:I

.field public D:J

.field public E:I

.field public F:Ld9/a;

.field public final a:Ll9/h;

.field public final b:I

.field public final c:Lw7/p;

.field public final d:Lw7/p;

.field public final e:Lw7/p;

.field public final f:Lw7/p;

.field public final g:Ljava/util/ArrayDeque;

.field public final h:Li9/o;

.field public final i:Ljava/util/ArrayList;

.field public j:Lhr/x0;

.field public k:I

.field public l:I

.field public m:J

.field public n:I

.field public o:Lw7/p;

.field public p:I

.field public q:I

.field public r:I

.field public s:I

.field public t:Z

.field public u:Z

.field public v:Z

.field public w:J

.field public x:Z

.field public y:J

.field public z:Lo8/q;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Ll9/h;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li9/m;->a:Ll9/h;

    .line 5
    .line 6
    iput p2, p0, Li9/m;->b:I

    .line 7
    .line 8
    sget-object p1, Lhr/h0;->e:Lhr/f0;

    .line 9
    .line 10
    sget-object p1, Lhr/x0;->h:Lhr/x0;

    .line 11
    .line 12
    iput-object p1, p0, Li9/m;->j:Lhr/x0;

    .line 13
    .line 14
    and-int/lit8 p1, p2, 0x4

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x3

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move p1, p2

    .line 22
    :goto_0
    iput p1, p0, Li9/m;->k:I

    .line 23
    .line 24
    new-instance p1, Li9/o;

    .line 25
    .line 26
    invoke-direct {p1}, Li9/o;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Li9/m;->h:Li9/o;

    .line 30
    .line 31
    new-instance p1, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Li9/m;->i:Ljava/util/ArrayList;

    .line 37
    .line 38
    new-instance p1, Lw7/p;

    .line 39
    .line 40
    const/16 v0, 0x10

    .line 41
    .line 42
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Li9/m;->f:Lw7/p;

    .line 46
    .line 47
    new-instance p1, Ljava/util/ArrayDeque;

    .line 48
    .line 49
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object p1, p0, Li9/m;->g:Ljava/util/ArrayDeque;

    .line 53
    .line 54
    new-instance p1, Lw7/p;

    .line 55
    .line 56
    sget-object v0, Lx7/n;->a:[B

    .line 57
    .line 58
    invoke-direct {p1, v0}, Lw7/p;-><init>([B)V

    .line 59
    .line 60
    .line 61
    iput-object p1, p0, Li9/m;->c:Lw7/p;

    .line 62
    .line 63
    new-instance p1, Lw7/p;

    .line 64
    .line 65
    const/4 v0, 0x6

    .line 66
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Li9/m;->d:Lw7/p;

    .line 70
    .line 71
    new-instance p1, Lw7/p;

    .line 72
    .line 73
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 74
    .line 75
    .line 76
    iput-object p1, p0, Li9/m;->e:Lw7/p;

    .line 77
    .line 78
    const/4 p1, -0x1

    .line 79
    iput p1, p0, Li9/m;->p:I

    .line 80
    .line 81
    sget-object p1, Lo8/q;->l1:Lrb0/a;

    .line 82
    .line 83
    iput-object p1, p0, Li9/m;->z:Lo8/q;

    .line 84
    .line 85
    new-array p1, p2, [Li9/l;

    .line 86
    .line 87
    iput-object p1, p0, Li9/m;->A:[Li9/l;

    .line 88
    .line 89
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 3

    .line 1
    iget v0, p0, Li9/m;->b:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x2

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    move v0, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v2

    .line 12
    :goto_0
    invoke-static {p1, v2, v0}, Li9/p;->k(Lo8/p;ZZ)Lo8/g0;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    invoke-static {p1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    sget-object v0, Lhr/h0;->e:Lhr/f0;

    .line 24
    .line 25
    sget-object v0, Lhr/x0;->h:Lhr/x0;

    .line 26
    .line 27
    :goto_1
    iput-object v0, p0, Li9/m;->j:Lhr/x0;

    .line 28
    .line 29
    if-nez p1, :cond_2

    .line 30
    .line 31
    return v1

    .line 32
    :cond_2
    return v2
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 2

    .line 1
    iget v0, p0, Li9/m;->b:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x10

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, La8/b;

    .line 8
    .line 9
    iget-object v1, p0, Li9/m;->a:Ll9/h;

    .line 10
    .line 11
    invoke-direct {v0, p1, v1}, La8/b;-><init>(Lo8/q;Ll9/h;)V

    .line 12
    .line 13
    .line 14
    move-object p1, v0

    .line 15
    :cond_0
    iput-object p1, p0, Li9/m;->z:Lo8/q;

    .line 16
    .line 17
    return-void
.end method

.method public final d(JJ)V
    .locals 6

    .line 1
    iget-object v0, p0, Li9/m;->g:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->clear()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput v0, p0, Li9/m;->n:I

    .line 8
    .line 9
    const/4 v1, -0x1

    .line 10
    iput v1, p0, Li9/m;->p:I

    .line 11
    .line 12
    iput v0, p0, Li9/m;->q:I

    .line 13
    .line 14
    iput v0, p0, Li9/m;->r:I

    .line 15
    .line 16
    iput v0, p0, Li9/m;->s:I

    .line 17
    .line 18
    iput-boolean v0, p0, Li9/m;->t:Z

    .line 19
    .line 20
    const-wide/16 v2, 0x0

    .line 21
    .line 22
    cmp-long p1, p1, v2

    .line 23
    .line 24
    if-nez p1, :cond_1

    .line 25
    .line 26
    iget p1, p0, Li9/m;->k:I

    .line 27
    .line 28
    const/4 p2, 0x3

    .line 29
    if-eq p1, p2, :cond_0

    .line 30
    .line 31
    iput v0, p0, Li9/m;->k:I

    .line 32
    .line 33
    iput v0, p0, Li9/m;->n:I

    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    iget-object p1, p0, Li9/m;->h:Li9/o;

    .line 37
    .line 38
    iget-object p2, p1, Li9/o;->a:Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-virtual {p2}, Ljava/util/ArrayList;->clear()V

    .line 41
    .line 42
    .line 43
    iput v0, p1, Li9/o;->b:I

    .line 44
    .line 45
    iget-object p0, p0, Li9/m;->i:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    iget-object p0, p0, Li9/m;->A:[Li9/l;

    .line 52
    .line 53
    array-length p1, p0

    .line 54
    move p2, v0

    .line 55
    :goto_0
    if-ge p2, p1, :cond_6

    .line 56
    .line 57
    aget-object v2, p0, p2

    .line 58
    .line 59
    iget-object v3, v2, Li9/l;->b:Li9/t;

    .line 60
    .line 61
    iget-object v4, v3, Li9/t;->f:[J

    .line 62
    .line 63
    invoke-static {v4, p3, p4, v0}, Lw7/w;->d([JJZ)I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    :goto_1
    if-ltz v4, :cond_3

    .line 68
    .line 69
    iget-object v5, v3, Li9/t;->g:[I

    .line 70
    .line 71
    aget v5, v5, v4

    .line 72
    .line 73
    and-int/lit8 v5, v5, 0x1

    .line 74
    .line 75
    if-eqz v5, :cond_2

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_2
    add-int/lit8 v4, v4, -0x1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    move v4, v1

    .line 82
    :goto_2
    if-ne v4, v1, :cond_4

    .line 83
    .line 84
    invoke-virtual {v3, p3, p4}, Li9/t;->a(J)I

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    :cond_4
    iput v4, v2, Li9/l;->e:I

    .line 89
    .line 90
    iget-object v2, v2, Li9/l;->d:Lo8/j0;

    .line 91
    .line 92
    if-eqz v2, :cond_5

    .line 93
    .line 94
    iput-boolean v0, v2, Lo8/j0;->b:Z

    .line 95
    .line 96
    iput v0, v2, Lo8/j0;->c:I

    .line 97
    .line 98
    :cond_5
    add-int/lit8 p2, p2, 0x1

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_6
    return-void
.end method

.method public final e(J)Lo8/b0;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    iget-object v3, v0, Li9/m;->A:[Li9/l;

    .line 6
    .line 7
    array-length v4, v3

    .line 8
    sget-object v5, Lo8/d0;->c:Lo8/d0;

    .line 9
    .line 10
    if-nez v4, :cond_0

    .line 11
    .line 12
    new-instance v0, Lo8/b0;

    .line 13
    .line 14
    invoke-direct {v0, v5, v5}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 15
    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    iget v4, v0, Li9/m;->C:I

    .line 19
    .line 20
    const/4 v6, 0x0

    .line 21
    const/4 v9, -0x1

    .line 22
    const-wide/16 v10, -0x1

    .line 23
    .line 24
    if-eq v4, v9, :cond_5

    .line 25
    .line 26
    aget-object v3, v3, v4

    .line 27
    .line 28
    iget-object v3, v3, Li9/l;->b:Li9/t;

    .line 29
    .line 30
    iget-object v4, v3, Li9/t;->f:[J

    .line 31
    .line 32
    invoke-static {v4, v1, v2, v6}, Lw7/w;->d([JJZ)I

    .line 33
    .line 34
    .line 35
    move-result v12

    .line 36
    :goto_0
    if-ltz v12, :cond_2

    .line 37
    .line 38
    iget-object v13, v3, Li9/t;->g:[I

    .line 39
    .line 40
    aget v13, v13, v12

    .line 41
    .line 42
    and-int/lit8 v13, v13, 0x1

    .line 43
    .line 44
    if-eqz v13, :cond_1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    add-int/lit8 v12, v12, -0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    move v12, v9

    .line 51
    :goto_1
    if-ne v12, v9, :cond_3

    .line 52
    .line 53
    invoke-virtual {v3, v1, v2}, Li9/t;->a(J)I

    .line 54
    .line 55
    .line 56
    move-result v12

    .line 57
    :cond_3
    iget-object v13, v3, Li9/t;->c:[J

    .line 58
    .line 59
    if-ne v12, v9, :cond_4

    .line 60
    .line 61
    new-instance v0, Lo8/b0;

    .line 62
    .line 63
    invoke-direct {v0, v5, v5}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 64
    .line 65
    .line 66
    return-object v0

    .line 67
    :cond_4
    aget-wide v14, v4, v12

    .line 68
    .line 69
    aget-wide v16, v13, v12

    .line 70
    .line 71
    cmp-long v5, v14, v1

    .line 72
    .line 73
    if-gez v5, :cond_6

    .line 74
    .line 75
    iget v5, v3, Li9/t;->b:I

    .line 76
    .line 77
    add-int/lit8 v5, v5, -0x1

    .line 78
    .line 79
    if-ge v12, v5, :cond_6

    .line 80
    .line 81
    invoke-virtual {v3, v1, v2}, Li9/t;->a(J)I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-eq v1, v9, :cond_6

    .line 86
    .line 87
    if-eq v1, v12, :cond_6

    .line 88
    .line 89
    aget-wide v2, v4, v1

    .line 90
    .line 91
    aget-wide v10, v13, v1

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_5
    const-wide v16, 0x7fffffffffffffffL

    .line 95
    .line 96
    .line 97
    .line 98
    .line 99
    move-wide v14, v1

    .line 100
    :cond_6
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    :goto_2
    move v1, v6

    .line 106
    move-wide/from16 v4, v16

    .line 107
    .line 108
    :goto_3
    iget-object v12, v0, Li9/m;->A:[Li9/l;

    .line 109
    .line 110
    array-length v13, v12

    .line 111
    if-ge v1, v13, :cond_11

    .line 112
    .line 113
    iget v13, v0, Li9/m;->C:I

    .line 114
    .line 115
    if-eq v1, v13, :cond_10

    .line 116
    .line 117
    aget-object v12, v12, v1

    .line 118
    .line 119
    iget-object v12, v12, Li9/l;->b:Li9/t;

    .line 120
    .line 121
    iget-object v13, v12, Li9/t;->c:[J

    .line 122
    .line 123
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 124
    .line 125
    .line 126
    .line 127
    .line 128
    iget-object v7, v12, Li9/t;->g:[I

    .line 129
    .line 130
    iget-object v8, v12, Li9/t;->f:[J

    .line 131
    .line 132
    invoke-static {v8, v14, v15, v6}, Lw7/w;->d([JJZ)I

    .line 133
    .line 134
    .line 135
    move-result v18

    .line 136
    :goto_4
    if-ltz v18, :cond_8

    .line 137
    .line 138
    aget v19, v7, v18

    .line 139
    .line 140
    and-int/lit8 v19, v19, 0x1

    .line 141
    .line 142
    if-eqz v19, :cond_7

    .line 143
    .line 144
    move/from16 v6, v18

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_7
    add-int/lit8 v18, v18, -0x1

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_8
    move v6, v9

    .line 151
    :goto_5
    if-ne v6, v9, :cond_9

    .line 152
    .line 153
    invoke-virtual {v12, v14, v15}, Li9/t;->a(J)I

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    :cond_9
    if-ne v6, v9, :cond_a

    .line 158
    .line 159
    move-wide/from16 p1, v10

    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_a
    move-wide/from16 p1, v10

    .line 163
    .line 164
    aget-wide v9, v13, v6

    .line 165
    .line 166
    invoke-static {v9, v10, v4, v5}, Ljava/lang/Math;->min(JJ)J

    .line 167
    .line 168
    .line 169
    move-result-wide v4

    .line 170
    :goto_6
    cmp-long v6, v2, v16

    .line 171
    .line 172
    if-eqz v6, :cond_f

    .line 173
    .line 174
    const/4 v6, 0x0

    .line 175
    invoke-static {v8, v2, v3, v6}, Lw7/w;->d([JJZ)I

    .line 176
    .line 177
    .line 178
    move-result v8

    .line 179
    :goto_7
    if-ltz v8, :cond_c

    .line 180
    .line 181
    aget v9, v7, v8

    .line 182
    .line 183
    and-int/lit8 v9, v9, 0x1

    .line 184
    .line 185
    if-eqz v9, :cond_b

    .line 186
    .line 187
    :goto_8
    const/4 v7, -0x1

    .line 188
    goto :goto_9

    .line 189
    :cond_b
    add-int/lit8 v8, v8, -0x1

    .line 190
    .line 191
    goto :goto_7

    .line 192
    :cond_c
    const/4 v8, -0x1

    .line 193
    goto :goto_8

    .line 194
    :goto_9
    if-ne v8, v7, :cond_d

    .line 195
    .line 196
    invoke-virtual {v12, v2, v3}, Li9/t;->a(J)I

    .line 197
    .line 198
    .line 199
    move-result v8

    .line 200
    :cond_d
    if-ne v8, v7, :cond_e

    .line 201
    .line 202
    move-wide/from16 v10, p1

    .line 203
    .line 204
    goto :goto_a

    .line 205
    :cond_e
    aget-wide v8, v13, v8

    .line 206
    .line 207
    move-wide/from16 v10, p1

    .line 208
    .line 209
    invoke-static {v8, v9, v10, v11}, Ljava/lang/Math;->min(JJ)J

    .line 210
    .line 211
    .line 212
    move-result-wide v10

    .line 213
    goto :goto_a

    .line 214
    :cond_f
    move-wide/from16 v10, p1

    .line 215
    .line 216
    const/4 v6, 0x0

    .line 217
    const/4 v7, -0x1

    .line 218
    goto :goto_a

    .line 219
    :cond_10
    move v7, v9

    .line 220
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 221
    .line 222
    .line 223
    .line 224
    .line 225
    :goto_a
    add-int/lit8 v1, v1, 0x1

    .line 226
    .line 227
    move v9, v7

    .line 228
    goto :goto_3

    .line 229
    :cond_11
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 230
    .line 231
    .line 232
    .line 233
    .line 234
    new-instance v0, Lo8/d0;

    .line 235
    .line 236
    invoke-direct {v0, v14, v15, v4, v5}, Lo8/d0;-><init>(JJ)V

    .line 237
    .line 238
    .line 239
    cmp-long v1, v2, v16

    .line 240
    .line 241
    if-nez v1, :cond_12

    .line 242
    .line 243
    new-instance v1, Lo8/b0;

    .line 244
    .line 245
    invoke-direct {v1, v0, v0}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 246
    .line 247
    .line 248
    return-object v1

    .line 249
    :cond_12
    new-instance v1, Lo8/d0;

    .line 250
    .line 251
    invoke-direct {v1, v2, v3, v10, v11}, Lo8/d0;-><init>(JJ)V

    .line 252
    .line 253
    .line 254
    new-instance v2, Lo8/b0;

    .line 255
    .line 256
    invoke-direct {v2, v0, v1}, Lo8/b0;-><init>(Lo8/d0;Lo8/d0;)V

    .line 257
    .line 258
    .line 259
    return-object v2
.end method

.method public final g()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 37

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
    :cond_0
    iget v3, v0, Li9/m;->k:I

    .line 8
    .line 9
    iget-object v5, v0, Li9/m;->g:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    iget v6, v0, Li9/m;->b:I

    .line 12
    .line 13
    iget-object v8, v0, Li9/m;->e:Lw7/p;

    .line 14
    .line 15
    const/4 v11, 0x0

    .line 16
    const/4 v15, 0x4

    .line 17
    const-wide/16 v16, -0x1

    .line 18
    .line 19
    const/4 v9, 0x0

    .line 20
    const/4 v10, 0x2

    .line 21
    const/4 v4, 0x1

    .line 22
    if-eqz v3, :cond_45

    .line 23
    .line 24
    const-wide/32 v19, 0x40000

    .line 25
    .line 26
    .line 27
    if-eq v3, v4, :cond_36

    .line 28
    .line 29
    const-wide/16 v21, 0x8

    .line 30
    .line 31
    if-eq v3, v10, :cond_19

    .line 32
    .line 33
    const/4 v5, 0x3

    .line 34
    if-ne v3, v5, :cond_18

    .line 35
    .line 36
    iget-object v3, v0, Li9/m;->h:Li9/o;

    .line 37
    .line 38
    iget-object v6, v3, Li9/o;->a:Ljava/util/ArrayList;

    .line 39
    .line 40
    iget v8, v3, Li9/o;->b:I

    .line 41
    .line 42
    if-eqz v8, :cond_14

    .line 43
    .line 44
    if-eq v8, v4, :cond_12

    .line 45
    .line 46
    const/16 v7, 0xb01

    .line 47
    .line 48
    const/16 v24, 0x8

    .line 49
    .line 50
    const/16 v12, 0xb00

    .line 51
    .line 52
    const/16 v4, 0x890

    .line 53
    .line 54
    if-eq v8, v10, :cond_d

    .line 55
    .line 56
    if-ne v8, v5, :cond_c

    .line 57
    .line 58
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 59
    .line 60
    .line 61
    move-result-wide v16

    .line 62
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 63
    .line 64
    .line 65
    move-result-wide v18

    .line 66
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 67
    .line 68
    .line 69
    move-result-wide v20

    .line 70
    sub-long v18, v18, v20

    .line 71
    .line 72
    iget v3, v3, Li9/o;->c:I

    .line 73
    .line 74
    int-to-long v13, v3

    .line 75
    sub-long v13, v18, v13

    .line 76
    .line 77
    long-to-int v3, v13

    .line 78
    new-instance v13, Lw7/p;

    .line 79
    .line 80
    invoke-direct {v13, v3}, Lw7/p;-><init>(I)V

    .line 81
    .line 82
    .line 83
    iget-object v14, v13, Lw7/p;->a:[B

    .line 84
    .line 85
    invoke-interface {v1, v14, v9, v3}, Lo8/p;->readFully([BII)V

    .line 86
    .line 87
    .line 88
    move v1, v9

    .line 89
    :goto_0
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    if-ge v1, v3, :cond_b

    .line 94
    .line 95
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Li9/n;

    .line 100
    .line 101
    iget-wide v8, v3, Li9/n;->a:J

    .line 102
    .line 103
    sub-long v8, v8, v16

    .line 104
    .line 105
    long-to-int v8, v8

    .line 106
    invoke-virtual {v13, v8}, Lw7/p;->I(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v13, v15}, Lw7/p;->J(I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v13}, Lw7/p;->l()I

    .line 113
    .line 114
    .line 115
    move-result v8

    .line 116
    sget-object v9, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 117
    .line 118
    invoke-virtual {v13, v8, v9}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v14

    .line 122
    invoke-virtual {v14}, Ljava/lang/String;->hashCode()I

    .line 123
    .line 124
    .line 125
    move-result v19

    .line 126
    sparse-switch v19, :sswitch_data_0

    .line 127
    .line 128
    .line 129
    :goto_1
    const/4 v14, -0x1

    .line 130
    goto :goto_2

    .line 131
    :sswitch_0
    const-string v15, "Super_SlowMotion_BGM"

    .line 132
    .line 133
    invoke-virtual {v14, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v14

    .line 137
    if-nez v14, :cond_1

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_1
    const/4 v14, 0x4

    .line 141
    goto :goto_2

    .line 142
    :sswitch_1
    const-string v15, "Super_SlowMotion_Deflickering_On"

    .line 143
    .line 144
    invoke-virtual {v14, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v14

    .line 148
    if-nez v14, :cond_2

    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_2
    move v14, v5

    .line 152
    goto :goto_2

    .line 153
    :sswitch_2
    const-string v15, "Super_SlowMotion_Data"

    .line 154
    .line 155
    invoke-virtual {v14, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v14

    .line 159
    if-nez v14, :cond_3

    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_3
    move v14, v10

    .line 163
    goto :goto_2

    .line 164
    :sswitch_3
    const-string v15, "Super_SlowMotion_Edit_Data"

    .line 165
    .line 166
    invoke-virtual {v14, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v14

    .line 170
    if-nez v14, :cond_4

    .line 171
    .line 172
    goto :goto_1

    .line 173
    :cond_4
    const/4 v14, 0x1

    .line 174
    goto :goto_2

    .line 175
    :sswitch_4
    const-string v15, "SlowMotion_Data"

    .line 176
    .line 177
    invoke-virtual {v14, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v14

    .line 181
    if-nez v14, :cond_5

    .line 182
    .line 183
    goto :goto_1

    .line 184
    :cond_5
    const/4 v14, 0x0

    .line 185
    :goto_2
    packed-switch v14, :pswitch_data_0

    .line 186
    .line 187
    .line 188
    const-string v0, "Invalid SEF name"

    .line 189
    .line 190
    invoke-static {v11, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    throw v0

    .line 195
    :pswitch_0
    move v14, v7

    .line 196
    goto :goto_3

    .line 197
    :pswitch_1
    const/16 v14, 0xb04

    .line 198
    .line 199
    goto :goto_3

    .line 200
    :pswitch_2
    move v14, v12

    .line 201
    goto :goto_3

    .line 202
    :pswitch_3
    const/16 v14, 0xb03

    .line 203
    .line 204
    goto :goto_3

    .line 205
    :pswitch_4
    move v14, v4

    .line 206
    :goto_3
    iget v3, v3, Li9/n;->b:I

    .line 207
    .line 208
    add-int/lit8 v8, v8, 0x8

    .line 209
    .line 210
    sub-int/2addr v3, v8

    .line 211
    if-eq v14, v4, :cond_7

    .line 212
    .line 213
    if-eq v14, v12, :cond_a

    .line 214
    .line 215
    if-eq v14, v7, :cond_a

    .line 216
    .line 217
    const/16 v3, 0xb03

    .line 218
    .line 219
    if-eq v14, v3, :cond_a

    .line 220
    .line 221
    const/16 v8, 0xb04

    .line 222
    .line 223
    if-ne v14, v8, :cond_6

    .line 224
    .line 225
    goto/16 :goto_5

    .line 226
    .line 227
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 228
    .line 229
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 230
    .line 231
    .line 232
    throw v0

    .line 233
    :cond_7
    new-instance v15, Ljava/util/ArrayList;

    .line 234
    .line 235
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v13, v3, v9}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object v3

    .line 242
    sget-object v9, Li9/o;->e:Lbb/g0;

    .line 243
    .line 244
    invoke-virtual {v9, v3}, Lbb/g0;->t(Ljava/lang/CharSequence;)Ljava/util/List;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    const/4 v9, 0x0

    .line 249
    :goto_4
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 250
    .line 251
    .line 252
    move-result v14

    .line 253
    if-ge v9, v14, :cond_9

    .line 254
    .line 255
    sget-object v14, Li9/o;->d:Lbb/g0;

    .line 256
    .line 257
    invoke-interface {v3, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v18

    .line 261
    move-object/from16 v8, v18

    .line 262
    .line 263
    check-cast v8, Ljava/lang/CharSequence;

    .line 264
    .line 265
    invoke-virtual {v14, v8}, Lbb/g0;->t(Ljava/lang/CharSequence;)Ljava/util/List;

    .line 266
    .line 267
    .line 268
    move-result-object v8

    .line 269
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 270
    .line 271
    .line 272
    move-result v14

    .line 273
    if-ne v14, v5, :cond_8

    .line 274
    .line 275
    const/4 v14, 0x0

    .line 276
    :try_start_0
    invoke-interface {v8, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v18

    .line 280
    check-cast v18, Ljava/lang/String;

    .line 281
    .line 282
    invoke-static/range {v18 .. v18}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 283
    .line 284
    .line 285
    move-result-wide v30

    .line 286
    const/4 v14, 0x1

    .line 287
    invoke-interface {v8, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v21

    .line 291
    check-cast v21, Ljava/lang/String;

    .line 292
    .line 293
    invoke-static/range {v21 .. v21}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 294
    .line 295
    .line 296
    move-result-wide v32

    .line 297
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v8

    .line 301
    check-cast v8, Ljava/lang/String;

    .line 302
    .line 303
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 304
    .line 305
    .line 306
    move-result v8

    .line 307
    const/16 v27, 0x1

    .line 308
    .line 309
    add-int/lit8 v8, v8, -0x1

    .line 310
    .line 311
    shl-int v29, v27, v8

    .line 312
    .line 313
    new-instance v28, Ld9/b;

    .line 314
    .line 315
    invoke-direct/range {v28 .. v33}, Ld9/b;-><init>(IJJ)V

    .line 316
    .line 317
    .line 318
    move-object/from16 v8, v28

    .line 319
    .line 320
    invoke-virtual {v15, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 321
    .line 322
    .line 323
    add-int/lit8 v9, v9, 0x1

    .line 324
    .line 325
    goto :goto_4

    .line 326
    :catch_0
    move-exception v0

    .line 327
    invoke-static {v0, v11}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    throw v0

    .line 332
    :cond_8
    invoke-static {v11, v11}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 333
    .line 334
    .line 335
    move-result-object v0

    .line 336
    throw v0

    .line 337
    :cond_9
    new-instance v3, Ld9/c;

    .line 338
    .line 339
    invoke-direct {v3, v15}, Ld9/c;-><init>(Ljava/util/ArrayList;)V

    .line 340
    .line 341
    .line 342
    iget-object v8, v0, Li9/m;->i:Ljava/util/ArrayList;

    .line 343
    .line 344
    invoke-virtual {v8, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    :cond_a
    :goto_5
    add-int/lit8 v1, v1, 0x1

    .line 348
    .line 349
    const/4 v9, 0x0

    .line 350
    const/4 v15, 0x4

    .line 351
    goto/16 :goto_0

    .line 352
    .line 353
    :cond_b
    const-wide/16 v8, 0x0

    .line 354
    .line 355
    iput-wide v8, v2, Lo8/s;->a:J

    .line 356
    .line 357
    :goto_6
    const/4 v1, 0x1

    .line 358
    goto/16 :goto_b

    .line 359
    .line 360
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 361
    .line 362
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 363
    .line 364
    .line 365
    throw v0

    .line 366
    :cond_d
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 367
    .line 368
    .line 369
    move-result-wide v8

    .line 370
    iget v11, v3, Li9/o;->c:I

    .line 371
    .line 372
    add-int/lit8 v11, v11, -0x14

    .line 373
    .line 374
    new-instance v13, Lw7/p;

    .line 375
    .line 376
    invoke-direct {v13, v11}, Lw7/p;-><init>(I)V

    .line 377
    .line 378
    .line 379
    iget-object v14, v13, Lw7/p;->a:[B

    .line 380
    .line 381
    const/4 v15, 0x0

    .line 382
    invoke-interface {v1, v14, v15, v11}, Lo8/p;->readFully([BII)V

    .line 383
    .line 384
    .line 385
    const/4 v1, 0x0

    .line 386
    :goto_7
    div-int/lit8 v15, v11, 0xc

    .line 387
    .line 388
    if-ge v1, v15, :cond_10

    .line 389
    .line 390
    invoke-virtual {v13, v10}, Lw7/p;->J(I)V

    .line 391
    .line 392
    .line 393
    iget-object v15, v13, Lw7/p;->a:[B

    .line 394
    .line 395
    iget v14, v13, Lw7/p;->b:I

    .line 396
    .line 397
    move/from16 v28, v10

    .line 398
    .line 399
    add-int/lit8 v10, v14, 0x1

    .line 400
    .line 401
    iput v10, v13, Lw7/p;->b:I

    .line 402
    .line 403
    aget-byte v5, v15, v14

    .line 404
    .line 405
    and-int/lit16 v5, v5, 0xff

    .line 406
    .line 407
    add-int/lit8 v14, v14, 0x2

    .line 408
    .line 409
    iput v14, v13, Lw7/p;->b:I

    .line 410
    .line 411
    aget-byte v10, v15, v10

    .line 412
    .line 413
    and-int/lit16 v10, v10, 0xff

    .line 414
    .line 415
    shl-int/lit8 v10, v10, 0x8

    .line 416
    .line 417
    or-int/2addr v5, v10

    .line 418
    int-to-short v5, v5

    .line 419
    if-eq v5, v4, :cond_e

    .line 420
    .line 421
    if-eq v5, v12, :cond_e

    .line 422
    .line 423
    if-eq v5, v7, :cond_e

    .line 424
    .line 425
    const/16 v10, 0xb03

    .line 426
    .line 427
    const/16 v14, 0xb04

    .line 428
    .line 429
    if-eq v5, v10, :cond_f

    .line 430
    .line 431
    if-eq v5, v14, :cond_f

    .line 432
    .line 433
    move/from16 v5, v24

    .line 434
    .line 435
    invoke-virtual {v13, v5}, Lw7/p;->J(I)V

    .line 436
    .line 437
    .line 438
    move/from16 v17, v11

    .line 439
    .line 440
    goto :goto_8

    .line 441
    :cond_e
    const/16 v10, 0xb03

    .line 442
    .line 443
    const/16 v14, 0xb04

    .line 444
    .line 445
    :cond_f
    iget v5, v3, Li9/o;->c:I

    .line 446
    .line 447
    int-to-long v4, v5

    .line 448
    sub-long v4, v8, v4

    .line 449
    .line 450
    invoke-virtual {v13}, Lw7/p;->l()I

    .line 451
    .line 452
    .line 453
    move-result v7

    .line 454
    move/from16 v17, v11

    .line 455
    .line 456
    int-to-long v10, v7

    .line 457
    sub-long/2addr v4, v10

    .line 458
    invoke-virtual {v13}, Lw7/p;->l()I

    .line 459
    .line 460
    .line 461
    move-result v7

    .line 462
    new-instance v10, Li9/n;

    .line 463
    .line 464
    invoke-direct {v10, v4, v5, v7}, Li9/n;-><init>(JI)V

    .line 465
    .line 466
    .line 467
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    :goto_8
    add-int/lit8 v1, v1, 0x1

    .line 471
    .line 472
    move/from16 v11, v17

    .line 473
    .line 474
    move/from16 v10, v28

    .line 475
    .line 476
    const/16 v4, 0x890

    .line 477
    .line 478
    const/4 v5, 0x3

    .line 479
    const/16 v7, 0xb01

    .line 480
    .line 481
    const/16 v24, 0x8

    .line 482
    .line 483
    goto :goto_7

    .line 484
    :cond_10
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    .line 485
    .line 486
    .line 487
    move-result v1

    .line 488
    if-eqz v1, :cond_11

    .line 489
    .line 490
    const-wide/16 v8, 0x0

    .line 491
    .line 492
    iput-wide v8, v2, Lo8/s;->a:J

    .line 493
    .line 494
    const/4 v14, 0x0

    .line 495
    goto/16 :goto_6

    .line 496
    .line 497
    :cond_11
    const/4 v1, 0x3

    .line 498
    iput v1, v3, Li9/o;->b:I

    .line 499
    .line 500
    const/4 v14, 0x0

    .line 501
    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    check-cast v1, Li9/n;

    .line 506
    .line 507
    iget-wide v3, v1, Li9/n;->a:J

    .line 508
    .line 509
    iput-wide v3, v2, Lo8/s;->a:J

    .line 510
    .line 511
    goto/16 :goto_6

    .line 512
    .line 513
    :cond_12
    move v14, v9

    .line 514
    move/from16 v28, v10

    .line 515
    .line 516
    new-instance v4, Lw7/p;

    .line 517
    .line 518
    const/16 v5, 0x8

    .line 519
    .line 520
    invoke-direct {v4, v5}, Lw7/p;-><init>(I)V

    .line 521
    .line 522
    .line 523
    iget-object v6, v4, Lw7/p;->a:[B

    .line 524
    .line 525
    invoke-interface {v1, v6, v14, v5}, Lo8/p;->readFully([BII)V

    .line 526
    .line 527
    .line 528
    invoke-virtual {v4}, Lw7/p;->l()I

    .line 529
    .line 530
    .line 531
    move-result v6

    .line 532
    add-int/2addr v6, v5

    .line 533
    iput v6, v3, Li9/o;->c:I

    .line 534
    .line 535
    invoke-virtual {v4}, Lw7/p;->j()I

    .line 536
    .line 537
    .line 538
    move-result v4

    .line 539
    const v5, 0x53454654

    .line 540
    .line 541
    .line 542
    if-eq v4, v5, :cond_13

    .line 543
    .line 544
    const-wide/16 v8, 0x0

    .line 545
    .line 546
    iput-wide v8, v2, Lo8/s;->a:J

    .line 547
    .line 548
    goto/16 :goto_6

    .line 549
    .line 550
    :cond_13
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 551
    .line 552
    .line 553
    move-result-wide v4

    .line 554
    iget v1, v3, Li9/o;->c:I

    .line 555
    .line 556
    add-int/lit8 v1, v1, -0xc

    .line 557
    .line 558
    int-to-long v6, v1

    .line 559
    sub-long/2addr v4, v6

    .line 560
    iput-wide v4, v2, Lo8/s;->a:J

    .line 561
    .line 562
    move/from16 v1, v28

    .line 563
    .line 564
    iput v1, v3, Li9/o;->b:I

    .line 565
    .line 566
    goto/16 :goto_6

    .line 567
    .line 568
    :cond_14
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 569
    .line 570
    .line 571
    move-result-wide v4

    .line 572
    cmp-long v1, v4, v16

    .line 573
    .line 574
    if-eqz v1, :cond_16

    .line 575
    .line 576
    cmp-long v1, v4, v21

    .line 577
    .line 578
    if-gez v1, :cond_15

    .line 579
    .line 580
    goto :goto_9

    .line 581
    :cond_15
    sub-long v4, v4, v21

    .line 582
    .line 583
    goto :goto_a

    .line 584
    :cond_16
    :goto_9
    const-wide/16 v4, 0x0

    .line 585
    .line 586
    :goto_a
    iput-wide v4, v2, Lo8/s;->a:J

    .line 587
    .line 588
    const/4 v1, 0x1

    .line 589
    iput v1, v3, Li9/o;->b:I

    .line 590
    .line 591
    :goto_b
    iget-wide v2, v2, Lo8/s;->a:J

    .line 592
    .line 593
    const-wide/16 v25, 0x0

    .line 594
    .line 595
    cmp-long v2, v2, v25

    .line 596
    .line 597
    if-nez v2, :cond_17

    .line 598
    .line 599
    const/4 v14, 0x0

    .line 600
    iput v14, v0, Li9/m;->k:I

    .line 601
    .line 602
    iput v14, v0, Li9/m;->n:I

    .line 603
    .line 604
    return v1

    .line 605
    :cond_17
    move v4, v1

    .line 606
    goto/16 :goto_20

    .line 607
    .line 608
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 609
    .line 610
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 611
    .line 612
    .line 613
    throw v0

    .line 614
    :cond_19
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 615
    .line 616
    .line 617
    move-result-wide v3

    .line 618
    iget v5, v0, Li9/m;->p:I

    .line 619
    .line 620
    const/4 v7, -0x1

    .line 621
    if-ne v5, v7, :cond_24

    .line 622
    .line 623
    const/4 v5, 0x0

    .line 624
    const/4 v7, -0x1

    .line 625
    const/4 v12, -0x1

    .line 626
    const/4 v13, 0x1

    .line 627
    const/4 v15, 0x1

    .line 628
    const-wide v16, 0x7fffffffffffffffL

    .line 629
    .line 630
    .line 631
    .line 632
    .line 633
    const-wide v29, 0x7fffffffffffffffL

    .line 634
    .line 635
    .line 636
    .line 637
    .line 638
    const-wide v31, 0x7fffffffffffffffL

    .line 639
    .line 640
    .line 641
    .line 642
    .line 643
    const-wide v33, 0x7fffffffffffffffL

    .line 644
    .line 645
    .line 646
    .line 647
    .line 648
    :goto_c
    iget-object v9, v0, Li9/m;->A:[Li9/l;

    .line 649
    .line 650
    array-length v10, v9

    .line 651
    if-ge v5, v10, :cond_21

    .line 652
    .line 653
    aget-object v9, v9, v5

    .line 654
    .line 655
    iget v10, v9, Li9/l;->e:I

    .line 656
    .line 657
    iget-object v9, v9, Li9/l;->b:Li9/t;

    .line 658
    .line 659
    iget v14, v9, Li9/t;->b:I

    .line 660
    .line 661
    if-ne v10, v14, :cond_1a

    .line 662
    .line 663
    goto :goto_f

    .line 664
    :cond_1a
    iget-object v9, v9, Li9/t;->c:[J

    .line 665
    .line 666
    aget-wide v35, v9, v10

    .line 667
    .line 668
    iget-object v9, v0, Li9/m;->B:[[J

    .line 669
    .line 670
    sget-object v14, Lw7/w;->a:Ljava/lang/String;

    .line 671
    .line 672
    aget-object v9, v9, v5

    .line 673
    .line 674
    aget-wide v9, v9, v10

    .line 675
    .line 676
    sub-long v35, v35, v3

    .line 677
    .line 678
    const-wide/16 v25, 0x0

    .line 679
    .line 680
    cmp-long v14, v35, v25

    .line 681
    .line 682
    if-ltz v14, :cond_1c

    .line 683
    .line 684
    cmp-long v14, v35, v19

    .line 685
    .line 686
    if-ltz v14, :cond_1b

    .line 687
    .line 688
    goto :goto_d

    .line 689
    :cond_1b
    const/4 v14, 0x0

    .line 690
    goto :goto_e

    .line 691
    :cond_1c
    :goto_d
    const/4 v14, 0x1

    .line 692
    :goto_e
    if-nez v14, :cond_1d

    .line 693
    .line 694
    if-nez v15, :cond_1e

    .line 695
    .line 696
    :cond_1d
    if-ne v14, v15, :cond_1f

    .line 697
    .line 698
    cmp-long v24, v35, v31

    .line 699
    .line 700
    if-gez v24, :cond_1f

    .line 701
    .line 702
    :cond_1e
    move v12, v5

    .line 703
    move-wide/from16 v29, v9

    .line 704
    .line 705
    move v15, v14

    .line 706
    move-wide/from16 v31, v35

    .line 707
    .line 708
    :cond_1f
    cmp-long v24, v9, v16

    .line 709
    .line 710
    if-gez v24, :cond_20

    .line 711
    .line 712
    move v7, v5

    .line 713
    move-wide/from16 v16, v9

    .line 714
    .line 715
    move v13, v14

    .line 716
    :cond_20
    :goto_f
    add-int/lit8 v5, v5, 0x1

    .line 717
    .line 718
    goto :goto_c

    .line 719
    :cond_21
    cmp-long v5, v16, v33

    .line 720
    .line 721
    if-eqz v5, :cond_22

    .line 722
    .line 723
    if-eqz v13, :cond_22

    .line 724
    .line 725
    const-wide/32 v9, 0xa00000

    .line 726
    .line 727
    .line 728
    add-long v16, v16, v9

    .line 729
    .line 730
    cmp-long v5, v29, v16

    .line 731
    .line 732
    if-gez v5, :cond_23

    .line 733
    .line 734
    :cond_22
    move v7, v12

    .line 735
    :cond_23
    iput v7, v0, Li9/m;->p:I

    .line 736
    .line 737
    const/4 v5, -0x1

    .line 738
    if-ne v7, v5, :cond_24

    .line 739
    .line 740
    move/from16 v23, v5

    .line 741
    .line 742
    goto/16 :goto_29

    .line 743
    .line 744
    :cond_24
    iget-object v5, v0, Li9/m;->A:[Li9/l;

    .line 745
    .line 746
    iget v7, v0, Li9/m;->p:I

    .line 747
    .line 748
    aget-object v5, v5, v7

    .line 749
    .line 750
    iget-object v7, v5, Li9/l;->c:Lo8/i0;

    .line 751
    .line 752
    iget-object v9, v5, Li9/l;->b:Li9/t;

    .line 753
    .line 754
    iget-object v10, v5, Li9/l;->a:Li9/q;

    .line 755
    .line 756
    iget v12, v5, Li9/l;->e:I

    .line 757
    .line 758
    iget-object v13, v9, Li9/t;->c:[J

    .line 759
    .line 760
    iget-object v15, v9, Li9/t;->d:[I

    .line 761
    .line 762
    aget-wide v13, v13, v12

    .line 763
    .line 764
    move/from16 v16, v12

    .line 765
    .line 766
    iget-wide v11, v0, Li9/m;->y:J

    .line 767
    .line 768
    add-long/2addr v13, v11

    .line 769
    aget v11, v15, v16

    .line 770
    .line 771
    iget-object v12, v5, Li9/l;->d:Lo8/j0;

    .line 772
    .line 773
    sub-long v3, v13, v3

    .line 774
    .line 775
    move-wide/from16 v29, v3

    .line 776
    .line 777
    iget v3, v0, Li9/m;->q:I

    .line 778
    .line 779
    int-to-long v3, v3

    .line 780
    add-long v3, v29, v3

    .line 781
    .line 782
    const-wide/16 v25, 0x0

    .line 783
    .line 784
    cmp-long v17, v3, v25

    .line 785
    .line 786
    if-ltz v17, :cond_25

    .line 787
    .line 788
    cmp-long v17, v3, v19

    .line 789
    .line 790
    if-ltz v17, :cond_26

    .line 791
    .line 792
    :cond_25
    const/16 v27, 0x1

    .line 793
    .line 794
    goto/16 :goto_19

    .line 795
    .line 796
    :cond_26
    iget v2, v10, Li9/q;->h:I

    .line 797
    .line 798
    iget v13, v10, Li9/q;->k:I

    .line 799
    .line 800
    iget-object v10, v10, Li9/q;->g:Lt7/o;

    .line 801
    .line 802
    const/4 v14, 0x1

    .line 803
    if-ne v2, v14, :cond_27

    .line 804
    .line 805
    add-long v3, v3, v21

    .line 806
    .line 807
    add-int/lit8 v11, v11, -0x8

    .line 808
    .line 809
    :cond_27
    long-to-int v2, v3

    .line 810
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 811
    .line 812
    .line 813
    iget-object v2, v10, Lt7/o;->n:Ljava/lang/String;

    .line 814
    .line 815
    iget-object v3, v10, Lt7/o;->n:Ljava/lang/String;

    .line 816
    .line 817
    const-string v4, "video/avc"

    .line 818
    .line 819
    invoke-static {v2, v4}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 820
    .line 821
    .line 822
    move-result v2

    .line 823
    if-eqz v2, :cond_29

    .line 824
    .line 825
    and-int/lit8 v2, v6, 0x20

    .line 826
    .line 827
    if-eqz v2, :cond_28

    .line 828
    .line 829
    goto :goto_10

    .line 830
    :cond_28
    const/4 v14, 0x1

    .line 831
    goto :goto_11

    .line 832
    :cond_29
    const-string v2, "video/hevc"

    .line 833
    .line 834
    invoke-static {v3, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 835
    .line 836
    .line 837
    move-result v2

    .line 838
    if-eqz v2, :cond_28

    .line 839
    .line 840
    and-int/lit16 v2, v6, 0x80

    .line 841
    .line 842
    if-eqz v2, :cond_28

    .line 843
    .line 844
    :goto_10
    const/4 v14, 0x1

    .line 845
    goto :goto_12

    .line 846
    :goto_11
    iput-boolean v14, v0, Li9/m;->t:Z

    .line 847
    .line 848
    :goto_12
    if-eqz v13, :cond_2f

    .line 849
    .line 850
    iget-object v2, v0, Li9/m;->d:Lw7/p;

    .line 851
    .line 852
    iget-object v3, v2, Lw7/p;->a:[B

    .line 853
    .line 854
    const/16 v18, 0x0

    .line 855
    .line 856
    aput-byte v18, v3, v18

    .line 857
    .line 858
    aput-byte v18, v3, v14

    .line 859
    .line 860
    const/16 v28, 0x2

    .line 861
    .line 862
    aput-byte v18, v3, v28

    .line 863
    .line 864
    rsub-int/lit8 v4, v13, 0x4

    .line 865
    .line 866
    add-int/2addr v11, v4

    .line 867
    :goto_13
    iget v6, v0, Li9/m;->r:I

    .line 868
    .line 869
    if-ge v6, v11, :cond_2e

    .line 870
    .line 871
    iget v6, v0, Li9/m;->s:I

    .line 872
    .line 873
    if-nez v6, :cond_2d

    .line 874
    .line 875
    iget-boolean v6, v0, Li9/m;->t:Z

    .line 876
    .line 877
    if-nez v6, :cond_2a

    .line 878
    .line 879
    invoke-static {v10}, Lx7/n;->d(Lt7/o;)I

    .line 880
    .line 881
    .line 882
    move-result v6

    .line 883
    add-int/2addr v6, v13

    .line 884
    aget v8, v15, v16

    .line 885
    .line 886
    iget v14, v0, Li9/m;->q:I

    .line 887
    .line 888
    sub-int/2addr v8, v14

    .line 889
    if-gt v6, v8, :cond_2a

    .line 890
    .line 891
    invoke-static {v10}, Lx7/n;->d(Lt7/o;)I

    .line 892
    .line 893
    .line 894
    move-result v14

    .line 895
    add-int v6, v13, v14

    .line 896
    .line 897
    move v8, v14

    .line 898
    goto :goto_14

    .line 899
    :cond_2a
    move v6, v13

    .line 900
    const/4 v8, 0x0

    .line 901
    :goto_14
    invoke-interface {v1, v3, v4, v6}, Lo8/p;->readFully([BII)V

    .line 902
    .line 903
    .line 904
    iget v14, v0, Li9/m;->q:I

    .line 905
    .line 906
    add-int/2addr v14, v6

    .line 907
    iput v14, v0, Li9/m;->q:I

    .line 908
    .line 909
    const/4 v14, 0x0

    .line 910
    invoke-virtual {v2, v14}, Lw7/p;->I(I)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 914
    .line 915
    .line 916
    move-result v6

    .line 917
    if-ltz v6, :cond_2c

    .line 918
    .line 919
    sub-int/2addr v6, v8

    .line 920
    iput v6, v0, Li9/m;->s:I

    .line 921
    .line 922
    iget-object v6, v0, Li9/m;->c:Lw7/p;

    .line 923
    .line 924
    invoke-virtual {v6, v14}, Lw7/p;->I(I)V

    .line 925
    .line 926
    .line 927
    move/from16 p2, v4

    .line 928
    .line 929
    const/4 v4, 0x4

    .line 930
    invoke-interface {v7, v6, v4, v14}, Lo8/i0;->a(Lw7/p;II)V

    .line 931
    .line 932
    .line 933
    iget v6, v0, Li9/m;->r:I

    .line 934
    .line 935
    add-int/2addr v6, v4

    .line 936
    iput v6, v0, Li9/m;->r:I

    .line 937
    .line 938
    if-lez v8, :cond_2b

    .line 939
    .line 940
    invoke-interface {v7, v2, v8, v14}, Lo8/i0;->a(Lw7/p;II)V

    .line 941
    .line 942
    .line 943
    iget v4, v0, Li9/m;->r:I

    .line 944
    .line 945
    add-int/2addr v4, v8

    .line 946
    iput v4, v0, Li9/m;->r:I

    .line 947
    .line 948
    invoke-static {v3, v8, v10}, Lx7/n;->c([BILt7/o;)Z

    .line 949
    .line 950
    .line 951
    move-result v4

    .line 952
    if-eqz v4, :cond_2b

    .line 953
    .line 954
    const/4 v4, 0x1

    .line 955
    iput-boolean v4, v0, Li9/m;->t:Z

    .line 956
    .line 957
    :cond_2b
    :goto_15
    move/from16 v4, p2

    .line 958
    .line 959
    goto :goto_13

    .line 960
    :cond_2c
    const-string v0, "Invalid NAL length"

    .line 961
    .line 962
    const/4 v1, 0x0

    .line 963
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 964
    .line 965
    .line 966
    move-result-object v0

    .line 967
    throw v0

    .line 968
    :cond_2d
    move/from16 p2, v4

    .line 969
    .line 970
    const/4 v14, 0x0

    .line 971
    invoke-interface {v7, v1, v6, v14}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 972
    .line 973
    .line 974
    move-result v4

    .line 975
    iget v6, v0, Li9/m;->q:I

    .line 976
    .line 977
    add-int/2addr v6, v4

    .line 978
    iput v6, v0, Li9/m;->q:I

    .line 979
    .line 980
    iget v6, v0, Li9/m;->r:I

    .line 981
    .line 982
    add-int/2addr v6, v4

    .line 983
    iput v6, v0, Li9/m;->r:I

    .line 984
    .line 985
    iget v6, v0, Li9/m;->s:I

    .line 986
    .line 987
    sub-int/2addr v6, v4

    .line 988
    iput v6, v0, Li9/m;->s:I

    .line 989
    .line 990
    goto :goto_15

    .line 991
    :cond_2e
    move/from16 v33, v11

    .line 992
    .line 993
    goto :goto_17

    .line 994
    :cond_2f
    const-string v2, "audio/ac4"

    .line 995
    .line 996
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 997
    .line 998
    .line 999
    move-result v2

    .line 1000
    if-eqz v2, :cond_31

    .line 1001
    .line 1002
    iget v2, v0, Li9/m;->r:I

    .line 1003
    .line 1004
    if-nez v2, :cond_30

    .line 1005
    .line 1006
    invoke-static {v11, v8}, Lo8/b;->g(ILw7/p;)V

    .line 1007
    .line 1008
    .line 1009
    const/4 v2, 0x7

    .line 1010
    const/4 v14, 0x0

    .line 1011
    invoke-interface {v7, v8, v2, v14}, Lo8/i0;->a(Lw7/p;II)V

    .line 1012
    .line 1013
    .line 1014
    iget v3, v0, Li9/m;->r:I

    .line 1015
    .line 1016
    add-int/2addr v3, v2

    .line 1017
    iput v3, v0, Li9/m;->r:I

    .line 1018
    .line 1019
    :cond_30
    add-int/lit8 v11, v11, 0x7

    .line 1020
    .line 1021
    goto :goto_16

    .line 1022
    :cond_31
    if-eqz v12, :cond_32

    .line 1023
    .line 1024
    invoke-virtual {v12, v1}, Lo8/j0;->c(Lo8/p;)V

    .line 1025
    .line 1026
    .line 1027
    :cond_32
    :goto_16
    iget v2, v0, Li9/m;->r:I

    .line 1028
    .line 1029
    if-ge v2, v11, :cond_2e

    .line 1030
    .line 1031
    sub-int v2, v11, v2

    .line 1032
    .line 1033
    const/4 v14, 0x0

    .line 1034
    invoke-interface {v7, v1, v2, v14}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 1035
    .line 1036
    .line 1037
    move-result v2

    .line 1038
    iget v3, v0, Li9/m;->q:I

    .line 1039
    .line 1040
    add-int/2addr v3, v2

    .line 1041
    iput v3, v0, Li9/m;->q:I

    .line 1042
    .line 1043
    iget v3, v0, Li9/m;->r:I

    .line 1044
    .line 1045
    add-int/2addr v3, v2

    .line 1046
    iput v3, v0, Li9/m;->r:I

    .line 1047
    .line 1048
    iget v3, v0, Li9/m;->s:I

    .line 1049
    .line 1050
    sub-int/2addr v3, v2

    .line 1051
    iput v3, v0, Li9/m;->s:I

    .line 1052
    .line 1053
    goto :goto_16

    .line 1054
    :goto_17
    iget-object v1, v9, Li9/t;->f:[J

    .line 1055
    .line 1056
    aget-wide v30, v1, v16

    .line 1057
    .line 1058
    iget-object v1, v9, Li9/t;->g:[I

    .line 1059
    .line 1060
    aget v1, v1, v16

    .line 1061
    .line 1062
    iget-boolean v2, v0, Li9/m;->t:Z

    .line 1063
    .line 1064
    if-nez v2, :cond_33

    .line 1065
    .line 1066
    const/high16 v2, 0x4000000

    .line 1067
    .line 1068
    or-int/2addr v1, v2

    .line 1069
    :cond_33
    move/from16 v32, v1

    .line 1070
    .line 1071
    if-eqz v12, :cond_34

    .line 1072
    .line 1073
    const/16 v35, 0x0

    .line 1074
    .line 1075
    const/16 v36, 0x0

    .line 1076
    .line 1077
    move-object/from16 v29, v12

    .line 1078
    .line 1079
    move/from16 v34, v33

    .line 1080
    .line 1081
    move/from16 v33, v32

    .line 1082
    .line 1083
    move-wide/from16 v31, v30

    .line 1084
    .line 1085
    move-object/from16 v30, v7

    .line 1086
    .line 1087
    invoke-virtual/range {v29 .. v36}, Lo8/j0;->b(Lo8/i0;JIIILo8/h0;)V

    .line 1088
    .line 1089
    .line 1090
    move-object/from16 v2, v29

    .line 1091
    .line 1092
    move-object/from16 v1, v30

    .line 1093
    .line 1094
    const/16 v27, 0x1

    .line 1095
    .line 1096
    add-int/lit8 v12, v16, 0x1

    .line 1097
    .line 1098
    iget v3, v9, Li9/t;->b:I

    .line 1099
    .line 1100
    if-ne v12, v3, :cond_35

    .line 1101
    .line 1102
    const/4 v3, 0x0

    .line 1103
    invoke-virtual {v2, v1, v3}, Lo8/j0;->a(Lo8/i0;Lo8/h0;)V

    .line 1104
    .line 1105
    .line 1106
    goto :goto_18

    .line 1107
    :cond_34
    move-object v1, v7

    .line 1108
    const/16 v27, 0x1

    .line 1109
    .line 1110
    const/16 v34, 0x0

    .line 1111
    .line 1112
    const/16 v35, 0x0

    .line 1113
    .line 1114
    move-object/from16 v29, v1

    .line 1115
    .line 1116
    invoke-interface/range {v29 .. v35}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 1117
    .line 1118
    .line 1119
    :cond_35
    :goto_18
    iget v1, v5, Li9/l;->e:I

    .line 1120
    .line 1121
    add-int/lit8 v1, v1, 0x1

    .line 1122
    .line 1123
    iput v1, v5, Li9/l;->e:I

    .line 1124
    .line 1125
    const/4 v5, -0x1

    .line 1126
    iput v5, v0, Li9/m;->p:I

    .line 1127
    .line 1128
    const/4 v14, 0x0

    .line 1129
    iput v14, v0, Li9/m;->q:I

    .line 1130
    .line 1131
    iput v14, v0, Li9/m;->r:I

    .line 1132
    .line 1133
    iput v14, v0, Li9/m;->s:I

    .line 1134
    .line 1135
    iput-boolean v14, v0, Li9/m;->t:Z

    .line 1136
    .line 1137
    return v14

    .line 1138
    :goto_19
    iput-wide v13, v2, Lo8/s;->a:J

    .line 1139
    .line 1140
    return v27

    .line 1141
    :cond_36
    iget-wide v3, v0, Li9/m;->m:J

    .line 1142
    .line 1143
    iget v6, v0, Li9/m;->n:I

    .line 1144
    .line 1145
    int-to-long v6, v6

    .line 1146
    sub-long/2addr v3, v6

    .line 1147
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1148
    .line 1149
    .line 1150
    move-result-wide v6

    .line 1151
    add-long/2addr v6, v3

    .line 1152
    iget-object v8, v0, Li9/m;->o:Lw7/p;

    .line 1153
    .line 1154
    if-eqz v8, :cond_3f

    .line 1155
    .line 1156
    iget-object v9, v8, Lw7/p;->a:[B

    .line 1157
    .line 1158
    iget v10, v0, Li9/m;->n:I

    .line 1159
    .line 1160
    long-to-int v3, v3

    .line 1161
    invoke-interface {v1, v9, v10, v3}, Lo8/p;->readFully([BII)V

    .line 1162
    .line 1163
    .line 1164
    iget v3, v0, Li9/m;->l:I

    .line 1165
    .line 1166
    const v4, 0x66747970

    .line 1167
    .line 1168
    .line 1169
    if-ne v3, v4, :cond_3e

    .line 1170
    .line 1171
    const/4 v4, 0x1

    .line 1172
    iput-boolean v4, v0, Li9/m;->u:Z

    .line 1173
    .line 1174
    const/16 v5, 0x8

    .line 1175
    .line 1176
    invoke-virtual {v8, v5}, Lw7/p;->I(I)V

    .line 1177
    .line 1178
    .line 1179
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 1180
    .line 1181
    .line 1182
    move-result v3

    .line 1183
    const v4, 0x71742020

    .line 1184
    .line 1185
    .line 1186
    const v5, 0x68656963

    .line 1187
    .line 1188
    .line 1189
    if-eq v3, v5, :cond_38

    .line 1190
    .line 1191
    if-eq v3, v4, :cond_37

    .line 1192
    .line 1193
    const/4 v3, 0x0

    .line 1194
    goto :goto_1a

    .line 1195
    :cond_37
    const/4 v3, 0x1

    .line 1196
    goto :goto_1a

    .line 1197
    :cond_38
    const/4 v3, 0x2

    .line 1198
    :goto_1a
    if-eqz v3, :cond_39

    .line 1199
    .line 1200
    goto :goto_1c

    .line 1201
    :cond_39
    const/4 v3, 0x4

    .line 1202
    invoke-virtual {v8, v3}, Lw7/p;->J(I)V

    .line 1203
    .line 1204
    .line 1205
    :cond_3a
    invoke-virtual {v8}, Lw7/p;->a()I

    .line 1206
    .line 1207
    .line 1208
    move-result v3

    .line 1209
    if-lez v3, :cond_3d

    .line 1210
    .line 1211
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 1212
    .line 1213
    .line 1214
    move-result v3

    .line 1215
    if-eq v3, v5, :cond_3c

    .line 1216
    .line 1217
    if-eq v3, v4, :cond_3b

    .line 1218
    .line 1219
    const/4 v3, 0x0

    .line 1220
    goto :goto_1b

    .line 1221
    :cond_3b
    const/4 v3, 0x1

    .line 1222
    goto :goto_1b

    .line 1223
    :cond_3c
    const/4 v3, 0x2

    .line 1224
    :goto_1b
    if-eqz v3, :cond_3a

    .line 1225
    .line 1226
    goto :goto_1c

    .line 1227
    :cond_3d
    const/4 v3, 0x0

    .line 1228
    :goto_1c
    iput v3, v0, Li9/m;->E:I

    .line 1229
    .line 1230
    goto :goto_1d

    .line 1231
    :cond_3e
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 1232
    .line 1233
    .line 1234
    move-result v3

    .line 1235
    if-nez v3, :cond_41

    .line 1236
    .line 1237
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 1238
    .line 1239
    .line 1240
    move-result-object v3

    .line 1241
    check-cast v3, Lx7/c;

    .line 1242
    .line 1243
    new-instance v4, Lx7/d;

    .line 1244
    .line 1245
    iget v5, v0, Li9/m;->l:I

    .line 1246
    .line 1247
    invoke-direct {v4, v5, v8}, Lx7/d;-><init>(ILw7/p;)V

    .line 1248
    .line 1249
    .line 1250
    iget-object v3, v3, Lx7/c;->g:Ljava/util/ArrayList;

    .line 1251
    .line 1252
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1253
    .line 1254
    .line 1255
    goto :goto_1d

    .line 1256
    :cond_3f
    iget-boolean v5, v0, Li9/m;->u:Z

    .line 1257
    .line 1258
    if-nez v5, :cond_40

    .line 1259
    .line 1260
    iget v5, v0, Li9/m;->l:I

    .line 1261
    .line 1262
    const v8, 0x6d646174

    .line 1263
    .line 1264
    .line 1265
    if-ne v5, v8, :cond_40

    .line 1266
    .line 1267
    const/4 v5, 0x1

    .line 1268
    iput v5, v0, Li9/m;->E:I

    .line 1269
    .line 1270
    :cond_40
    cmp-long v5, v3, v19

    .line 1271
    .line 1272
    if-gez v5, :cond_42

    .line 1273
    .line 1274
    long-to-int v3, v3

    .line 1275
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 1276
    .line 1277
    .line 1278
    :cond_41
    :goto_1d
    const/4 v3, 0x0

    .line 1279
    goto :goto_1e

    .line 1280
    :cond_42
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1281
    .line 1282
    .line 1283
    move-result-wide v8

    .line 1284
    add-long/2addr v8, v3

    .line 1285
    iput-wide v8, v2, Lo8/s;->a:J

    .line 1286
    .line 1287
    const/4 v3, 0x1

    .line 1288
    :goto_1e
    invoke-virtual {v0, v6, v7}, Li9/m;->m(J)V

    .line 1289
    .line 1290
    .line 1291
    iget-boolean v4, v0, Li9/m;->v:Z

    .line 1292
    .line 1293
    if-eqz v4, :cond_43

    .line 1294
    .line 1295
    const/4 v4, 0x1

    .line 1296
    iput-boolean v4, v0, Li9/m;->x:Z

    .line 1297
    .line 1298
    iget-wide v3, v0, Li9/m;->w:J

    .line 1299
    .line 1300
    iput-wide v3, v2, Lo8/s;->a:J

    .line 1301
    .line 1302
    const/4 v14, 0x0

    .line 1303
    iput-boolean v14, v0, Li9/m;->v:Z

    .line 1304
    .line 1305
    const/4 v3, 0x1

    .line 1306
    :cond_43
    if-eqz v3, :cond_44

    .line 1307
    .line 1308
    iget v3, v0, Li9/m;->k:I

    .line 1309
    .line 1310
    const/4 v4, 0x2

    .line 1311
    if-eq v3, v4, :cond_44

    .line 1312
    .line 1313
    const/4 v9, 0x1

    .line 1314
    goto :goto_1f

    .line 1315
    :cond_44
    const/4 v9, 0x0

    .line 1316
    :goto_1f
    if-eqz v9, :cond_0

    .line 1317
    .line 1318
    const/4 v4, 0x1

    .line 1319
    :goto_20
    return v4

    .line 1320
    :cond_45
    iget v3, v0, Li9/m;->n:I

    .line 1321
    .line 1322
    iget-object v7, v0, Li9/m;->f:Lw7/p;

    .line 1323
    .line 1324
    if-nez v3, :cond_49

    .line 1325
    .line 1326
    iget-object v3, v7, Lw7/p;->a:[B

    .line 1327
    .line 1328
    const/16 v9, 0x8

    .line 1329
    .line 1330
    const/4 v14, 0x0

    .line 1331
    invoke-interface {v1, v3, v14, v9, v4}, Lo8/p;->f([BIIZ)Z

    .line 1332
    .line 1333
    .line 1334
    move-result v3

    .line 1335
    if-nez v3, :cond_48

    .line 1336
    .line 1337
    iget v3, v0, Li9/m;->E:I

    .line 1338
    .line 1339
    const/4 v4, 0x2

    .line 1340
    if-ne v3, v4, :cond_47

    .line 1341
    .line 1342
    and-int/lit8 v3, v6, 0x2

    .line 1343
    .line 1344
    if-eqz v3, :cond_47

    .line 1345
    .line 1346
    iget-object v3, v0, Li9/m;->z:Lo8/q;

    .line 1347
    .line 1348
    const/4 v4, 0x4

    .line 1349
    invoke-interface {v3, v14, v4}, Lo8/q;->q(II)Lo8/i0;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v3

    .line 1353
    iget-object v4, v0, Li9/m;->F:Ld9/a;

    .line 1354
    .line 1355
    if-nez v4, :cond_46

    .line 1356
    .line 1357
    const/4 v11, 0x0

    .line 1358
    goto :goto_21

    .line 1359
    :cond_46
    new-instance v11, Lt7/c0;

    .line 1360
    .line 1361
    const/4 v5, 0x1

    .line 1362
    new-array v5, v5, [Lt7/b0;

    .line 1363
    .line 1364
    aput-object v4, v5, v14

    .line 1365
    .line 1366
    invoke-direct {v11, v5}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 1367
    .line 1368
    .line 1369
    :goto_21
    new-instance v4, Lt7/n;

    .line 1370
    .line 1371
    invoke-direct {v4}, Lt7/n;-><init>()V

    .line 1372
    .line 1373
    .line 1374
    iput-object v11, v4, Lt7/n;->k:Lt7/c0;

    .line 1375
    .line 1376
    invoke-static {v4, v3}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 1377
    .line 1378
    .line 1379
    iget-object v3, v0, Li9/m;->z:Lo8/q;

    .line 1380
    .line 1381
    invoke-interface {v3}, Lo8/q;->m()V

    .line 1382
    .line 1383
    .line 1384
    iget-object v3, v0, Li9/m;->z:Lo8/q;

    .line 1385
    .line 1386
    new-instance v4, Lo8/t;

    .line 1387
    .line 1388
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 1389
    .line 1390
    .line 1391
    .line 1392
    .line 1393
    invoke-direct {v4, v5, v6}, Lo8/t;-><init>(J)V

    .line 1394
    .line 1395
    .line 1396
    invoke-interface {v3, v4}, Lo8/q;->c(Lo8/c0;)V

    .line 1397
    .line 1398
    .line 1399
    :cond_47
    const/4 v9, 0x0

    .line 1400
    goto/16 :goto_28

    .line 1401
    .line 1402
    :cond_48
    const/16 v9, 0x8

    .line 1403
    .line 1404
    iput v9, v0, Li9/m;->n:I

    .line 1405
    .line 1406
    const/4 v14, 0x0

    .line 1407
    invoke-virtual {v7, v14}, Lw7/p;->I(I)V

    .line 1408
    .line 1409
    .line 1410
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1411
    .line 1412
    .line 1413
    move-result-wide v3

    .line 1414
    iput-wide v3, v0, Li9/m;->m:J

    .line 1415
    .line 1416
    invoke-virtual {v7}, Lw7/p;->j()I

    .line 1417
    .line 1418
    .line 1419
    move-result v3

    .line 1420
    iput v3, v0, Li9/m;->l:I

    .line 1421
    .line 1422
    :cond_49
    iget-wide v3, v0, Li9/m;->m:J

    .line 1423
    .line 1424
    const-wide/16 v9, 0x1

    .line 1425
    .line 1426
    cmp-long v6, v3, v9

    .line 1427
    .line 1428
    if-nez v6, :cond_4a

    .line 1429
    .line 1430
    iget-object v3, v7, Lw7/p;->a:[B

    .line 1431
    .line 1432
    const/16 v9, 0x8

    .line 1433
    .line 1434
    invoke-interface {v1, v3, v9, v9}, Lo8/p;->readFully([BII)V

    .line 1435
    .line 1436
    .line 1437
    iget v3, v0, Li9/m;->n:I

    .line 1438
    .line 1439
    add-int/2addr v3, v9

    .line 1440
    iput v3, v0, Li9/m;->n:I

    .line 1441
    .line 1442
    invoke-virtual {v7}, Lw7/p;->B()J

    .line 1443
    .line 1444
    .line 1445
    move-result-wide v3

    .line 1446
    iput-wide v3, v0, Li9/m;->m:J

    .line 1447
    .line 1448
    goto :goto_22

    .line 1449
    :cond_4a
    const-wide/16 v25, 0x0

    .line 1450
    .line 1451
    cmp-long v3, v3, v25

    .line 1452
    .line 1453
    if-nez v3, :cond_4c

    .line 1454
    .line 1455
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 1456
    .line 1457
    .line 1458
    move-result-wide v3

    .line 1459
    cmp-long v6, v3, v16

    .line 1460
    .line 1461
    if-nez v6, :cond_4b

    .line 1462
    .line 1463
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 1464
    .line 1465
    .line 1466
    move-result-object v6

    .line 1467
    check-cast v6, Lx7/c;

    .line 1468
    .line 1469
    if-eqz v6, :cond_4b

    .line 1470
    .line 1471
    iget-wide v3, v6, Lx7/c;->f:J

    .line 1472
    .line 1473
    :cond_4b
    cmp-long v6, v3, v16

    .line 1474
    .line 1475
    if-eqz v6, :cond_4c

    .line 1476
    .line 1477
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1478
    .line 1479
    .line 1480
    move-result-wide v9

    .line 1481
    sub-long/2addr v3, v9

    .line 1482
    iget v6, v0, Li9/m;->n:I

    .line 1483
    .line 1484
    int-to-long v9, v6

    .line 1485
    add-long/2addr v3, v9

    .line 1486
    iput-wide v3, v0, Li9/m;->m:J

    .line 1487
    .line 1488
    :cond_4c
    :goto_22
    iget-wide v3, v0, Li9/m;->m:J

    .line 1489
    .line 1490
    iget v6, v0, Li9/m;->n:I

    .line 1491
    .line 1492
    int-to-long v9, v6

    .line 1493
    cmp-long v3, v3, v9

    .line 1494
    .line 1495
    if-ltz v3, :cond_56

    .line 1496
    .line 1497
    iget v3, v0, Li9/m;->l:I

    .line 1498
    .line 1499
    const v4, 0x6d6f6f76

    .line 1500
    .line 1501
    .line 1502
    const v9, 0x6d657461

    .line 1503
    .line 1504
    .line 1505
    if-eq v3, v4, :cond_4d

    .line 1506
    .line 1507
    const v4, 0x7472616b

    .line 1508
    .line 1509
    .line 1510
    if-eq v3, v4, :cond_4d

    .line 1511
    .line 1512
    const v4, 0x6d646961

    .line 1513
    .line 1514
    .line 1515
    if-eq v3, v4, :cond_4d

    .line 1516
    .line 1517
    const v4, 0x6d696e66

    .line 1518
    .line 1519
    .line 1520
    if-eq v3, v4, :cond_4d

    .line 1521
    .line 1522
    const v4, 0x7374626c

    .line 1523
    .line 1524
    .line 1525
    if-eq v3, v4, :cond_4d

    .line 1526
    .line 1527
    const v4, 0x65647473

    .line 1528
    .line 1529
    .line 1530
    if-eq v3, v4, :cond_4d

    .line 1531
    .line 1532
    if-eq v3, v9, :cond_4d

    .line 1533
    .line 1534
    const v4, 0x61787465

    .line 1535
    .line 1536
    .line 1537
    if-ne v3, v4, :cond_4e

    .line 1538
    .line 1539
    :cond_4d
    const/4 v4, 0x1

    .line 1540
    goto/16 :goto_26

    .line 1541
    .line 1542
    :cond_4e
    const v4, 0x6d646864

    .line 1543
    .line 1544
    .line 1545
    if-eq v3, v4, :cond_4f

    .line 1546
    .line 1547
    const v4, 0x6d766864

    .line 1548
    .line 1549
    .line 1550
    if-eq v3, v4, :cond_4f

    .line 1551
    .line 1552
    const v4, 0x68646c72    # 4.3148E24f

    .line 1553
    .line 1554
    .line 1555
    if-eq v3, v4, :cond_4f

    .line 1556
    .line 1557
    const v4, 0x73747364

    .line 1558
    .line 1559
    .line 1560
    if-eq v3, v4, :cond_4f

    .line 1561
    .line 1562
    const v4, 0x73747473

    .line 1563
    .line 1564
    .line 1565
    if-eq v3, v4, :cond_4f

    .line 1566
    .line 1567
    const v4, 0x73747373

    .line 1568
    .line 1569
    .line 1570
    if-eq v3, v4, :cond_4f

    .line 1571
    .line 1572
    const v4, 0x63747473

    .line 1573
    .line 1574
    .line 1575
    if-eq v3, v4, :cond_4f

    .line 1576
    .line 1577
    const v4, 0x656c7374

    .line 1578
    .line 1579
    .line 1580
    if-eq v3, v4, :cond_4f

    .line 1581
    .line 1582
    const v4, 0x73747363

    .line 1583
    .line 1584
    .line 1585
    if-eq v3, v4, :cond_4f

    .line 1586
    .line 1587
    const v4, 0x7374737a

    .line 1588
    .line 1589
    .line 1590
    if-eq v3, v4, :cond_4f

    .line 1591
    .line 1592
    const v4, 0x73747a32

    .line 1593
    .line 1594
    .line 1595
    if-eq v3, v4, :cond_4f

    .line 1596
    .line 1597
    const v4, 0x7374636f

    .line 1598
    .line 1599
    .line 1600
    if-eq v3, v4, :cond_4f

    .line 1601
    .line 1602
    const v4, 0x636f3634

    .line 1603
    .line 1604
    .line 1605
    if-eq v3, v4, :cond_4f

    .line 1606
    .line 1607
    const v4, 0x746b6864

    .line 1608
    .line 1609
    .line 1610
    if-eq v3, v4, :cond_4f

    .line 1611
    .line 1612
    const v4, 0x66747970

    .line 1613
    .line 1614
    .line 1615
    if-eq v3, v4, :cond_4f

    .line 1616
    .line 1617
    const v4, 0x75647461

    .line 1618
    .line 1619
    .line 1620
    if-eq v3, v4, :cond_4f

    .line 1621
    .line 1622
    const v4, 0x6b657973

    .line 1623
    .line 1624
    .line 1625
    if-eq v3, v4, :cond_4f

    .line 1626
    .line 1627
    const v4, 0x696c7374

    .line 1628
    .line 1629
    .line 1630
    if-ne v3, v4, :cond_50

    .line 1631
    .line 1632
    :cond_4f
    const/16 v5, 0x8

    .line 1633
    .line 1634
    goto :goto_23

    .line 1635
    :cond_50
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1636
    .line 1637
    .line 1638
    move-result-wide v3

    .line 1639
    iget v5, v0, Li9/m;->n:I

    .line 1640
    .line 1641
    int-to-long v5, v5

    .line 1642
    sub-long v10, v3, v5

    .line 1643
    .line 1644
    iget v3, v0, Li9/m;->l:I

    .line 1645
    .line 1646
    const v4, 0x6d707664

    .line 1647
    .line 1648
    .line 1649
    if-ne v3, v4, :cond_51

    .line 1650
    .line 1651
    new-instance v7, Ld9/a;

    .line 1652
    .line 1653
    add-long v14, v10, v5

    .line 1654
    .line 1655
    iget-wide v3, v0, Li9/m;->m:J

    .line 1656
    .line 1657
    sub-long v16, v3, v5

    .line 1658
    .line 1659
    const-wide/16 v8, 0x0

    .line 1660
    .line 1661
    const-wide v12, -0x7fffffffffffffffL    # -4.9E-324

    .line 1662
    .line 1663
    .line 1664
    .line 1665
    .line 1666
    invoke-direct/range {v7 .. v17}, Ld9/a;-><init>(JJJJJ)V

    .line 1667
    .line 1668
    .line 1669
    iput-object v7, v0, Li9/m;->F:Ld9/a;

    .line 1670
    .line 1671
    :cond_51
    const/4 v3, 0x0

    .line 1672
    iput-object v3, v0, Li9/m;->o:Lw7/p;

    .line 1673
    .line 1674
    const/4 v4, 0x1

    .line 1675
    iput v4, v0, Li9/m;->k:I

    .line 1676
    .line 1677
    goto/16 :goto_27

    .line 1678
    .line 1679
    :goto_23
    if-ne v6, v5, :cond_52

    .line 1680
    .line 1681
    const/4 v3, 0x1

    .line 1682
    goto :goto_24

    .line 1683
    :cond_52
    const/4 v3, 0x0

    .line 1684
    :goto_24
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 1685
    .line 1686
    .line 1687
    iget-wide v3, v0, Li9/m;->m:J

    .line 1688
    .line 1689
    const-wide/32 v5, 0x7fffffff

    .line 1690
    .line 1691
    .line 1692
    cmp-long v3, v3, v5

    .line 1693
    .line 1694
    if-gtz v3, :cond_53

    .line 1695
    .line 1696
    const/4 v3, 0x1

    .line 1697
    goto :goto_25

    .line 1698
    :cond_53
    const/4 v3, 0x0

    .line 1699
    :goto_25
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 1700
    .line 1701
    .line 1702
    new-instance v3, Lw7/p;

    .line 1703
    .line 1704
    iget-wide v4, v0, Li9/m;->m:J

    .line 1705
    .line 1706
    long-to-int v4, v4

    .line 1707
    invoke-direct {v3, v4}, Lw7/p;-><init>(I)V

    .line 1708
    .line 1709
    .line 1710
    iget-object v4, v7, Lw7/p;->a:[B

    .line 1711
    .line 1712
    iget-object v5, v3, Lw7/p;->a:[B

    .line 1713
    .line 1714
    const/16 v9, 0x8

    .line 1715
    .line 1716
    const/4 v14, 0x0

    .line 1717
    invoke-static {v4, v14, v5, v14, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 1718
    .line 1719
    .line 1720
    iput-object v3, v0, Li9/m;->o:Lw7/p;

    .line 1721
    .line 1722
    const/4 v4, 0x1

    .line 1723
    iput v4, v0, Li9/m;->k:I

    .line 1724
    .line 1725
    goto :goto_27

    .line 1726
    :goto_26
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1727
    .line 1728
    .line 1729
    move-result-wide v6

    .line 1730
    iget-wide v10, v0, Li9/m;->m:J

    .line 1731
    .line 1732
    add-long/2addr v6, v10

    .line 1733
    iget v3, v0, Li9/m;->n:I

    .line 1734
    .line 1735
    int-to-long v12, v3

    .line 1736
    sub-long/2addr v6, v12

    .line 1737
    cmp-long v3, v10, v12

    .line 1738
    .line 1739
    if-eqz v3, :cond_54

    .line 1740
    .line 1741
    iget v3, v0, Li9/m;->l:I

    .line 1742
    .line 1743
    if-ne v3, v9, :cond_54

    .line 1744
    .line 1745
    const/16 v9, 0x8

    .line 1746
    .line 1747
    invoke-virtual {v8, v9}, Lw7/p;->F(I)V

    .line 1748
    .line 1749
    .line 1750
    iget-object v3, v8, Lw7/p;->a:[B

    .line 1751
    .line 1752
    const/4 v14, 0x0

    .line 1753
    invoke-interface {v1, v3, v14, v9}, Lo8/p;->o([BII)V

    .line 1754
    .line 1755
    .line 1756
    invoke-static {v8}, Li9/e;->a(Lw7/p;)V

    .line 1757
    .line 1758
    .line 1759
    iget v3, v8, Lw7/p;->b:I

    .line 1760
    .line 1761
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 1762
    .line 1763
    .line 1764
    invoke-interface {v1}, Lo8/p;->e()V

    .line 1765
    .line 1766
    .line 1767
    :cond_54
    new-instance v3, Lx7/c;

    .line 1768
    .line 1769
    iget v8, v0, Li9/m;->l:I

    .line 1770
    .line 1771
    invoke-direct {v3, v8, v6, v7}, Lx7/c;-><init>(IJ)V

    .line 1772
    .line 1773
    .line 1774
    invoke-virtual {v5, v3}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 1775
    .line 1776
    .line 1777
    iget-wide v8, v0, Li9/m;->m:J

    .line 1778
    .line 1779
    iget v3, v0, Li9/m;->n:I

    .line 1780
    .line 1781
    int-to-long v10, v3

    .line 1782
    cmp-long v3, v8, v10

    .line 1783
    .line 1784
    if-nez v3, :cond_55

    .line 1785
    .line 1786
    invoke-virtual {v0, v6, v7}, Li9/m;->m(J)V

    .line 1787
    .line 1788
    .line 1789
    goto :goto_27

    .line 1790
    :cond_55
    const/4 v14, 0x0

    .line 1791
    iput v14, v0, Li9/m;->k:I

    .line 1792
    .line 1793
    iput v14, v0, Li9/m;->n:I

    .line 1794
    .line 1795
    :goto_27
    move v9, v4

    .line 1796
    :goto_28
    if-nez v9, :cond_0

    .line 1797
    .line 1798
    const/16 v23, -0x1

    .line 1799
    .line 1800
    :goto_29
    return v23

    .line 1801
    :cond_56
    const-string v0, "Atom size less than header length (unsupported)."

    .line 1802
    .line 1803
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 1804
    .line 1805
    .line 1806
    move-result-object v0

    .line 1807
    throw v0

    .line 1808
    nop

    .line 1809
    :sswitch_data_0
    .sparse-switch
        -0x6604662e -> :sswitch_4
        -0x4f6659e5 -> :sswitch_3
        -0x4a96a712 -> :sswitch_2
        -0x3182f331 -> :sswitch_1
        0x68f2d704 -> :sswitch_0
    .end sparse-switch

    .line 1810
    .line 1811
    .line 1812
    .line 1813
    .line 1814
    .line 1815
    .line 1816
    .line 1817
    .line 1818
    .line 1819
    .line 1820
    .line 1821
    .line 1822
    .line 1823
    .line 1824
    .line 1825
    .line 1826
    .line 1827
    .line 1828
    .line 1829
    .line 1830
    .line 1831
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final j()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Li9/m;->j:Lhr/x0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()J
    .locals 2

    .line 1
    iget-wide v0, p0, Li9/m;->D:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final m(J)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    :cond_0
    :goto_0
    iget-object v1, v0, Li9/m;->g:Ljava/util/ArrayDeque;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x2

    .line 11
    if-nez v2, :cond_21

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Lx7/c;

    .line 18
    .line 19
    iget-wide v5, v2, Lx7/c;->f:J

    .line 20
    .line 21
    cmp-long v2, v5, p1

    .line 22
    .line 23
    if-nez v2, :cond_21

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    move-object v5, v2

    .line 30
    check-cast v5, Lx7/c;

    .line 31
    .line 32
    iget v2, v5, Lkq/d;->e:I

    .line 33
    .line 34
    const v6, 0x6d6f6f76

    .line 35
    .line 36
    .line 37
    if-ne v2, v6, :cond_20

    .line 38
    .line 39
    const v2, 0x6d657461

    .line 40
    .line 41
    .line 42
    invoke-virtual {v5, v2}, Lx7/c;->m(I)Lx7/c;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    new-instance v6, Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 49
    .line 50
    .line 51
    const/4 v13, 0x1

    .line 52
    const-wide/16 v14, 0x0

    .line 53
    .line 54
    iget v7, v0, Li9/m;->b:I

    .line 55
    .line 56
    const/16 v16, 0x0

    .line 57
    .line 58
    if-eqz v2, :cond_9

    .line 59
    .line 60
    invoke-static {v2}, Li9/e;->f(Lx7/c;)Lt7/c0;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    iget-boolean v8, v0, Li9/m;->x:Z

    .line 65
    .line 66
    if-eqz v8, :cond_7

    .line 67
    .line 68
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    const-string v6, "auxiliary.tracks.interleaved"

    .line 72
    .line 73
    invoke-static {v2, v6}, Li9/p;->a(Lt7/c0;Ljava/lang/String;)Lx7/a;

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    if-eqz v6, :cond_1

    .line 78
    .line 79
    iget-object v6, v6, Lx7/a;->b:[B

    .line 80
    .line 81
    aget-byte v6, v6, v3

    .line 82
    .line 83
    if-nez v6, :cond_1

    .line 84
    .line 85
    iget-wide v8, v0, Li9/m;->w:J

    .line 86
    .line 87
    const-wide/16 v10, 0x10

    .line 88
    .line 89
    add-long/2addr v8, v10

    .line 90
    iput-wide v8, v0, Li9/m;->y:J

    .line 91
    .line 92
    :cond_1
    const-string v6, "auxiliary.tracks.map"

    .line 93
    .line 94
    invoke-static {v2, v6}, Li9/p;->a(Lt7/c0;Ljava/lang/String;)Lx7/a;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    invoke-static {v6}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v6}, Lx7/a;->d()Ljava/util/ArrayList;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    new-instance v8, Ljava/util/ArrayList;

    .line 106
    .line 107
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 108
    .line 109
    .line 110
    move-result v9

    .line 111
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 112
    .line 113
    .line 114
    move v9, v3

    .line 115
    :goto_1
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 116
    .line 117
    .line 118
    move-result v10

    .line 119
    if-ge v9, v10, :cond_6

    .line 120
    .line 121
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    check-cast v10, Ljava/lang/Integer;

    .line 126
    .line 127
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 128
    .line 129
    .line 130
    move-result v10

    .line 131
    if-eqz v10, :cond_4

    .line 132
    .line 133
    if-eq v10, v13, :cond_3

    .line 134
    .line 135
    const/4 v11, 0x3

    .line 136
    if-eq v10, v4, :cond_5

    .line 137
    .line 138
    if-eq v10, v11, :cond_2

    .line 139
    .line 140
    move v11, v3

    .line 141
    goto :goto_2

    .line 142
    :cond_2
    const/4 v11, 0x4

    .line 143
    goto :goto_2

    .line 144
    :cond_3
    move v11, v4

    .line 145
    goto :goto_2

    .line 146
    :cond_4
    move v11, v13

    .line 147
    :cond_5
    :goto_2
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 148
    .line 149
    .line 150
    move-result-object v10

    .line 151
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    add-int/lit8 v9, v9, 0x1

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_6
    move-object v6, v8

    .line 158
    goto :goto_3

    .line 159
    :cond_7
    if-nez v2, :cond_8

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_8
    and-int/lit8 v8, v7, 0x40

    .line 163
    .line 164
    if-eqz v8, :cond_a

    .line 165
    .line 166
    const-string v8, "auxiliary.tracks.offset"

    .line 167
    .line 168
    invoke-static {v2, v8}, Li9/p;->a(Lt7/c0;Ljava/lang/String;)Lx7/a;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    if-eqz v8, :cond_a

    .line 173
    .line 174
    new-instance v9, Lw7/p;

    .line 175
    .line 176
    iget-object v8, v8, Lx7/a;->b:[B

    .line 177
    .line 178
    invoke-direct {v9, v8}, Lw7/p;-><init>([B)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v9}, Lw7/p;->B()J

    .line 182
    .line 183
    .line 184
    move-result-wide v8

    .line 185
    cmp-long v10, v8, v14

    .line 186
    .line 187
    if-lez v10, :cond_a

    .line 188
    .line 189
    iput-wide v8, v0, Li9/m;->w:J

    .line 190
    .line 191
    iput-boolean v13, v0, Li9/m;->v:Z

    .line 192
    .line 193
    move-object/from16 v24, v1

    .line 194
    .line 195
    goto/16 :goto_14

    .line 196
    .line 197
    :cond_9
    move-object/from16 v2, v16

    .line 198
    .line 199
    :cond_a
    :goto_3
    new-instance v8, Ljava/util/ArrayList;

    .line 200
    .line 201
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 202
    .line 203
    .line 204
    iget v9, v0, Li9/m;->E:I

    .line 205
    .line 206
    if-ne v9, v13, :cond_b

    .line 207
    .line 208
    move v11, v13

    .line 209
    :goto_4
    move-object v9, v6

    .line 210
    goto :goto_5

    .line 211
    :cond_b
    move v11, v3

    .line 212
    goto :goto_4

    .line 213
    :goto_5
    new-instance v6, Lo8/w;

    .line 214
    .line 215
    invoke-direct {v6}, Lo8/w;-><init>()V

    .line 216
    .line 217
    .line 218
    const v10, 0x75647461

    .line 219
    .line 220
    .line 221
    invoke-virtual {v5, v10}, Lx7/c;->n(I)Lx7/d;

    .line 222
    .line 223
    .line 224
    move-result-object v10

    .line 225
    if-eqz v10, :cond_c

    .line 226
    .line 227
    invoke-static {v10}, Li9/e;->k(Lx7/d;)Lt7/c0;

    .line 228
    .line 229
    .line 230
    move-result-object v10

    .line 231
    invoke-virtual {v6, v10}, Lo8/w;->b(Lt7/c0;)V

    .line 232
    .line 233
    .line 234
    goto :goto_6

    .line 235
    :cond_c
    move-object/from16 v10, v16

    .line 236
    .line 237
    :goto_6
    new-instance v12, Lt7/c0;

    .line 238
    .line 239
    const v14, 0x6d766864

    .line 240
    .line 241
    .line 242
    invoke-virtual {v5, v14}, Lx7/c;->n(I)Lx7/d;

    .line 243
    .line 244
    .line 245
    move-result-object v14

    .line 246
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 247
    .line 248
    .line 249
    iget-object v14, v14, Lx7/d;->f:Lw7/p;

    .line 250
    .line 251
    invoke-static {v14}, Li9/e;->g(Lw7/p;)Lx7/f;

    .line 252
    .line 253
    .line 254
    move-result-object v14

    .line 255
    new-array v15, v13, [Lt7/b0;

    .line 256
    .line 257
    aput-object v14, v15, v3

    .line 258
    .line 259
    invoke-direct {v12, v15}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 260
    .line 261
    .line 262
    and-int/lit8 v14, v7, 0x1

    .line 263
    .line 264
    if-eqz v14, :cond_d

    .line 265
    .line 266
    move-object v14, v10

    .line 267
    move v10, v13

    .line 268
    :goto_7
    move-object v15, v12

    .line 269
    goto :goto_8

    .line 270
    :cond_d
    move-object v14, v10

    .line 271
    move v10, v3

    .line 272
    goto :goto_7

    .line 273
    :goto_8
    new-instance v12, Lf3/d;

    .line 274
    .line 275
    const/16 v3, 0x1a

    .line 276
    .line 277
    invoke-direct {v12, v3}, Lf3/d;-><init>(I)V

    .line 278
    .line 279
    .line 280
    move/from16 v18, v7

    .line 281
    .line 282
    move-object v3, v8

    .line 283
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 284
    .line 285
    .line 286
    .line 287
    .line 288
    move-object/from16 v19, v9

    .line 289
    .line 290
    const/4 v9, 0x0

    .line 291
    move-object/from16 v20, v15

    .line 292
    .line 293
    move-object v15, v14

    .line 294
    move-object v14, v3

    .line 295
    move-object/from16 v3, v19

    .line 296
    .line 297
    invoke-static/range {v5 .. v12}, Li9/e;->j(Lx7/c;Lo8/w;JLt7/k;ZZLgr/e;)Ljava/util/ArrayList;

    .line 298
    .line 299
    .line 300
    move-result-object v5

    .line 301
    iget-boolean v7, v0, Li9/m;->x:Z

    .line 302
    .line 303
    if-eqz v7, :cond_f

    .line 304
    .line 305
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 306
    .line 307
    .line 308
    move-result v7

    .line 309
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 310
    .line 311
    .line 312
    move-result v8

    .line 313
    if-ne v7, v8, :cond_e

    .line 314
    .line 315
    move v7, v13

    .line 316
    goto :goto_9

    .line 317
    :cond_e
    const/4 v7, 0x0

    .line 318
    :goto_9
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 319
    .line 320
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 321
    .line 322
    .line 323
    move-result v8

    .line 324
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 325
    .line 326
    .line 327
    move-result v9

    .line 328
    const-string v10, ") is not same as the number of auxiliary tracks ("

    .line 329
    .line 330
    const-string v11, ")"

    .line 331
    .line 332
    const-string v12, "The number of auxiliary track types from metadata ("

    .line 333
    .line 334
    invoke-static {v8, v9, v12, v10, v11}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v8

    .line 338
    invoke-static {v8, v7}, Lw7/a;->i(Ljava/lang/String;Z)V

    .line 339
    .line 340
    .line 341
    :cond_f
    invoke-static {v5}, Li9/p;->b(Ljava/util/ArrayList;)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v7

    .line 345
    move-object/from16 v19, v14

    .line 346
    .line 347
    const/4 v9, -0x1

    .line 348
    const/4 v11, 0x0

    .line 349
    const/4 v12, 0x0

    .line 350
    const-wide v13, -0x7fffffffffffffffL    # -4.9E-324

    .line 351
    .line 352
    .line 353
    .line 354
    .line 355
    const-wide v21, -0x7fffffffffffffffL    # -4.9E-324

    .line 356
    .line 357
    .line 358
    .line 359
    .line 360
    :goto_a
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 361
    .line 362
    .line 363
    move-result v10

    .line 364
    if-ge v11, v10, :cond_1a

    .line 365
    .line 366
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v10

    .line 370
    check-cast v10, Li9/t;

    .line 371
    .line 372
    iget v8, v10, Li9/t;->b:I

    .line 373
    .line 374
    iget v4, v10, Li9/t;->e:I

    .line 375
    .line 376
    if-nez v8, :cond_10

    .line 377
    .line 378
    move-object/from16 v24, v1

    .line 379
    .line 380
    move-object/from16 v27, v5

    .line 381
    .line 382
    move-object/from16 v28, v7

    .line 383
    .line 384
    move/from16 v26, v12

    .line 385
    .line 386
    move-object/from16 v1, v19

    .line 387
    .line 388
    move-object/from16 v7, v20

    .line 389
    .line 390
    const/4 v8, -0x1

    .line 391
    move-object v12, v2

    .line 392
    goto/16 :goto_10

    .line 393
    .line 394
    :cond_10
    iget-object v8, v10, Li9/t;->a:Li9/q;

    .line 395
    .line 396
    move-object/from16 v24, v1

    .line 397
    .line 398
    new-instance v1, Li9/l;

    .line 399
    .line 400
    move/from16 v25, v4

    .line 401
    .line 402
    iget-object v4, v0, Li9/m;->z:Lo8/q;

    .line 403
    .line 404
    add-int/lit8 v26, v12, 0x1

    .line 405
    .line 406
    move-object/from16 v27, v5

    .line 407
    .line 408
    iget v5, v8, Li9/q;->b:I

    .line 409
    .line 410
    move-object/from16 v28, v7

    .line 411
    .line 412
    iget-object v7, v8, Li9/q;->g:Lt7/o;

    .line 413
    .line 414
    invoke-interface {v4, v12, v5}, Lo8/q;->q(II)Lo8/i0;

    .line 415
    .line 416
    .line 417
    move-result-object v4

    .line 418
    invoke-direct {v1, v8, v10, v4}, Li9/l;-><init>(Li9/q;Li9/t;Lo8/i0;)V

    .line 419
    .line 420
    .line 421
    move-object/from16 v29, v1

    .line 422
    .line 423
    move-object v12, v2

    .line 424
    iget-wide v1, v8, Li9/q;->e:J

    .line 425
    .line 426
    cmp-long v8, v1, v21

    .line 427
    .line 428
    if-eqz v8, :cond_11

    .line 429
    .line 430
    goto :goto_b

    .line 431
    :cond_11
    iget-wide v1, v10, Li9/t;->h:J

    .line 432
    .line 433
    :goto_b
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 434
    .line 435
    .line 436
    invoke-static {v13, v14, v1, v2}, Ljava/lang/Math;->max(JJ)J

    .line 437
    .line 438
    .line 439
    move-result-wide v13

    .line 440
    const-string v1, "audio/true-hd"

    .line 441
    .line 442
    iget-object v2, v7, Lt7/o;->n:Ljava/lang/String;

    .line 443
    .line 444
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 445
    .line 446
    .line 447
    move-result v1

    .line 448
    if-eqz v1, :cond_12

    .line 449
    .line 450
    mul-int/lit8 v1, v25, 0x10

    .line 451
    .line 452
    goto :goto_c

    .line 453
    :cond_12
    add-int/lit8 v1, v25, 0x1e

    .line 454
    .line 455
    :goto_c
    invoke-virtual {v7}, Lt7/o;->a()Lt7/n;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    iput v1, v2, Lt7/n;->n:I

    .line 460
    .line 461
    const/4 v1, 0x2

    .line 462
    if-ne v5, v1, :cond_16

    .line 463
    .line 464
    iget v1, v7, Lt7/o;->f:I

    .line 465
    .line 466
    and-int/lit8 v8, v18, 0x8

    .line 467
    .line 468
    if-eqz v8, :cond_14

    .line 469
    .line 470
    const/4 v8, -0x1

    .line 471
    if-ne v9, v8, :cond_13

    .line 472
    .line 473
    const/4 v10, 0x1

    .line 474
    goto :goto_d

    .line 475
    :cond_13
    const/4 v10, 0x2

    .line 476
    :goto_d
    or-int/2addr v1, v10

    .line 477
    :cond_14
    iget-boolean v8, v0, Li9/m;->x:Z

    .line 478
    .line 479
    if-eqz v8, :cond_15

    .line 480
    .line 481
    const v8, 0x8000

    .line 482
    .line 483
    .line 484
    or-int/2addr v1, v8

    .line 485
    invoke-interface {v3, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v8

    .line 489
    check-cast v8, Ljava/lang/Integer;

    .line 490
    .line 491
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 492
    .line 493
    .line 494
    move-result v8

    .line 495
    iput v8, v2, Lt7/n;->g:I

    .line 496
    .line 497
    :cond_15
    iput v1, v2, Lt7/n;->f:I

    .line 498
    .line 499
    :cond_16
    const/4 v10, 0x1

    .line 500
    if-ne v5, v10, :cond_17

    .line 501
    .line 502
    iget v1, v6, Lo8/w;->a:I

    .line 503
    .line 504
    const/4 v8, -0x1

    .line 505
    if-eq v1, v8, :cond_17

    .line 506
    .line 507
    iget v10, v6, Lo8/w;->b:I

    .line 508
    .line 509
    if-eq v10, v8, :cond_17

    .line 510
    .line 511
    iput v1, v2, Lt7/n;->H:I

    .line 512
    .line 513
    iput v10, v2, Lt7/n;->I:I

    .line 514
    .line 515
    :cond_17
    iget-object v1, v7, Lt7/o;->l:Lt7/c0;

    .line 516
    .line 517
    iget-object v7, v0, Li9/m;->i:Ljava/util/ArrayList;

    .line 518
    .line 519
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 520
    .line 521
    .line 522
    move-result v8

    .line 523
    if-eqz v8, :cond_18

    .line 524
    .line 525
    move-object/from16 v8, v16

    .line 526
    .line 527
    :goto_e
    move-object/from16 v7, v20

    .line 528
    .line 529
    goto :goto_f

    .line 530
    :cond_18
    new-instance v8, Lt7/c0;

    .line 531
    .line 532
    invoke-direct {v8, v7}, Lt7/c0;-><init>(Ljava/util/List;)V

    .line 533
    .line 534
    .line 535
    goto :goto_e

    .line 536
    :goto_f
    filled-new-array {v8, v15, v7}, [Lt7/c0;

    .line 537
    .line 538
    .line 539
    move-result-object v8

    .line 540
    invoke-static {v5, v12, v2, v1, v8}, Li9/p;->j(ILt7/c0;Lt7/n;Lt7/c0;[Lt7/c0;)V

    .line 541
    .line 542
    .line 543
    invoke-static/range {v28 .. v28}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 544
    .line 545
    .line 546
    move-result-object v1

    .line 547
    iput-object v1, v2, Lt7/n;->l:Ljava/lang/String;

    .line 548
    .line 549
    invoke-static {v2, v4}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 550
    .line 551
    .line 552
    const/4 v1, 0x2

    .line 553
    const/4 v8, -0x1

    .line 554
    if-ne v5, v1, :cond_19

    .line 555
    .line 556
    if-ne v9, v8, :cond_19

    .line 557
    .line 558
    invoke-virtual/range {v19 .. v19}, Ljava/util/ArrayList;->size()I

    .line 559
    .line 560
    .line 561
    move-result v9

    .line 562
    :cond_19
    move-object/from16 v1, v19

    .line 563
    .line 564
    move-object/from16 v2, v29

    .line 565
    .line 566
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 567
    .line 568
    .line 569
    :goto_10
    add-int/lit8 v11, v11, 0x1

    .line 570
    .line 571
    move-object/from16 v19, v1

    .line 572
    .line 573
    move-object/from16 v20, v7

    .line 574
    .line 575
    move-object v2, v12

    .line 576
    move-object/from16 v1, v24

    .line 577
    .line 578
    move/from16 v12, v26

    .line 579
    .line 580
    move-object/from16 v5, v27

    .line 581
    .line 582
    move-object/from16 v7, v28

    .line 583
    .line 584
    const/4 v4, 0x2

    .line 585
    goto/16 :goto_a

    .line 586
    .line 587
    :cond_1a
    move-object/from16 v24, v1

    .line 588
    .line 589
    move-object/from16 v1, v19

    .line 590
    .line 591
    const/4 v8, -0x1

    .line 592
    iput v9, v0, Li9/m;->C:I

    .line 593
    .line 594
    iput-wide v13, v0, Li9/m;->D:J

    .line 595
    .line 596
    const/4 v2, 0x0

    .line 597
    new-array v3, v2, [Li9/l;

    .line 598
    .line 599
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    move-result-object v1

    .line 603
    check-cast v1, [Li9/l;

    .line 604
    .line 605
    iput-object v1, v0, Li9/m;->A:[Li9/l;

    .line 606
    .line 607
    array-length v2, v1

    .line 608
    new-array v2, v2, [[J

    .line 609
    .line 610
    array-length v3, v1

    .line 611
    new-array v3, v3, [I

    .line 612
    .line 613
    array-length v4, v1

    .line 614
    new-array v4, v4, [J

    .line 615
    .line 616
    array-length v5, v1

    .line 617
    new-array v5, v5, [Z

    .line 618
    .line 619
    const/4 v6, 0x0

    .line 620
    :goto_11
    array-length v7, v1

    .line 621
    if-ge v6, v7, :cond_1b

    .line 622
    .line 623
    aget-object v7, v1, v6

    .line 624
    .line 625
    iget-object v7, v7, Li9/l;->b:Li9/t;

    .line 626
    .line 627
    iget v7, v7, Li9/t;->b:I

    .line 628
    .line 629
    new-array v7, v7, [J

    .line 630
    .line 631
    aput-object v7, v2, v6

    .line 632
    .line 633
    aget-object v7, v1, v6

    .line 634
    .line 635
    iget-object v7, v7, Li9/l;->b:Li9/t;

    .line 636
    .line 637
    iget-object v7, v7, Li9/t;->f:[J

    .line 638
    .line 639
    const/16 v17, 0x0

    .line 640
    .line 641
    aget-wide v9, v7, v17

    .line 642
    .line 643
    aput-wide v9, v4, v6

    .line 644
    .line 645
    add-int/lit8 v6, v6, 0x1

    .line 646
    .line 647
    goto :goto_11

    .line 648
    :cond_1b
    const/4 v6, 0x0

    .line 649
    const-wide/16 v14, 0x0

    .line 650
    .line 651
    :goto_12
    array-length v7, v1

    .line 652
    if-ge v6, v7, :cond_1f

    .line 653
    .line 654
    const-wide v9, 0x7fffffffffffffffL

    .line 655
    .line 656
    .line 657
    .line 658
    .line 659
    move-wide v10, v9

    .line 660
    const/4 v7, 0x0

    .line 661
    move v9, v8

    .line 662
    :goto_13
    array-length v12, v1

    .line 663
    if-ge v7, v12, :cond_1d

    .line 664
    .line 665
    aget-boolean v12, v5, v7

    .line 666
    .line 667
    if-nez v12, :cond_1c

    .line 668
    .line 669
    aget-wide v12, v4, v7

    .line 670
    .line 671
    cmp-long v16, v12, v10

    .line 672
    .line 673
    if-gtz v16, :cond_1c

    .line 674
    .line 675
    move v9, v7

    .line 676
    move-wide v10, v12

    .line 677
    :cond_1c
    add-int/lit8 v7, v7, 0x1

    .line 678
    .line 679
    goto :goto_13

    .line 680
    :cond_1d
    aget v7, v3, v9

    .line 681
    .line 682
    aget-object v10, v2, v9

    .line 683
    .line 684
    aput-wide v14, v10, v7

    .line 685
    .line 686
    aget-object v11, v1, v9

    .line 687
    .line 688
    iget-object v11, v11, Li9/l;->b:Li9/t;

    .line 689
    .line 690
    iget-object v12, v11, Li9/t;->d:[I

    .line 691
    .line 692
    aget v12, v12, v7

    .line 693
    .line 694
    int-to-long v12, v12

    .line 695
    add-long/2addr v14, v12

    .line 696
    const/16 v23, 0x1

    .line 697
    .line 698
    add-int/lit8 v7, v7, 0x1

    .line 699
    .line 700
    aput v7, v3, v9

    .line 701
    .line 702
    array-length v10, v10

    .line 703
    if-ge v7, v10, :cond_1e

    .line 704
    .line 705
    iget-object v10, v11, Li9/t;->f:[J

    .line 706
    .line 707
    aget-wide v10, v10, v7

    .line 708
    .line 709
    aput-wide v10, v4, v9

    .line 710
    .line 711
    goto :goto_12

    .line 712
    :cond_1e
    aput-boolean v23, v5, v9

    .line 713
    .line 714
    add-int/lit8 v6, v6, 0x1

    .line 715
    .line 716
    goto :goto_12

    .line 717
    :cond_1f
    iput-object v2, v0, Li9/m;->B:[[J

    .line 718
    .line 719
    iget-object v1, v0, Li9/m;->z:Lo8/q;

    .line 720
    .line 721
    invoke-interface {v1}, Lo8/q;->m()V

    .line 722
    .line 723
    .line 724
    iget-object v1, v0, Li9/m;->z:Lo8/q;

    .line 725
    .line 726
    invoke-interface {v1, v0}, Lo8/q;->c(Lo8/c0;)V

    .line 727
    .line 728
    .line 729
    :goto_14
    invoke-virtual/range {v24 .. v24}, Ljava/util/ArrayDeque;->clear()V

    .line 730
    .line 731
    .line 732
    iget-boolean v1, v0, Li9/m;->v:Z

    .line 733
    .line 734
    if-nez v1, :cond_0

    .line 735
    .line 736
    const/4 v1, 0x2

    .line 737
    iput v1, v0, Li9/m;->k:I

    .line 738
    .line 739
    goto/16 :goto_0

    .line 740
    .line 741
    :cond_20
    move-object/from16 v24, v1

    .line 742
    .line 743
    invoke-virtual/range {v24 .. v24}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 744
    .line 745
    .line 746
    move-result v1

    .line 747
    if-nez v1, :cond_0

    .line 748
    .line 749
    invoke-virtual/range {v24 .. v24}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    move-result-object v1

    .line 753
    check-cast v1, Lx7/c;

    .line 754
    .line 755
    iget-object v1, v1, Lx7/c;->h:Ljava/util/ArrayList;

    .line 756
    .line 757
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 758
    .line 759
    .line 760
    goto/16 :goto_0

    .line 761
    .line 762
    :cond_21
    iget v1, v0, Li9/m;->k:I

    .line 763
    .line 764
    const/4 v2, 0x2

    .line 765
    if-eq v1, v2, :cond_22

    .line 766
    .line 767
    const/4 v2, 0x0

    .line 768
    iput v2, v0, Li9/m;->k:I

    .line 769
    .line 770
    iput v2, v0, Li9/m;->n:I

    .line 771
    .line 772
    :cond_22
    return-void
.end method
