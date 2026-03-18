.class public final Lv9/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:Lw7/u;

.field public final b:Landroid/util/SparseArray;

.field public final c:Lw7/p;

.field public final d:Lv9/x;

.field public e:Z

.field public f:Z

.field public g:Z

.field public h:J

.field public i:Lt8/b;

.field public j:Lo8/q;

.field public k:Z


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    new-instance v0, Lw7/u;

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    invoke-direct {v0, v1, v2}, Lw7/u;-><init>(J)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lv9/z;->a:Lw7/u;

    .line 12
    .line 13
    new-instance v0, Lw7/p;

    .line 14
    .line 15
    const/16 v1, 0x1000

    .line 16
    .line 17
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lv9/z;->c:Lw7/p;

    .line 21
    .line 22
    new-instance v0, Landroid/util/SparseArray;

    .line 23
    .line 24
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lv9/z;->b:Landroid/util/SparseArray;

    .line 28
    .line 29
    new-instance v0, Lv9/x;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    invoke-direct {v0, v1}, Lv9/x;-><init>(I)V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lv9/z;->d:Lv9/x;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 8

    .line 1
    const/16 p0, 0xe

    .line 2
    .line 3
    new-array v0, p0, [B

    .line 4
    .line 5
    check-cast p1, Lo8/l;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-virtual {p1, v0, v1, p0, v1}, Lo8/l;->b([BIIZ)Z

    .line 9
    .line 10
    .line 11
    aget-byte p0, v0, v1

    .line 12
    .line 13
    and-int/lit16 p0, p0, 0xff

    .line 14
    .line 15
    shl-int/lit8 p0, p0, 0x18

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    aget-byte v3, v0, v2

    .line 19
    .line 20
    and-int/lit16 v3, v3, 0xff

    .line 21
    .line 22
    shl-int/lit8 v3, v3, 0x10

    .line 23
    .line 24
    or-int/2addr p0, v3

    .line 25
    const/4 v3, 0x2

    .line 26
    aget-byte v4, v0, v3

    .line 27
    .line 28
    and-int/lit16 v4, v4, 0xff

    .line 29
    .line 30
    const/16 v5, 0x8

    .line 31
    .line 32
    shl-int/2addr v4, v5

    .line 33
    or-int/2addr p0, v4

    .line 34
    const/4 v4, 0x3

    .line 35
    aget-byte v6, v0, v4

    .line 36
    .line 37
    and-int/lit16 v6, v6, 0xff

    .line 38
    .line 39
    or-int/2addr p0, v6

    .line 40
    const/16 v6, 0x1ba

    .line 41
    .line 42
    if-eq v6, p0, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const/4 p0, 0x4

    .line 46
    aget-byte v6, v0, p0

    .line 47
    .line 48
    and-int/lit16 v6, v6, 0xc4

    .line 49
    .line 50
    const/16 v7, 0x44

    .line 51
    .line 52
    if-eq v6, v7, :cond_1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    const/4 v6, 0x6

    .line 56
    aget-byte v6, v0, v6

    .line 57
    .line 58
    and-int/2addr v6, p0

    .line 59
    if-eq v6, p0, :cond_2

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    aget-byte v6, v0, v5

    .line 63
    .line 64
    and-int/2addr v6, p0

    .line 65
    if-eq v6, p0, :cond_3

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_3
    const/16 p0, 0x9

    .line 69
    .line 70
    aget-byte p0, v0, p0

    .line 71
    .line 72
    and-int/2addr p0, v2

    .line 73
    if-eq p0, v2, :cond_4

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_4
    const/16 p0, 0xc

    .line 77
    .line 78
    aget-byte p0, v0, p0

    .line 79
    .line 80
    and-int/2addr p0, v4

    .line 81
    if-eq p0, v4, :cond_5

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_5
    const/16 p0, 0xd

    .line 85
    .line 86
    aget-byte p0, v0, p0

    .line 87
    .line 88
    and-int/lit8 p0, p0, 0x7

    .line 89
    .line 90
    invoke-virtual {p1, p0, v1}, Lo8/l;->c(IZ)Z

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, v0, v1, v4, v1}, Lo8/l;->b([BIIZ)Z

    .line 94
    .line 95
    .line 96
    aget-byte p0, v0, v1

    .line 97
    .line 98
    and-int/lit16 p0, p0, 0xff

    .line 99
    .line 100
    shl-int/lit8 p0, p0, 0x10

    .line 101
    .line 102
    aget-byte p1, v0, v2

    .line 103
    .line 104
    and-int/lit16 p1, p1, 0xff

    .line 105
    .line 106
    shl-int/2addr p1, v5

    .line 107
    or-int/2addr p0, p1

    .line 108
    aget-byte p1, v0, v3

    .line 109
    .line 110
    and-int/lit16 p1, p1, 0xff

    .line 111
    .line 112
    or-int/2addr p0, p1

    .line 113
    if-ne v2, p0, :cond_6

    .line 114
    .line 115
    return v2

    .line 116
    :cond_6
    :goto_0
    return v1
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lv9/z;->j:Lo8/q;

    .line 2
    .line 3
    return-void
.end method

.method public final d(JJ)V
    .locals 7

    .line 1
    iget-object p1, p0, Lv9/z;->b:Landroid/util/SparseArray;

    .line 2
    .line 3
    iget-object p2, p0, Lv9/z;->a:Lw7/u;

    .line 4
    .line 5
    monitor-enter p2

    .line 6
    :try_start_0
    iget-wide v0, p2, Lw7/u;->b:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    monitor-exit p2

    .line 9
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    cmp-long v0, v0, v2

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    const/4 v4, 0x0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    move v0, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v4

    .line 23
    :goto_0
    if-nez v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {p2}, Lw7/u;->d()J

    .line 26
    .line 27
    .line 28
    move-result-wide v5

    .line 29
    cmp-long v0, v5, v2

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const-wide/16 v2, 0x0

    .line 34
    .line 35
    cmp-long v0, v5, v2

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    cmp-long v0, v5, p3

    .line 40
    .line 41
    if-eqz v0, :cond_1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v1, v4

    .line 45
    :goto_1
    move v0, v1

    .line 46
    :cond_2
    if-eqz v0, :cond_3

    .line 47
    .line 48
    invoke-virtual {p2, p3, p4}, Lw7/u;->e(J)V

    .line 49
    .line 50
    .line 51
    :cond_3
    iget-object p0, p0, Lv9/z;->i:Lt8/b;

    .line 52
    .line 53
    if-eqz p0, :cond_4

    .line 54
    .line 55
    invoke-virtual {p0, p3, p4}, Lo8/j;->B(J)V

    .line 56
    .line 57
    .line 58
    :cond_4
    move p0, v4

    .line 59
    :goto_2
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    if-ge p0, p2, :cond_5

    .line 64
    .line 65
    invoke-virtual {p1, p0}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    check-cast p2, Lv9/y;

    .line 70
    .line 71
    iput-boolean v4, p2, Lv9/y;->f:Z

    .line 72
    .line 73
    iget-object p2, p2, Lv9/y;->a:Lv9/h;

    .line 74
    .line 75
    invoke-interface {p2}, Lv9/h;->c()V

    .line 76
    .line 77
    .line 78
    add-int/lit8 p0, p0, 0x1

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_5
    return-void

    .line 82
    :catchall_0
    move-exception p0

    .line 83
    :try_start_1
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 84
    throw p0
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 26

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
    iget-object v3, v0, Lv9/z;->j:Lo8/q;

    .line 8
    .line 9
    invoke-static {v3}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 13
    .line 14
    .line 15
    move-result-wide v13

    .line 16
    const-wide/16 v18, -0x1

    .line 17
    .line 18
    cmp-long v3, v13, v18

    .line 19
    .line 20
    const/4 v4, 0x3

    .line 21
    const/16 v7, 0x1ba

    .line 22
    .line 23
    iget-object v8, v0, Lv9/z;->d:Lv9/x;

    .line 24
    .line 25
    const/4 v9, 0x4

    .line 26
    const/4 v10, 0x1

    .line 27
    const/4 v11, 0x0

    .line 28
    if-eqz v3, :cond_a

    .line 29
    .line 30
    iget-boolean v12, v8, Lv9/x;->d:Z

    .line 31
    .line 32
    if-nez v12, :cond_a

    .line 33
    .line 34
    iget-object v0, v8, Lv9/x;->b:Lw7/u;

    .line 35
    .line 36
    iget-object v3, v8, Lv9/x;->c:Lw7/p;

    .line 37
    .line 38
    iget-boolean v12, v8, Lv9/x;->f:Z

    .line 39
    .line 40
    const-wide/16 v13, 0x4e20

    .line 41
    .line 42
    if-nez v12, :cond_3

    .line 43
    .line 44
    const-wide v15, -0x7fffffffffffffffL    # -4.9E-324

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 50
    .line 51
    .line 52
    move-result-wide v5

    .line 53
    invoke-static {v13, v14, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 54
    .line 55
    .line 56
    move-result-wide v12

    .line 57
    long-to-int v0, v12

    .line 58
    int-to-long v12, v0

    .line 59
    sub-long/2addr v5, v12

    .line 60
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 61
    .line 62
    .line 63
    move-result-wide v12

    .line 64
    cmp-long v4, v12, v5

    .line 65
    .line 66
    if-eqz v4, :cond_0

    .line 67
    .line 68
    iput-wide v5, v2, Lo8/s;->a:J

    .line 69
    .line 70
    return v10

    .line 71
    :cond_0
    invoke-virtual {v3, v0}, Lw7/p;->F(I)V

    .line 72
    .line 73
    .line 74
    invoke-interface {v1}, Lo8/p;->e()V

    .line 75
    .line 76
    .line 77
    iget-object v2, v3, Lw7/p;->a:[B

    .line 78
    .line 79
    invoke-interface {v1, v2, v11, v0}, Lo8/p;->o([BII)V

    .line 80
    .line 81
    .line 82
    iget v0, v3, Lw7/p;->b:I

    .line 83
    .line 84
    iget v1, v3, Lw7/p;->c:I

    .line 85
    .line 86
    sub-int/2addr v1, v9

    .line 87
    :goto_0
    if-lt v1, v0, :cond_2

    .line 88
    .line 89
    iget-object v2, v3, Lw7/p;->a:[B

    .line 90
    .line 91
    invoke-static {v1, v2}, Lv9/x;->b(I[B)I

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    if-ne v2, v7, :cond_1

    .line 96
    .line 97
    add-int/lit8 v2, v1, 0x4

    .line 98
    .line 99
    invoke-virtual {v3, v2}, Lw7/p;->I(I)V

    .line 100
    .line 101
    .line 102
    invoke-static {v3}, Lv9/x;->c(Lw7/p;)J

    .line 103
    .line 104
    .line 105
    move-result-wide v4

    .line 106
    cmp-long v2, v4, v15

    .line 107
    .line 108
    if-eqz v2, :cond_1

    .line 109
    .line 110
    move-wide v5, v4

    .line 111
    goto :goto_1

    .line 112
    :cond_1
    add-int/lit8 v1, v1, -0x1

    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_2
    move-wide v5, v15

    .line 116
    :goto_1
    iput-wide v5, v8, Lv9/x;->h:J

    .line 117
    .line 118
    iput-boolean v10, v8, Lv9/x;->f:Z

    .line 119
    .line 120
    return v11

    .line 121
    :cond_3
    const-wide v15, -0x7fffffffffffffffL    # -4.9E-324

    .line 122
    .line 123
    .line 124
    .line 125
    .line 126
    iget-wide v5, v8, Lv9/x;->h:J

    .line 127
    .line 128
    cmp-long v5, v5, v15

    .line 129
    .line 130
    if-nez v5, :cond_4

    .line 131
    .line 132
    invoke-virtual {v8, v1}, Lv9/x;->a(Lo8/p;)V

    .line 133
    .line 134
    .line 135
    return v11

    .line 136
    :cond_4
    iget-boolean v5, v8, Lv9/x;->e:Z

    .line 137
    .line 138
    if-nez v5, :cond_8

    .line 139
    .line 140
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 141
    .line 142
    .line 143
    move-result-wide v5

    .line 144
    invoke-static {v13, v14, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 145
    .line 146
    .line 147
    move-result-wide v5

    .line 148
    long-to-int v0, v5

    .line 149
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 150
    .line 151
    .line 152
    move-result-wide v5

    .line 153
    int-to-long v12, v11

    .line 154
    cmp-long v5, v5, v12

    .line 155
    .line 156
    if-eqz v5, :cond_5

    .line 157
    .line 158
    iput-wide v12, v2, Lo8/s;->a:J

    .line 159
    .line 160
    return v10

    .line 161
    :cond_5
    invoke-virtual {v3, v0}, Lw7/p;->F(I)V

    .line 162
    .line 163
    .line 164
    invoke-interface {v1}, Lo8/p;->e()V

    .line 165
    .line 166
    .line 167
    iget-object v2, v3, Lw7/p;->a:[B

    .line 168
    .line 169
    invoke-interface {v1, v2, v11, v0}, Lo8/p;->o([BII)V

    .line 170
    .line 171
    .line 172
    iget v0, v3, Lw7/p;->b:I

    .line 173
    .line 174
    iget v1, v3, Lw7/p;->c:I

    .line 175
    .line 176
    :goto_2
    add-int/lit8 v2, v1, -0x3

    .line 177
    .line 178
    if-ge v0, v2, :cond_7

    .line 179
    .line 180
    iget-object v2, v3, Lw7/p;->a:[B

    .line 181
    .line 182
    invoke-static {v0, v2}, Lv9/x;->b(I[B)I

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    if-ne v2, v7, :cond_6

    .line 187
    .line 188
    add-int/lit8 v2, v0, 0x4

    .line 189
    .line 190
    invoke-virtual {v3, v2}, Lw7/p;->I(I)V

    .line 191
    .line 192
    .line 193
    invoke-static {v3}, Lv9/x;->c(Lw7/p;)J

    .line 194
    .line 195
    .line 196
    move-result-wide v5

    .line 197
    cmp-long v2, v5, v15

    .line 198
    .line 199
    if-eqz v2, :cond_6

    .line 200
    .line 201
    goto :goto_3

    .line 202
    :cond_6
    add-int/lit8 v0, v0, 0x1

    .line 203
    .line 204
    goto :goto_2

    .line 205
    :cond_7
    move-wide v5, v15

    .line 206
    :goto_3
    iput-wide v5, v8, Lv9/x;->g:J

    .line 207
    .line 208
    iput-boolean v10, v8, Lv9/x;->e:Z

    .line 209
    .line 210
    return v11

    .line 211
    :cond_8
    iget-wide v2, v8, Lv9/x;->g:J

    .line 212
    .line 213
    cmp-long v4, v2, v15

    .line 214
    .line 215
    if-nez v4, :cond_9

    .line 216
    .line 217
    invoke-virtual {v8, v1}, Lv9/x;->a(Lo8/p;)V

    .line 218
    .line 219
    .line 220
    return v11

    .line 221
    :cond_9
    invoke-virtual {v0, v2, v3}, Lw7/u;->b(J)J

    .line 222
    .line 223
    .line 224
    move-result-wide v2

    .line 225
    iget-wide v4, v8, Lv9/x;->h:J

    .line 226
    .line 227
    invoke-virtual {v0, v4, v5}, Lw7/u;->c(J)J

    .line 228
    .line 229
    .line 230
    move-result-wide v4

    .line 231
    sub-long/2addr v4, v2

    .line 232
    iput-wide v4, v8, Lv9/x;->i:J

    .line 233
    .line 234
    invoke-virtual {v8, v1}, Lv9/x;->a(Lo8/p;)V

    .line 235
    .line 236
    .line 237
    return v11

    .line 238
    :cond_a
    const-wide v15, -0x7fffffffffffffffL    # -4.9E-324

    .line 239
    .line 240
    .line 241
    .line 242
    .line 243
    iget-boolean v5, v0, Lv9/z;->k:Z

    .line 244
    .line 245
    if-nez v5, :cond_c

    .line 246
    .line 247
    iput-boolean v10, v0, Lv9/z;->k:Z

    .line 248
    .line 249
    iget-wide v5, v8, Lv9/x;->i:J

    .line 250
    .line 251
    cmp-long v12, v5, v15

    .line 252
    .line 253
    if-eqz v12, :cond_b

    .line 254
    .line 255
    move v12, v4

    .line 256
    new-instance v4, Lt8/b;

    .line 257
    .line 258
    iget-object v8, v8, Lv9/x;->b:Lw7/u;

    .line 259
    .line 260
    move-wide v15, v5

    .line 261
    new-instance v5, Lpy/a;

    .line 262
    .line 263
    const/16 v6, 0xa

    .line 264
    .line 265
    invoke-direct {v5, v6}, Lpy/a;-><init>(I)V

    .line 266
    .line 267
    .line 268
    new-instance v6, Lb81/a;

    .line 269
    .line 270
    invoke-direct {v6, v8}, Lb81/a;-><init>(Lw7/u;)V

    .line 271
    .line 272
    .line 273
    const-wide/16 v20, 0x1

    .line 274
    .line 275
    add-long v20, v15, v20

    .line 276
    .line 277
    move/from16 v17, v7

    .line 278
    .line 279
    move-wide v7, v15

    .line 280
    const-wide/16 v15, 0xbc

    .line 281
    .line 282
    move/from16 v22, v17

    .line 283
    .line 284
    const/16 v17, 0x3e8

    .line 285
    .line 286
    move/from16 v24, v11

    .line 287
    .line 288
    move/from16 v23, v12

    .line 289
    .line 290
    const-wide/16 v11, 0x0

    .line 291
    .line 292
    move/from16 v25, v3

    .line 293
    .line 294
    move v3, v9

    .line 295
    move-wide/from16 v9, v20

    .line 296
    .line 297
    invoke-direct/range {v4 .. v17}, Lo8/j;-><init>(Lo8/g;Lo8/i;JJJJJI)V

    .line 298
    .line 299
    .line 300
    iput-object v4, v0, Lv9/z;->i:Lt8/b;

    .line 301
    .line 302
    iget-object v5, v0, Lv9/z;->j:Lo8/q;

    .line 303
    .line 304
    iget-object v4, v4, Lo8/j;->c:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v4, Lo8/e;

    .line 307
    .line 308
    invoke-interface {v5, v4}, Lo8/q;->c(Lo8/c0;)V

    .line 309
    .line 310
    .line 311
    goto :goto_4

    .line 312
    :cond_b
    move/from16 v25, v3

    .line 313
    .line 314
    move-wide v7, v5

    .line 315
    move v3, v9

    .line 316
    iget-object v4, v0, Lv9/z;->j:Lo8/q;

    .line 317
    .line 318
    new-instance v5, Lo8/t;

    .line 319
    .line 320
    invoke-direct {v5, v7, v8}, Lo8/t;-><init>(J)V

    .line 321
    .line 322
    .line 323
    invoke-interface {v4, v5}, Lo8/q;->c(Lo8/c0;)V

    .line 324
    .line 325
    .line 326
    goto :goto_4

    .line 327
    :cond_c
    move/from16 v25, v3

    .line 328
    .line 329
    move v3, v9

    .line 330
    :goto_4
    iget-object v4, v0, Lv9/z;->i:Lt8/b;

    .line 331
    .line 332
    if-eqz v4, :cond_d

    .line 333
    .line 334
    iget-object v5, v4, Lo8/j;->e:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast v5, Lo8/f;

    .line 337
    .line 338
    if-eqz v5, :cond_d

    .line 339
    .line 340
    invoke-virtual {v4, v1, v2}, Lo8/j;->u(Lo8/p;Lo8/s;)I

    .line 341
    .line 342
    .line 343
    move-result v0

    .line 344
    return v0

    .line 345
    :cond_d
    invoke-interface {v1}, Lo8/p;->e()V

    .line 346
    .line 347
    .line 348
    if-eqz v25, :cond_e

    .line 349
    .line 350
    invoke-interface {v1}, Lo8/p;->h()J

    .line 351
    .line 352
    .line 353
    move-result-wide v4

    .line 354
    sub-long/2addr v13, v4

    .line 355
    goto :goto_5

    .line 356
    :cond_e
    move-wide/from16 v13, v18

    .line 357
    .line 358
    :goto_5
    cmp-long v2, v13, v18

    .line 359
    .line 360
    if-eqz v2, :cond_f

    .line 361
    .line 362
    const-wide/16 v4, 0x4

    .line 363
    .line 364
    cmp-long v2, v13, v4

    .line 365
    .line 366
    if-gez v2, :cond_f

    .line 367
    .line 368
    goto :goto_6

    .line 369
    :cond_f
    iget-object v2, v0, Lv9/z;->c:Lw7/p;

    .line 370
    .line 371
    iget-object v4, v2, Lw7/p;->a:[B

    .line 372
    .line 373
    const/4 v5, 0x1

    .line 374
    const/4 v6, 0x0

    .line 375
    invoke-interface {v1, v4, v6, v3, v5}, Lo8/p;->b([BIIZ)Z

    .line 376
    .line 377
    .line 378
    move-result v4

    .line 379
    if-nez v4, :cond_10

    .line 380
    .line 381
    goto :goto_6

    .line 382
    :cond_10
    invoke-virtual {v2, v6}, Lw7/p;->I(I)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 386
    .line 387
    .line 388
    move-result v4

    .line 389
    const/16 v7, 0x1b9

    .line 390
    .line 391
    if-ne v4, v7, :cond_11

    .line 392
    .line 393
    :goto_6
    const/4 v0, -0x1

    .line 394
    return v0

    .line 395
    :cond_11
    const/16 v7, 0x1ba

    .line 396
    .line 397
    if-ne v4, v7, :cond_12

    .line 398
    .line 399
    iget-object v0, v2, Lw7/p;->a:[B

    .line 400
    .line 401
    const/16 v3, 0xa

    .line 402
    .line 403
    invoke-interface {v1, v0, v6, v3}, Lo8/p;->o([BII)V

    .line 404
    .line 405
    .line 406
    const/16 v0, 0x9

    .line 407
    .line 408
    invoke-virtual {v2, v0}, Lw7/p;->I(I)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 412
    .line 413
    .line 414
    move-result v0

    .line 415
    and-int/lit8 v0, v0, 0x7

    .line 416
    .line 417
    add-int/lit8 v0, v0, 0xe

    .line 418
    .line 419
    invoke-interface {v1, v0}, Lo8/p;->n(I)V

    .line 420
    .line 421
    .line 422
    return v6

    .line 423
    :cond_12
    const/16 v7, 0x1bb

    .line 424
    .line 425
    const/4 v8, 0x2

    .line 426
    const/4 v9, 0x6

    .line 427
    if-ne v4, v7, :cond_13

    .line 428
    .line 429
    iget-object v0, v2, Lw7/p;->a:[B

    .line 430
    .line 431
    invoke-interface {v1, v0, v6, v8}, Lo8/p;->o([BII)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v2, v6}, Lw7/p;->I(I)V

    .line 435
    .line 436
    .line 437
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 438
    .line 439
    .line 440
    move-result v0

    .line 441
    add-int/2addr v0, v9

    .line 442
    invoke-interface {v1, v0}, Lo8/p;->n(I)V

    .line 443
    .line 444
    .line 445
    return v6

    .line 446
    :cond_13
    and-int/lit16 v7, v4, -0x100

    .line 447
    .line 448
    const/16 v10, 0x8

    .line 449
    .line 450
    shr-int/2addr v7, v10

    .line 451
    if-eq v7, v5, :cond_14

    .line 452
    .line 453
    invoke-interface {v1, v5}, Lo8/p;->n(I)V

    .line 454
    .line 455
    .line 456
    return v6

    .line 457
    :cond_14
    and-int/lit16 v7, v4, 0xff

    .line 458
    .line 459
    iget-object v11, v0, Lv9/z;->b:Landroid/util/SparseArray;

    .line 460
    .line 461
    invoke-virtual {v11, v7}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object v12

    .line 465
    check-cast v12, Lv9/y;

    .line 466
    .line 467
    iget-boolean v13, v0, Lv9/z;->e:Z

    .line 468
    .line 469
    if-nez v13, :cond_1a

    .line 470
    .line 471
    if-nez v12, :cond_18

    .line 472
    .line 473
    const/16 v13, 0xbd

    .line 474
    .line 475
    const-string v14, "video/mp2p"

    .line 476
    .line 477
    if-ne v7, v13, :cond_15

    .line 478
    .line 479
    new-instance v4, Lv9/b;

    .line 480
    .line 481
    invoke-direct {v4, v14}, Lv9/b;-><init>(Ljava/lang/String;)V

    .line 482
    .line 483
    .line 484
    iput-boolean v5, v0, Lv9/z;->f:Z

    .line 485
    .line 486
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 487
    .line 488
    .line 489
    move-result-wide v13

    .line 490
    iput-wide v13, v0, Lv9/z;->h:J

    .line 491
    .line 492
    goto :goto_7

    .line 493
    :cond_15
    and-int/lit16 v13, v4, 0xe0

    .line 494
    .line 495
    const/16 v15, 0xc0

    .line 496
    .line 497
    const/4 v3, 0x0

    .line 498
    if-ne v13, v15, :cond_16

    .line 499
    .line 500
    new-instance v4, Lv9/t;

    .line 501
    .line 502
    invoke-direct {v4, v3, v6, v14}, Lv9/t;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 503
    .line 504
    .line 505
    iput-boolean v5, v0, Lv9/z;->f:Z

    .line 506
    .line 507
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 508
    .line 509
    .line 510
    move-result-wide v13

    .line 511
    iput-wide v13, v0, Lv9/z;->h:J

    .line 512
    .line 513
    goto :goto_7

    .line 514
    :cond_16
    and-int/lit16 v4, v4, 0xf0

    .line 515
    .line 516
    const/16 v13, 0xe0

    .line 517
    .line 518
    if-ne v4, v13, :cond_17

    .line 519
    .line 520
    new-instance v4, Lv9/j;

    .line 521
    .line 522
    invoke-direct {v4, v3, v14}, Lv9/j;-><init>(Lv9/c0;Ljava/lang/String;)V

    .line 523
    .line 524
    .line 525
    iput-boolean v5, v0, Lv9/z;->g:Z

    .line 526
    .line 527
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 528
    .line 529
    .line 530
    move-result-wide v13

    .line 531
    iput-wide v13, v0, Lv9/z;->h:J

    .line 532
    .line 533
    goto :goto_7

    .line 534
    :cond_17
    move-object v4, v3

    .line 535
    :goto_7
    if-eqz v4, :cond_18

    .line 536
    .line 537
    new-instance v3, Lh11/h;

    .line 538
    .line 539
    const/16 v12, 0x100

    .line 540
    .line 541
    invoke-direct {v3, v7, v12}, Lh11/h;-><init>(II)V

    .line 542
    .line 543
    .line 544
    iget-object v12, v0, Lv9/z;->j:Lo8/q;

    .line 545
    .line 546
    invoke-interface {v4, v12, v3}, Lv9/h;->d(Lo8/q;Lh11/h;)V

    .line 547
    .line 548
    .line 549
    new-instance v12, Lv9/y;

    .line 550
    .line 551
    iget-object v3, v0, Lv9/z;->a:Lw7/u;

    .line 552
    .line 553
    invoke-direct {v12, v4, v3}, Lv9/y;-><init>(Lv9/h;Lw7/u;)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v11, v7, v12}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 557
    .line 558
    .line 559
    :cond_18
    iget-boolean v3, v0, Lv9/z;->f:Z

    .line 560
    .line 561
    if-eqz v3, :cond_19

    .line 562
    .line 563
    iget-boolean v3, v0, Lv9/z;->g:Z

    .line 564
    .line 565
    if-eqz v3, :cond_19

    .line 566
    .line 567
    iget-wide v3, v0, Lv9/z;->h:J

    .line 568
    .line 569
    const-wide/16 v13, 0x2000

    .line 570
    .line 571
    add-long/2addr v3, v13

    .line 572
    goto :goto_8

    .line 573
    :cond_19
    const-wide/32 v3, 0x100000

    .line 574
    .line 575
    .line 576
    :goto_8
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 577
    .line 578
    .line 579
    move-result-wide v13

    .line 580
    cmp-long v3, v13, v3

    .line 581
    .line 582
    if-lez v3, :cond_1a

    .line 583
    .line 584
    iput-boolean v5, v0, Lv9/z;->e:Z

    .line 585
    .line 586
    iget-object v0, v0, Lv9/z;->j:Lo8/q;

    .line 587
    .line 588
    invoke-interface {v0}, Lo8/q;->m()V

    .line 589
    .line 590
    .line 591
    :cond_1a
    iget-object v0, v2, Lw7/p;->a:[B

    .line 592
    .line 593
    invoke-interface {v1, v0, v6, v8}, Lo8/p;->o([BII)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {v2, v6}, Lw7/p;->I(I)V

    .line 597
    .line 598
    .line 599
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 600
    .line 601
    .line 602
    move-result v0

    .line 603
    add-int/2addr v0, v9

    .line 604
    if-nez v12, :cond_1b

    .line 605
    .line 606
    invoke-interface {v1, v0}, Lo8/p;->n(I)V

    .line 607
    .line 608
    .line 609
    return v6

    .line 610
    :cond_1b
    invoke-virtual {v2, v0}, Lw7/p;->F(I)V

    .line 611
    .line 612
    .line 613
    iget-object v3, v2, Lw7/p;->a:[B

    .line 614
    .line 615
    invoke-interface {v1, v3, v6, v0}, Lo8/p;->readFully([BII)V

    .line 616
    .line 617
    .line 618
    invoke-virtual {v2, v9}, Lw7/p;->I(I)V

    .line 619
    .line 620
    .line 621
    iget-object v0, v12, Lv9/y;->a:Lv9/h;

    .line 622
    .line 623
    iget-object v1, v12, Lv9/y;->c:Lm9/f;

    .line 624
    .line 625
    iget-object v3, v1, Lm9/f;->b:[B

    .line 626
    .line 627
    const/4 v4, 0x3

    .line 628
    invoke-virtual {v2, v3, v6, v4}, Lw7/p;->h([BII)V

    .line 629
    .line 630
    .line 631
    invoke-virtual {v1, v6}, Lm9/f;->q(I)V

    .line 632
    .line 633
    .line 634
    invoke-virtual {v1, v10}, Lm9/f;->t(I)V

    .line 635
    .line 636
    .line 637
    invoke-virtual {v1}, Lm9/f;->h()Z

    .line 638
    .line 639
    .line 640
    move-result v3

    .line 641
    iput-boolean v3, v12, Lv9/y;->d:Z

    .line 642
    .line 643
    invoke-virtual {v1}, Lm9/f;->h()Z

    .line 644
    .line 645
    .line 646
    move-result v3

    .line 647
    iput-boolean v3, v12, Lv9/y;->e:Z

    .line 648
    .line 649
    invoke-virtual {v1, v9}, Lm9/f;->t(I)V

    .line 650
    .line 651
    .line 652
    invoke-virtual {v1, v10}, Lm9/f;->i(I)I

    .line 653
    .line 654
    .line 655
    move-result v3

    .line 656
    iget-object v4, v1, Lm9/f;->b:[B

    .line 657
    .line 658
    invoke-virtual {v2, v4, v6, v3}, Lw7/p;->h([BII)V

    .line 659
    .line 660
    .line 661
    invoke-virtual {v1, v6}, Lm9/f;->q(I)V

    .line 662
    .line 663
    .line 664
    iget-object v3, v12, Lv9/y;->b:Lw7/u;

    .line 665
    .line 666
    const-wide/16 v7, 0x0

    .line 667
    .line 668
    iput-wide v7, v12, Lv9/y;->g:J

    .line 669
    .line 670
    iget-boolean v4, v12, Lv9/y;->d:Z

    .line 671
    .line 672
    if-eqz v4, :cond_1d

    .line 673
    .line 674
    const/4 v4, 0x4

    .line 675
    invoke-virtual {v1, v4}, Lm9/f;->t(I)V

    .line 676
    .line 677
    .line 678
    const/4 v4, 0x3

    .line 679
    invoke-virtual {v1, v4}, Lm9/f;->i(I)I

    .line 680
    .line 681
    .line 682
    move-result v7

    .line 683
    int-to-long v7, v7

    .line 684
    const/16 v4, 0x1e

    .line 685
    .line 686
    shl-long/2addr v7, v4

    .line 687
    invoke-virtual {v1, v5}, Lm9/f;->t(I)V

    .line 688
    .line 689
    .line 690
    const/16 v9, 0xf

    .line 691
    .line 692
    invoke-virtual {v1, v9}, Lm9/f;->i(I)I

    .line 693
    .line 694
    .line 695
    move-result v10

    .line 696
    shl-int/2addr v10, v9

    .line 697
    int-to-long v10, v10

    .line 698
    or-long/2addr v7, v10

    .line 699
    invoke-virtual {v1, v5}, Lm9/f;->t(I)V

    .line 700
    .line 701
    .line 702
    invoke-virtual {v1, v9}, Lm9/f;->i(I)I

    .line 703
    .line 704
    .line 705
    move-result v10

    .line 706
    int-to-long v10, v10

    .line 707
    or-long/2addr v7, v10

    .line 708
    invoke-virtual {v1, v5}, Lm9/f;->t(I)V

    .line 709
    .line 710
    .line 711
    iget-boolean v10, v12, Lv9/y;->f:Z

    .line 712
    .line 713
    if-nez v10, :cond_1c

    .line 714
    .line 715
    iget-boolean v10, v12, Lv9/y;->e:Z

    .line 716
    .line 717
    if-eqz v10, :cond_1c

    .line 718
    .line 719
    const/4 v10, 0x4

    .line 720
    invoke-virtual {v1, v10}, Lm9/f;->t(I)V

    .line 721
    .line 722
    .line 723
    const/4 v10, 0x3

    .line 724
    invoke-virtual {v1, v10}, Lm9/f;->i(I)I

    .line 725
    .line 726
    .line 727
    move-result v10

    .line 728
    int-to-long v10, v10

    .line 729
    shl-long/2addr v10, v4

    .line 730
    invoke-virtual {v1, v5}, Lm9/f;->t(I)V

    .line 731
    .line 732
    .line 733
    invoke-virtual {v1, v9}, Lm9/f;->i(I)I

    .line 734
    .line 735
    .line 736
    move-result v4

    .line 737
    shl-int/2addr v4, v9

    .line 738
    int-to-long v13, v4

    .line 739
    or-long/2addr v10, v13

    .line 740
    invoke-virtual {v1, v5}, Lm9/f;->t(I)V

    .line 741
    .line 742
    .line 743
    invoke-virtual {v1, v9}, Lm9/f;->i(I)I

    .line 744
    .line 745
    .line 746
    move-result v4

    .line 747
    int-to-long v13, v4

    .line 748
    or-long v9, v10, v13

    .line 749
    .line 750
    invoke-virtual {v1, v5}, Lm9/f;->t(I)V

    .line 751
    .line 752
    .line 753
    invoke-virtual {v3, v9, v10}, Lw7/u;->b(J)J

    .line 754
    .line 755
    .line 756
    iput-boolean v5, v12, Lv9/y;->f:Z

    .line 757
    .line 758
    :cond_1c
    invoke-virtual {v3, v7, v8}, Lw7/u;->b(J)J

    .line 759
    .line 760
    .line 761
    move-result-wide v3

    .line 762
    iput-wide v3, v12, Lv9/y;->g:J

    .line 763
    .line 764
    :cond_1d
    iget-wide v3, v12, Lv9/y;->g:J

    .line 765
    .line 766
    const/4 v10, 0x4

    .line 767
    invoke-interface {v0, v10, v3, v4}, Lv9/h;->f(IJ)V

    .line 768
    .line 769
    .line 770
    invoke-interface {v0, v2}, Lv9/h;->b(Lw7/p;)V

    .line 771
    .line 772
    .line 773
    invoke-interface {v0, v6}, Lv9/h;->e(Z)V

    .line 774
    .line 775
    .line 776
    iget-object v0, v2, Lw7/p;->a:[B

    .line 777
    .line 778
    array-length v0, v0

    .line 779
    invoke-virtual {v2, v0}, Lw7/p;->H(I)V

    .line 780
    .line 781
    .line 782
    return v6
.end method
