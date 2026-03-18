.class public final Lh8/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/y0;


# instance fields
.field public final d:I

.field public final synthetic e:Lh8/r0;


# direct methods
.method public constructor <init>(Lh8/r0;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/p0;->e:Lh8/r0;

    .line 5
    .line 6
    iput p2, p0, Lh8/p0;->d:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lh8/p0;->e:Lh8/r0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lh8/r0;->E()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    iget-object v1, v0, Lh8/r0;->w:[Lh8/x0;

    .line 10
    .line 11
    iget p0, p0, Lh8/p0;->d:I

    .line 12
    .line 13
    aget-object p0, v1, p0

    .line 14
    .line 15
    iget-boolean v0, v0, Lh8/r0;->Q:Z

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lh8/x0;->i(Z)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public final c()V
    .locals 3

    .line 1
    iget v0, p0, Lh8/p0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lh8/p0;->e:Lh8/r0;

    .line 4
    .line 5
    iget-object v1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 6
    .line 7
    aget-object v0, v1, v0

    .line 8
    .line 9
    iget-object v1, v0, Lh8/x0;->h:Laq/a;

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {v1}, Laq/a;->w()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v1, v2, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget-object p0, v0, Lh8/x0;->h:Laq/a;

    .line 22
    .line 23
    invoke-virtual {p0}, Laq/a;->n()Ld8/d;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    iget-object v0, p0, Lh8/r0;->o:Lk8/l;

    .line 32
    .line 33
    iget-object v1, p0, Lh8/r0;->g:Lmb/e;

    .line 34
    .line 35
    iget p0, p0, Lh8/r0;->G:I

    .line 36
    .line 37
    invoke-virtual {v1, p0}, Lmb/e;->q(I)I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    iget-object v1, v0, Lk8/l;->c:Ljava/io/IOException;

    .line 42
    .line 43
    if-nez v1, :cond_5

    .line 44
    .line 45
    iget-object v0, v0, Lk8/l;->b:Lk8/i;

    .line 46
    .line 47
    if-eqz v0, :cond_4

    .line 48
    .line 49
    const/high16 v1, -0x80000000

    .line 50
    .line 51
    if-ne p0, v1, :cond_2

    .line 52
    .line 53
    iget p0, v0, Lk8/i;->d:I

    .line 54
    .line 55
    :cond_2
    iget-object v1, v0, Lk8/i;->g:Ljava/io/IOException;

    .line 56
    .line 57
    if-eqz v1, :cond_4

    .line 58
    .line 59
    iget v0, v0, Lk8/i;->h:I

    .line 60
    .line 61
    if-gt v0, p0, :cond_3

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    throw v1

    .line 65
    :cond_4
    :goto_1
    return-void

    .line 66
    :cond_5
    throw v1
.end method

.method public final d(Lb81/d;Lz7/e;I)I
    .locals 16

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
    iget-object v3, v0, Lh8/p0;->e:Lh8/r0;

    .line 8
    .line 9
    iget v0, v0, Lh8/p0;->d:I

    .line 10
    .line 11
    invoke-virtual {v3}, Lh8/r0;->E()Z

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const/4 v5, -0x3

    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    return v5

    .line 19
    :cond_0
    invoke-virtual {v3, v0}, Lh8/r0;->z(I)V

    .line 20
    .line 21
    .line 22
    iget-object v4, v3, Lh8/r0;->w:[Lh8/x0;

    .line 23
    .line 24
    aget-object v4, v4, v0

    .line 25
    .line 26
    iget-boolean v6, v3, Lh8/r0;->Q:Z

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    and-int/lit8 v7, p3, 0x2

    .line 32
    .line 33
    const/4 v8, 0x1

    .line 34
    const/4 v9, 0x0

    .line 35
    if-eqz v7, :cond_1

    .line 36
    .line 37
    move v7, v8

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    move v7, v9

    .line 40
    :goto_0
    iget-object v10, v4, Lh8/x0;->b:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 41
    .line 42
    monitor-enter v4

    .line 43
    :try_start_0
    iput-boolean v9, v2, Lz7/e;->i:Z

    .line 44
    .line 45
    iget v11, v4, Lh8/x0;->s:I

    .line 46
    .line 47
    iget v12, v4, Lh8/x0;->p:I

    .line 48
    .line 49
    if-eq v11, v12, :cond_2

    .line 50
    .line 51
    move v12, v8

    .line 52
    goto :goto_1

    .line 53
    :cond_2
    move v12, v9

    .line 54
    :goto_1
    const/4 v13, -0x4

    .line 55
    const/4 v14, 0x4

    .line 56
    const/4 v15, -0x5

    .line 57
    if-nez v12, :cond_7

    .line 58
    .line 59
    if-nez v6, :cond_6

    .line 60
    .line 61
    iget-boolean v6, v4, Lh8/x0;->w:Z

    .line 62
    .line 63
    if-eqz v6, :cond_3

    .line 64
    .line 65
    goto :goto_4

    .line 66
    :cond_3
    iget-object v6, v4, Lh8/x0;->z:Lt7/o;

    .line 67
    .line 68
    if-eqz v6, :cond_5

    .line 69
    .line 70
    if-nez v7, :cond_4

    .line 71
    .line 72
    iget-object v7, v4, Lh8/x0;->g:Lt7/o;

    .line 73
    .line 74
    if-eq v6, v7, :cond_5

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :catchall_0
    move-exception v0

    .line 78
    goto/16 :goto_a

    .line 79
    .line 80
    :cond_4
    :goto_2
    invoke-virtual {v4, v6, v1}, Lh8/x0;->k(Lt7/o;Lb81/d;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 81
    .line 82
    .line 83
    monitor-exit v4

    .line 84
    goto :goto_7

    .line 85
    :cond_5
    monitor-exit v4

    .line 86
    :goto_3
    move v15, v5

    .line 87
    goto :goto_7

    .line 88
    :cond_6
    :goto_4
    :try_start_1
    iput v14, v2, Lkq/d;->e:I

    .line 89
    .line 90
    const-wide/high16 v6, -0x8000000000000000L

    .line 91
    .line 92
    iput-wide v6, v2, Lz7/e;->j:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 93
    .line 94
    monitor-exit v4

    .line 95
    :goto_5
    move v15, v13

    .line 96
    goto :goto_7

    .line 97
    :cond_7
    :try_start_2
    iget-object v12, v4, Lh8/x0;->c:Lbb/g0;

    .line 98
    .line 99
    iget v9, v4, Lh8/x0;->q:I

    .line 100
    .line 101
    add-int/2addr v9, v11

    .line 102
    invoke-virtual {v12, v9}, Lbb/g0;->g(I)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    check-cast v9, Lh8/w0;

    .line 107
    .line 108
    iget-object v9, v9, Lh8/w0;->a:Lt7/o;

    .line 109
    .line 110
    if-nez v7, :cond_c

    .line 111
    .line 112
    iget-object v7, v4, Lh8/x0;->g:Lt7/o;

    .line 113
    .line 114
    if-eq v9, v7, :cond_8

    .line 115
    .line 116
    goto :goto_6

    .line 117
    :cond_8
    iget v1, v4, Lh8/x0;->s:I

    .line 118
    .line 119
    invoke-virtual {v4, v1}, Lh8/x0;->h(I)I

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    invoke-virtual {v4, v1}, Lh8/x0;->j(I)Z

    .line 124
    .line 125
    .line 126
    move-result v7

    .line 127
    if-nez v7, :cond_9

    .line 128
    .line 129
    iput-boolean v8, v2, Lz7/e;->i:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 130
    .line 131
    monitor-exit v4

    .line 132
    goto :goto_3

    .line 133
    :cond_9
    :try_start_3
    iget-object v7, v4, Lh8/x0;->m:[I

    .line 134
    .line 135
    aget v7, v7, v1

    .line 136
    .line 137
    iput v7, v2, Lkq/d;->e:I

    .line 138
    .line 139
    iget v7, v4, Lh8/x0;->s:I

    .line 140
    .line 141
    iget v9, v4, Lh8/x0;->p:I

    .line 142
    .line 143
    sub-int/2addr v9, v8

    .line 144
    if-ne v7, v9, :cond_b

    .line 145
    .line 146
    if-nez v6, :cond_a

    .line 147
    .line 148
    iget-boolean v6, v4, Lh8/x0;->w:Z

    .line 149
    .line 150
    if-eqz v6, :cond_b

    .line 151
    .line 152
    :cond_a
    const/high16 v6, 0x20000000

    .line 153
    .line 154
    invoke-virtual {v2, v6}, Lkq/d;->a(I)V

    .line 155
    .line 156
    .line 157
    :cond_b
    iget-object v6, v4, Lh8/x0;->n:[J

    .line 158
    .line 159
    aget-wide v6, v6, v1

    .line 160
    .line 161
    iput-wide v6, v2, Lz7/e;->j:J

    .line 162
    .line 163
    iget-object v6, v4, Lh8/x0;->l:[I

    .line 164
    .line 165
    aget v6, v6, v1

    .line 166
    .line 167
    iput v6, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 168
    .line 169
    iget-object v6, v4, Lh8/x0;->k:[J

    .line 170
    .line 171
    aget-wide v6, v6, v1

    .line 172
    .line 173
    iput-wide v6, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 174
    .line 175
    iget-object v6, v4, Lh8/x0;->o:[Lo8/h0;

    .line 176
    .line 177
    aget-object v1, v6, v1

    .line 178
    .line 179
    iput-object v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 180
    .line 181
    monitor-exit v4

    .line 182
    goto :goto_5

    .line 183
    :cond_c
    :goto_6
    :try_start_4
    invoke-virtual {v4, v9, v1}, Lh8/x0;->k(Lt7/o;Lb81/d;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 184
    .line 185
    .line 186
    monitor-exit v4

    .line 187
    :goto_7
    if-ne v15, v13, :cond_10

    .line 188
    .line 189
    invoke-virtual {v2, v14}, Lkq/d;->c(I)Z

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-nez v1, :cond_10

    .line 194
    .line 195
    and-int/lit8 v1, p3, 0x1

    .line 196
    .line 197
    if-eqz v1, :cond_d

    .line 198
    .line 199
    move v9, v8

    .line 200
    goto :goto_8

    .line 201
    :cond_d
    const/4 v9, 0x0

    .line 202
    :goto_8
    and-int/lit8 v1, p3, 0x4

    .line 203
    .line 204
    if-nez v1, :cond_f

    .line 205
    .line 206
    if-eqz v9, :cond_e

    .line 207
    .line 208
    iget-object v1, v4, Lh8/x0;->a:Lh8/v0;

    .line 209
    .line 210
    iget-object v6, v4, Lh8/x0;->b:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 211
    .line 212
    iget-object v7, v1, Lh8/v0;->e:Lc1/i2;

    .line 213
    .line 214
    iget-object v1, v1, Lh8/v0;->c:Lw7/p;

    .line 215
    .line 216
    invoke-static {v7, v2, v6, v1}, Lh8/v0;->e(Lc1/i2;Lz7/e;Lcom/google/crypto/tink/shaded/protobuf/d;Lw7/p;)Lc1/i2;

    .line 217
    .line 218
    .line 219
    goto :goto_9

    .line 220
    :cond_e
    iget-object v1, v4, Lh8/x0;->a:Lh8/v0;

    .line 221
    .line 222
    iget-object v6, v4, Lh8/x0;->b:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 223
    .line 224
    iget-object v7, v1, Lh8/v0;->e:Lc1/i2;

    .line 225
    .line 226
    iget-object v10, v1, Lh8/v0;->c:Lw7/p;

    .line 227
    .line 228
    invoke-static {v7, v2, v6, v10}, Lh8/v0;->e(Lc1/i2;Lz7/e;Lcom/google/crypto/tink/shaded/protobuf/d;Lw7/p;)Lc1/i2;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    iput-object v2, v1, Lh8/v0;->e:Lc1/i2;

    .line 233
    .line 234
    :cond_f
    :goto_9
    if-nez v9, :cond_10

    .line 235
    .line 236
    iget v1, v4, Lh8/x0;->s:I

    .line 237
    .line 238
    add-int/2addr v1, v8

    .line 239
    iput v1, v4, Lh8/x0;->s:I

    .line 240
    .line 241
    :cond_10
    if-ne v15, v5, :cond_11

    .line 242
    .line 243
    invoke-virtual {v3, v0}, Lh8/r0;->A(I)V

    .line 244
    .line 245
    .line 246
    :cond_11
    return v15

    .line 247
    :goto_a
    :try_start_5
    monitor-exit v4
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 248
    throw v0
.end method

.method public final l(J)I
    .locals 10

    .line 1
    iget-object v0, p0, Lh8/p0;->e:Lh8/r0;

    .line 2
    .line 3
    iget p0, p0, Lh8/p0;->d:I

    .line 4
    .line 5
    invoke-virtual {v0}, Lh8/r0;->E()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    return v2

    .line 13
    :cond_0
    invoke-virtual {v0, p0}, Lh8/r0;->z(I)V

    .line 14
    .line 15
    .line 16
    iget-object v1, v0, Lh8/r0;->w:[Lh8/x0;

    .line 17
    .line 18
    aget-object v3, v1, p0

    .line 19
    .line 20
    iget-boolean v1, v0, Lh8/r0;->Q:Z

    .line 21
    .line 22
    monitor-enter v3

    .line 23
    :try_start_0
    iget v4, v3, Lh8/x0;->s:I

    .line 24
    .line 25
    invoke-virtual {v3, v4}, Lh8/x0;->h(I)I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    iget v4, v3, Lh8/x0;->s:I

    .line 30
    .line 31
    iget v5, v3, Lh8/x0;->p:I

    .line 32
    .line 33
    const/4 v9, 0x1

    .line 34
    if-eq v4, v5, :cond_1

    .line 35
    .line 36
    move v7, v9

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    move v7, v2

    .line 39
    :goto_0
    if-eqz v7, :cond_5

    .line 40
    .line 41
    iget-object v7, v3, Lh8/x0;->n:[J

    .line 42
    .line 43
    aget-wide v7, v7, v6

    .line 44
    .line 45
    cmp-long v7, p1, v7

    .line 46
    .line 47
    if-gez v7, :cond_2

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    iget-wide v7, v3, Lh8/x0;->v:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    cmp-long v7, p1, v7

    .line 53
    .line 54
    if-lez v7, :cond_3

    .line 55
    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    sub-int/2addr v5, v4

    .line 59
    monitor-exit v3

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    sub-int v7, v5, v4

    .line 62
    .line 63
    const/4 v8, 0x1

    .line 64
    move-wide v4, p1

    .line 65
    :try_start_1
    invoke-virtual/range {v3 .. v8}, Lh8/x0;->g(JIIZ)I

    .line 66
    .line 67
    .line 68
    move-result v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 69
    const/4 p1, -0x1

    .line 70
    if-ne v5, p1, :cond_4

    .line 71
    .line 72
    monitor-exit v3

    .line 73
    :goto_1
    move v5, v2

    .line 74
    goto :goto_3

    .line 75
    :cond_4
    monitor-exit v3

    .line 76
    goto :goto_3

    .line 77
    :catchall_0
    move-exception v0

    .line 78
    move-object p0, v0

    .line 79
    goto :goto_6

    .line 80
    :cond_5
    :goto_2
    monitor-exit v3

    .line 81
    goto :goto_1

    .line 82
    :goto_3
    monitor-enter v3

    .line 83
    if-ltz v5, :cond_6

    .line 84
    .line 85
    :try_start_2
    iget p1, v3, Lh8/x0;->s:I

    .line 86
    .line 87
    add-int/2addr p1, v5

    .line 88
    iget p2, v3, Lh8/x0;->p:I

    .line 89
    .line 90
    if-gt p1, p2, :cond_6

    .line 91
    .line 92
    move v2, v9

    .line 93
    goto :goto_4

    .line 94
    :catchall_1
    move-exception v0

    .line 95
    move-object p0, v0

    .line 96
    goto :goto_5

    .line 97
    :cond_6
    :goto_4
    invoke-static {v2}, Lw7/a;->c(Z)V

    .line 98
    .line 99
    .line 100
    iget p1, v3, Lh8/x0;->s:I

    .line 101
    .line 102
    add-int/2addr p1, v5

    .line 103
    iput p1, v3, Lh8/x0;->s:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 104
    .line 105
    monitor-exit v3

    .line 106
    if-nez v5, :cond_7

    .line 107
    .line 108
    invoke-virtual {v0, p0}, Lh8/r0;->A(I)V

    .line 109
    .line 110
    .line 111
    :cond_7
    return v5

    .line 112
    :goto_5
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 113
    throw p0

    .line 114
    :goto_6
    :try_start_4
    monitor-exit v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 115
    throw p0
.end method
