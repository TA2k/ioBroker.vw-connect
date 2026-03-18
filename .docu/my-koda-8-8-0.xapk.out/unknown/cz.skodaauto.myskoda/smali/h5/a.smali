.class public final Lh5/a;
.super Lh5/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public t0:I

.field public u0:Z

.field public v0:I

.field public w0:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Lh5/i;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lh5/a;->t0:I

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iput-boolean v1, p0, Lh5/a;->u0:Z

    .line 9
    .line 10
    iput v0, p0, Lh5/a;->v0:I

    .line 11
    .line 12
    iput-boolean v0, p0, Lh5/a;->w0:Z

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final B()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lh5/a;->w0:Z

    .line 2
    .line 3
    return p0
.end method

.method public final C()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lh5/a;->w0:Z

    .line 2
    .line 3
    return p0
.end method

.method public final Y()Z
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v3, v0

    .line 4
    move v2, v1

    .line 5
    :goto_0
    iget v4, p0, Lh5/i;->s0:I

    .line 6
    .line 7
    const/4 v5, 0x3

    .line 8
    const/4 v6, 0x2

    .line 9
    if-ge v2, v4, :cond_5

    .line 10
    .line 11
    iget-object v4, p0, Lh5/i;->r0:[Lh5/d;

    .line 12
    .line 13
    aget-object v4, v4, v2

    .line 14
    .line 15
    iget-boolean v7, p0, Lh5/a;->u0:Z

    .line 16
    .line 17
    if-nez v7, :cond_0

    .line 18
    .line 19
    invoke-virtual {v4}, Lh5/d;->d()Z

    .line 20
    .line 21
    .line 22
    move-result v7

    .line 23
    if-nez v7, :cond_0

    .line 24
    .line 25
    goto :goto_2

    .line 26
    :cond_0
    iget v7, p0, Lh5/a;->t0:I

    .line 27
    .line 28
    if-eqz v7, :cond_1

    .line 29
    .line 30
    if-ne v7, v0, :cond_2

    .line 31
    .line 32
    :cond_1
    invoke-virtual {v4}, Lh5/d;->B()Z

    .line 33
    .line 34
    .line 35
    move-result v7

    .line 36
    if-nez v7, :cond_2

    .line 37
    .line 38
    :goto_1
    move v3, v1

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    iget v7, p0, Lh5/a;->t0:I

    .line 41
    .line 42
    if-eq v7, v6, :cond_3

    .line 43
    .line 44
    if-ne v7, v5, :cond_4

    .line 45
    .line 46
    :cond_3
    invoke-virtual {v4}, Lh5/d;->C()Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-nez v4, :cond_4

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_4
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_5
    if-eqz v3, :cond_13

    .line 57
    .line 58
    if-lez v4, :cond_13

    .line 59
    .line 60
    move v2, v1

    .line 61
    move v3, v2

    .line 62
    :goto_3
    iget v4, p0, Lh5/i;->s0:I

    .line 63
    .line 64
    if-ge v1, v4, :cond_10

    .line 65
    .line 66
    iget-object v4, p0, Lh5/i;->r0:[Lh5/d;

    .line 67
    .line 68
    aget-object v4, v4, v1

    .line 69
    .line 70
    iget-boolean v7, p0, Lh5/a;->u0:Z

    .line 71
    .line 72
    if-nez v7, :cond_6

    .line 73
    .line 74
    invoke-virtual {v4}, Lh5/d;->d()Z

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    if-nez v7, :cond_6

    .line 79
    .line 80
    goto/16 :goto_5

    .line 81
    .line 82
    :cond_6
    const/4 v7, 0x5

    .line 83
    const/4 v8, 0x4

    .line 84
    if-nez v3, :cond_b

    .line 85
    .line 86
    iget v3, p0, Lh5/a;->t0:I

    .line 87
    .line 88
    if-nez v3, :cond_7

    .line 89
    .line 90
    invoke-virtual {v4, v6}, Lh5/d;->j(I)Lh5/c;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-virtual {v2}, Lh5/c;->d()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    goto :goto_4

    .line 99
    :cond_7
    if-ne v3, v0, :cond_8

    .line 100
    .line 101
    invoke-virtual {v4, v8}, Lh5/d;->j(I)Lh5/c;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    invoke-virtual {v2}, Lh5/c;->d()I

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    goto :goto_4

    .line 110
    :cond_8
    if-ne v3, v6, :cond_9

    .line 111
    .line 112
    invoke-virtual {v4, v5}, Lh5/d;->j(I)Lh5/c;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-virtual {v2}, Lh5/c;->d()I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    goto :goto_4

    .line 121
    :cond_9
    if-ne v3, v5, :cond_a

    .line 122
    .line 123
    invoke-virtual {v4, v7}, Lh5/d;->j(I)Lh5/c;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    invoke-virtual {v2}, Lh5/c;->d()I

    .line 128
    .line 129
    .line 130
    move-result v2

    .line 131
    :cond_a
    :goto_4
    move v3, v0

    .line 132
    :cond_b
    iget v9, p0, Lh5/a;->t0:I

    .line 133
    .line 134
    if-nez v9, :cond_c

    .line 135
    .line 136
    invoke-virtual {v4, v6}, Lh5/d;->j(I)Lh5/c;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    invoke-virtual {v4}, Lh5/c;->d()I

    .line 141
    .line 142
    .line 143
    move-result v4

    .line 144
    invoke-static {v2, v4}, Ljava/lang/Math;->min(II)I

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    goto :goto_5

    .line 149
    :cond_c
    if-ne v9, v0, :cond_d

    .line 150
    .line 151
    invoke-virtual {v4, v8}, Lh5/d;->j(I)Lh5/c;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    invoke-virtual {v4}, Lh5/c;->d()I

    .line 156
    .line 157
    .line 158
    move-result v4

    .line 159
    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    goto :goto_5

    .line 164
    :cond_d
    if-ne v9, v6, :cond_e

    .line 165
    .line 166
    invoke-virtual {v4, v5}, Lh5/d;->j(I)Lh5/c;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    invoke-virtual {v4}, Lh5/c;->d()I

    .line 171
    .line 172
    .line 173
    move-result v4

    .line 174
    invoke-static {v2, v4}, Ljava/lang/Math;->min(II)I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    goto :goto_5

    .line 179
    :cond_e
    if-ne v9, v5, :cond_f

    .line 180
    .line 181
    invoke-virtual {v4, v7}, Lh5/d;->j(I)Lh5/c;

    .line 182
    .line 183
    .line 184
    move-result-object v4

    .line 185
    invoke-virtual {v4}, Lh5/c;->d()I

    .line 186
    .line 187
    .line 188
    move-result v4

    .line 189
    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    .line 190
    .line 191
    .line 192
    move-result v2

    .line 193
    :cond_f
    :goto_5
    add-int/lit8 v1, v1, 0x1

    .line 194
    .line 195
    goto/16 :goto_3

    .line 196
    .line 197
    :cond_10
    iget v1, p0, Lh5/a;->v0:I

    .line 198
    .line 199
    add-int/2addr v2, v1

    .line 200
    iget v1, p0, Lh5/a;->t0:I

    .line 201
    .line 202
    if-eqz v1, :cond_12

    .line 203
    .line 204
    if-ne v1, v0, :cond_11

    .line 205
    .line 206
    goto :goto_6

    .line 207
    :cond_11
    invoke-virtual {p0, v2, v2}, Lh5/d;->M(II)V

    .line 208
    .line 209
    .line 210
    goto :goto_7

    .line 211
    :cond_12
    :goto_6
    invoke-virtual {p0, v2, v2}, Lh5/d;->L(II)V

    .line 212
    .line 213
    .line 214
    :goto_7
    iput-boolean v0, p0, Lh5/a;->w0:Z

    .line 215
    .line 216
    return v0

    .line 217
    :cond_13
    return v1
.end method

.method public final Z()I
    .locals 2

    .line 1
    iget p0, p0, Lh5/a;->t0:I

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    if-eq p0, v0, :cond_1

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    if-eq p0, v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    if-eq p0, v1, :cond_0

    .line 13
    .line 14
    const/4 p0, -0x1

    .line 15
    return p0

    .line 16
    :cond_0
    return v0

    .line 17
    :cond_1
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final c(La5/c;Z)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lh5/d;->R:[Lh5/c;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    iget-object v4, v0, Lh5/d;->J:Lh5/c;

    .line 9
    .line 10
    aput-object v4, v2, v3

    .line 11
    .line 12
    const/4 v5, 0x2

    .line 13
    iget-object v6, v0, Lh5/d;->K:Lh5/c;

    .line 14
    .line 15
    aput-object v6, v2, v5

    .line 16
    .line 17
    const/4 v7, 0x1

    .line 18
    iget-object v8, v0, Lh5/d;->L:Lh5/c;

    .line 19
    .line 20
    aput-object v8, v2, v7

    .line 21
    .line 22
    const/4 v9, 0x3

    .line 23
    iget-object v10, v0, Lh5/d;->M:Lh5/c;

    .line 24
    .line 25
    aput-object v10, v2, v9

    .line 26
    .line 27
    move v11, v3

    .line 28
    :goto_0
    array-length v12, v2

    .line 29
    if-ge v11, v12, :cond_0

    .line 30
    .line 31
    aget-object v12, v2, v11

    .line 32
    .line 33
    invoke-virtual {v1, v12}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 34
    .line 35
    .line 36
    move-result-object v13

    .line 37
    iput-object v13, v12, Lh5/c;->i:La5/h;

    .line 38
    .line 39
    add-int/lit8 v11, v11, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget v11, v0, Lh5/a;->t0:I

    .line 43
    .line 44
    if-ltz v11, :cond_1e

    .line 45
    .line 46
    const/4 v12, 0x4

    .line 47
    if-ge v11, v12, :cond_1e

    .line 48
    .line 49
    aget-object v2, v2, v11

    .line 50
    .line 51
    iget-boolean v11, v0, Lh5/a;->w0:Z

    .line 52
    .line 53
    if-nez v11, :cond_1

    .line 54
    .line 55
    invoke-virtual {v0}, Lh5/a;->Y()Z

    .line 56
    .line 57
    .line 58
    :cond_1
    iget-boolean v11, v0, Lh5/a;->w0:Z

    .line 59
    .line 60
    if-eqz v11, :cond_5

    .line 61
    .line 62
    iput-boolean v3, v0, Lh5/a;->w0:Z

    .line 63
    .line 64
    iget v2, v0, Lh5/a;->t0:I

    .line 65
    .line 66
    if-eqz v2, :cond_4

    .line 67
    .line 68
    if-ne v2, v7, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    if-eq v2, v5, :cond_3

    .line 72
    .line 73
    if-ne v2, v9, :cond_1e

    .line 74
    .line 75
    :cond_3
    iget-object v2, v6, Lh5/c;->i:La5/h;

    .line 76
    .line 77
    iget v3, v0, Lh5/d;->a0:I

    .line 78
    .line 79
    invoke-virtual {v1, v2, v3}, La5/c;->d(La5/h;I)V

    .line 80
    .line 81
    .line 82
    iget-object v2, v10, Lh5/c;->i:La5/h;

    .line 83
    .line 84
    iget v0, v0, Lh5/d;->a0:I

    .line 85
    .line 86
    invoke-virtual {v1, v2, v0}, La5/c;->d(La5/h;I)V

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :cond_4
    :goto_1
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 91
    .line 92
    iget v3, v0, Lh5/d;->Z:I

    .line 93
    .line 94
    invoke-virtual {v1, v2, v3}, La5/c;->d(La5/h;I)V

    .line 95
    .line 96
    .line 97
    iget-object v2, v8, Lh5/c;->i:La5/h;

    .line 98
    .line 99
    iget v0, v0, Lh5/d;->Z:I

    .line 100
    .line 101
    invoke-virtual {v1, v2, v0}, La5/c;->d(La5/h;I)V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :cond_5
    move v11, v3

    .line 106
    :goto_2
    iget v13, v0, Lh5/i;->s0:I

    .line 107
    .line 108
    if-ge v11, v13, :cond_b

    .line 109
    .line 110
    iget-object v13, v0, Lh5/i;->r0:[Lh5/d;

    .line 111
    .line 112
    aget-object v13, v13, v11

    .line 113
    .line 114
    iget-boolean v14, v0, Lh5/a;->u0:Z

    .line 115
    .line 116
    if-nez v14, :cond_6

    .line 117
    .line 118
    invoke-virtual {v13}, Lh5/d;->d()Z

    .line 119
    .line 120
    .line 121
    move-result v14

    .line 122
    if-nez v14, :cond_6

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_6
    iget v14, v0, Lh5/a;->t0:I

    .line 126
    .line 127
    if-eqz v14, :cond_7

    .line 128
    .line 129
    if-ne v14, v7, :cond_8

    .line 130
    .line 131
    :cond_7
    iget-object v15, v13, Lh5/d;->q0:[I

    .line 132
    .line 133
    aget v15, v15, v3

    .line 134
    .line 135
    if-ne v15, v9, :cond_8

    .line 136
    .line 137
    iget-object v15, v13, Lh5/d;->J:Lh5/c;

    .line 138
    .line 139
    iget-object v15, v15, Lh5/c;->f:Lh5/c;

    .line 140
    .line 141
    if-eqz v15, :cond_8

    .line 142
    .line 143
    iget-object v15, v13, Lh5/d;->L:Lh5/c;

    .line 144
    .line 145
    iget-object v15, v15, Lh5/c;->f:Lh5/c;

    .line 146
    .line 147
    if-eqz v15, :cond_8

    .line 148
    .line 149
    :goto_3
    move v11, v7

    .line 150
    goto :goto_5

    .line 151
    :cond_8
    if-eq v14, v5, :cond_9

    .line 152
    .line 153
    if-ne v14, v9, :cond_a

    .line 154
    .line 155
    :cond_9
    iget-object v14, v13, Lh5/d;->q0:[I

    .line 156
    .line 157
    aget v14, v14, v7

    .line 158
    .line 159
    if-ne v14, v9, :cond_a

    .line 160
    .line 161
    iget-object v14, v13, Lh5/d;->K:Lh5/c;

    .line 162
    .line 163
    iget-object v14, v14, Lh5/c;->f:Lh5/c;

    .line 164
    .line 165
    if-eqz v14, :cond_a

    .line 166
    .line 167
    iget-object v13, v13, Lh5/d;->M:Lh5/c;

    .line 168
    .line 169
    iget-object v13, v13, Lh5/c;->f:Lh5/c;

    .line 170
    .line 171
    if-eqz v13, :cond_a

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_a
    :goto_4
    add-int/lit8 v11, v11, 0x1

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_b
    move v11, v3

    .line 178
    :goto_5
    invoke-virtual {v4}, Lh5/c;->g()Z

    .line 179
    .line 180
    .line 181
    move-result v13

    .line 182
    if-nez v13, :cond_d

    .line 183
    .line 184
    invoke-virtual {v8}, Lh5/c;->g()Z

    .line 185
    .line 186
    .line 187
    move-result v13

    .line 188
    if-eqz v13, :cond_c

    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_c
    move v13, v3

    .line 192
    goto :goto_7

    .line 193
    :cond_d
    :goto_6
    move v13, v7

    .line 194
    :goto_7
    invoke-virtual {v6}, Lh5/c;->g()Z

    .line 195
    .line 196
    .line 197
    move-result v14

    .line 198
    if-nez v14, :cond_f

    .line 199
    .line 200
    invoke-virtual {v10}, Lh5/c;->g()Z

    .line 201
    .line 202
    .line 203
    move-result v14

    .line 204
    if-eqz v14, :cond_e

    .line 205
    .line 206
    goto :goto_8

    .line 207
    :cond_e
    move v14, v3

    .line 208
    goto :goto_9

    .line 209
    :cond_f
    :goto_8
    move v14, v7

    .line 210
    :goto_9
    if-nez v11, :cond_14

    .line 211
    .line 212
    iget v11, v0, Lh5/a;->t0:I

    .line 213
    .line 214
    if-nez v11, :cond_10

    .line 215
    .line 216
    if-nez v13, :cond_13

    .line 217
    .line 218
    :cond_10
    if-ne v11, v5, :cond_11

    .line 219
    .line 220
    if-nez v14, :cond_13

    .line 221
    .line 222
    :cond_11
    if-ne v11, v7, :cond_12

    .line 223
    .line 224
    if-nez v13, :cond_13

    .line 225
    .line 226
    :cond_12
    if-ne v11, v9, :cond_14

    .line 227
    .line 228
    if-eqz v14, :cond_14

    .line 229
    .line 230
    :cond_13
    move v11, v7

    .line 231
    goto :goto_a

    .line 232
    :cond_14
    move v11, v3

    .line 233
    :goto_a
    if-nez v11, :cond_15

    .line 234
    .line 235
    move v11, v12

    .line 236
    goto :goto_b

    .line 237
    :cond_15
    const/4 v11, 0x5

    .line 238
    :goto_b
    move v13, v3

    .line 239
    :goto_c
    iget v14, v0, Lh5/i;->s0:I

    .line 240
    .line 241
    if-ge v13, v14, :cond_1a

    .line 242
    .line 243
    iget-object v14, v0, Lh5/i;->r0:[Lh5/d;

    .line 244
    .line 245
    aget-object v14, v14, v13

    .line 246
    .line 247
    iget-boolean v15, v0, Lh5/a;->u0:Z

    .line 248
    .line 249
    if-nez v15, :cond_16

    .line 250
    .line 251
    invoke-virtual {v14}, Lh5/d;->d()Z

    .line 252
    .line 253
    .line 254
    move-result v15

    .line 255
    if-nez v15, :cond_16

    .line 256
    .line 257
    goto :goto_10

    .line 258
    :cond_16
    iget-object v15, v14, Lh5/d;->R:[Lh5/c;

    .line 259
    .line 260
    iget v9, v0, Lh5/a;->t0:I

    .line 261
    .line 262
    aget-object v9, v15, v9

    .line 263
    .line 264
    invoke-virtual {v1, v9}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 265
    .line 266
    .line 267
    move-result-object v9

    .line 268
    iget-object v14, v14, Lh5/d;->R:[Lh5/c;

    .line 269
    .line 270
    iget v15, v0, Lh5/a;->t0:I

    .line 271
    .line 272
    aget-object v14, v14, v15

    .line 273
    .line 274
    iput-object v9, v14, Lh5/c;->i:La5/h;

    .line 275
    .line 276
    iget-object v7, v14, Lh5/c;->f:Lh5/c;

    .line 277
    .line 278
    if-eqz v7, :cond_17

    .line 279
    .line 280
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 281
    .line 282
    if-ne v7, v0, :cond_17

    .line 283
    .line 284
    iget v7, v14, Lh5/c;->g:I

    .line 285
    .line 286
    goto :goto_d

    .line 287
    :cond_17
    move v7, v3

    .line 288
    :goto_d
    if-eqz v15, :cond_19

    .line 289
    .line 290
    if-ne v15, v5, :cond_18

    .line 291
    .line 292
    goto :goto_e

    .line 293
    :cond_18
    iget-object v14, v2, Lh5/c;->i:La5/h;

    .line 294
    .line 295
    iget v15, v0, Lh5/a;->v0:I

    .line 296
    .line 297
    add-int/2addr v15, v7

    .line 298
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 299
    .line 300
    .line 301
    move-result-object v5

    .line 302
    invoke-virtual {v1}, La5/c;->m()La5/h;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    iput v3, v12, La5/h;->g:I

    .line 307
    .line 308
    invoke-virtual {v5, v14, v9, v12, v15}, La5/b;->b(La5/h;La5/h;La5/h;I)V

    .line 309
    .line 310
    .line 311
    invoke-virtual {v1, v5}, La5/c;->c(La5/b;)V

    .line 312
    .line 313
    .line 314
    goto :goto_f

    .line 315
    :cond_19
    :goto_e
    iget-object v5, v2, Lh5/c;->i:La5/h;

    .line 316
    .line 317
    iget v12, v0, Lh5/a;->v0:I

    .line 318
    .line 319
    sub-int/2addr v12, v7

    .line 320
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 321
    .line 322
    .line 323
    move-result-object v14

    .line 324
    invoke-virtual {v1}, La5/c;->m()La5/h;

    .line 325
    .line 326
    .line 327
    move-result-object v15

    .line 328
    iput v3, v15, La5/h;->g:I

    .line 329
    .line 330
    invoke-virtual {v14, v5, v9, v15, v12}, La5/b;->c(La5/h;La5/h;La5/h;I)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v1, v14}, La5/c;->c(La5/b;)V

    .line 334
    .line 335
    .line 336
    :goto_f
    iget-object v5, v2, Lh5/c;->i:La5/h;

    .line 337
    .line 338
    iget v12, v0, Lh5/a;->v0:I

    .line 339
    .line 340
    add-int/2addr v12, v7

    .line 341
    invoke-virtual {v1, v5, v9, v12, v11}, La5/c;->e(La5/h;La5/h;II)V

    .line 342
    .line 343
    .line 344
    :goto_10
    add-int/lit8 v13, v13, 0x1

    .line 345
    .line 346
    const/4 v5, 0x2

    .line 347
    const/4 v7, 0x1

    .line 348
    const/4 v9, 0x3

    .line 349
    const/4 v12, 0x4

    .line 350
    goto :goto_c

    .line 351
    :cond_1a
    iget v2, v0, Lh5/a;->t0:I

    .line 352
    .line 353
    const/16 v5, 0x8

    .line 354
    .line 355
    if-nez v2, :cond_1b

    .line 356
    .line 357
    iget-object v2, v8, Lh5/c;->i:La5/h;

    .line 358
    .line 359
    iget-object v6, v4, Lh5/c;->i:La5/h;

    .line 360
    .line 361
    invoke-virtual {v1, v2, v6, v3, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 362
    .line 363
    .line 364
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 365
    .line 366
    iget-object v5, v0, Lh5/d;->U:Lh5/e;

    .line 367
    .line 368
    iget-object v5, v5, Lh5/d;->L:Lh5/c;

    .line 369
    .line 370
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 371
    .line 372
    const/4 v6, 0x4

    .line 373
    invoke-virtual {v1, v2, v5, v3, v6}, La5/c;->e(La5/h;La5/h;II)V

    .line 374
    .line 375
    .line 376
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 377
    .line 378
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 379
    .line 380
    iget-object v0, v0, Lh5/d;->J:Lh5/c;

    .line 381
    .line 382
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 383
    .line 384
    invoke-virtual {v1, v2, v0, v3, v3}, La5/c;->e(La5/h;La5/h;II)V

    .line 385
    .line 386
    .line 387
    return-void

    .line 388
    :cond_1b
    const/4 v7, 0x1

    .line 389
    if-ne v2, v7, :cond_1c

    .line 390
    .line 391
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 392
    .line 393
    iget-object v6, v8, Lh5/c;->i:La5/h;

    .line 394
    .line 395
    invoke-virtual {v1, v2, v6, v3, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 396
    .line 397
    .line 398
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 399
    .line 400
    iget-object v5, v0, Lh5/d;->U:Lh5/e;

    .line 401
    .line 402
    iget-object v5, v5, Lh5/d;->J:Lh5/c;

    .line 403
    .line 404
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 405
    .line 406
    const/4 v6, 0x4

    .line 407
    invoke-virtual {v1, v2, v5, v3, v6}, La5/c;->e(La5/h;La5/h;II)V

    .line 408
    .line 409
    .line 410
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 411
    .line 412
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 413
    .line 414
    iget-object v0, v0, Lh5/d;->L:Lh5/c;

    .line 415
    .line 416
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 417
    .line 418
    invoke-virtual {v1, v2, v0, v3, v3}, La5/c;->e(La5/h;La5/h;II)V

    .line 419
    .line 420
    .line 421
    return-void

    .line 422
    :cond_1c
    const/4 v4, 0x2

    .line 423
    if-ne v2, v4, :cond_1d

    .line 424
    .line 425
    iget-object v2, v10, Lh5/c;->i:La5/h;

    .line 426
    .line 427
    iget-object v4, v6, Lh5/c;->i:La5/h;

    .line 428
    .line 429
    invoke-virtual {v1, v2, v4, v3, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 430
    .line 431
    .line 432
    iget-object v2, v6, Lh5/c;->i:La5/h;

    .line 433
    .line 434
    iget-object v4, v0, Lh5/d;->U:Lh5/e;

    .line 435
    .line 436
    iget-object v4, v4, Lh5/d;->M:Lh5/c;

    .line 437
    .line 438
    iget-object v4, v4, Lh5/c;->i:La5/h;

    .line 439
    .line 440
    const/4 v5, 0x4

    .line 441
    invoke-virtual {v1, v2, v4, v3, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 442
    .line 443
    .line 444
    iget-object v2, v6, Lh5/c;->i:La5/h;

    .line 445
    .line 446
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 447
    .line 448
    iget-object v0, v0, Lh5/d;->K:Lh5/c;

    .line 449
    .line 450
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 451
    .line 452
    invoke-virtual {v1, v2, v0, v3, v3}, La5/c;->e(La5/h;La5/h;II)V

    .line 453
    .line 454
    .line 455
    return-void

    .line 456
    :cond_1d
    const/4 v4, 0x3

    .line 457
    if-ne v2, v4, :cond_1e

    .line 458
    .line 459
    iget-object v2, v6, Lh5/c;->i:La5/h;

    .line 460
    .line 461
    iget-object v4, v10, Lh5/c;->i:La5/h;

    .line 462
    .line 463
    invoke-virtual {v1, v2, v4, v3, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 464
    .line 465
    .line 466
    iget-object v2, v6, Lh5/c;->i:La5/h;

    .line 467
    .line 468
    iget-object v4, v0, Lh5/d;->U:Lh5/e;

    .line 469
    .line 470
    iget-object v4, v4, Lh5/d;->K:Lh5/c;

    .line 471
    .line 472
    iget-object v4, v4, Lh5/c;->i:La5/h;

    .line 473
    .line 474
    const/4 v5, 0x4

    .line 475
    invoke-virtual {v1, v2, v4, v3, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 476
    .line 477
    .line 478
    iget-object v2, v6, Lh5/c;->i:La5/h;

    .line 479
    .line 480
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 481
    .line 482
    iget-object v0, v0, Lh5/d;->M:Lh5/c;

    .line 483
    .line 484
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 485
    .line 486
    invoke-virtual {v1, v2, v0, v3, v3}, La5/c;->e(La5/h;La5/h;II)V

    .line 487
    .line 488
    .line 489
    :cond_1e
    return-void
.end method

.method public final d()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "[Barrier] "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 9
    .line 10
    const-string v2, " {"

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const/4 v1, 0x0

    .line 17
    :goto_0
    iget v2, p0, Lh5/i;->s0:I

    .line 18
    .line 19
    if-ge v1, v2, :cond_1

    .line 20
    .line 21
    iget-object v2, p0, Lh5/i;->r0:[Lh5/d;

    .line 22
    .line 23
    aget-object v2, v2, v1

    .line 24
    .line 25
    if-lez v1, :cond_0

    .line 26
    .line 27
    const-string v3, ", "

    .line 28
    .line 29
    invoke-static {v0, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    :cond_0
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iget-object v2, v2, Lh5/d;->i0:Ljava/lang/String;

    .line 38
    .line 39
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    add-int/lit8 v1, v1, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    const-string p0, "}"

    .line 50
    .line 51
    invoke-static {v0, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method
