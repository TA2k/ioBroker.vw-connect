.class public final Lv2/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/k;

.field public b:Ljava/lang/Object;

.field public c:Landroidx/collection/h0;

.field public d:I

.field public final e:Landroidx/collection/q0;

.field public final f:Landroidx/collection/q0;

.field public final g:Landroidx/collection/r0;

.field public final h:Ln2/b;

.field public final i:Ll2/s;

.field public j:I

.field public final k:Landroidx/collection/q0;

.field public final l:Ljava/util/HashMap;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv2/q;->a:Lay0/k;

    .line 5
    .line 6
    const/4 p1, -0x1

    .line 7
    iput p1, p0, Lv2/q;->d:I

    .line 8
    .line 9
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Lv2/q;->e:Landroidx/collection/q0;

    .line 14
    .line 15
    new-instance p1, Landroidx/collection/q0;

    .line 16
    .line 17
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lv2/q;->f:Landroidx/collection/q0;

    .line 21
    .line 22
    new-instance p1, Landroidx/collection/r0;

    .line 23
    .line 24
    invoke-direct {p1}, Landroidx/collection/r0;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lv2/q;->g:Landroidx/collection/r0;

    .line 28
    .line 29
    new-instance p1, Ln2/b;

    .line 30
    .line 31
    const/16 v0, 0x10

    .line 32
    .line 33
    new-array v0, v0, [Ll2/h0;

    .line 34
    .line 35
    invoke-direct {p1, v0}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lv2/q;->h:Ln2/b;

    .line 39
    .line 40
    new-instance p1, Ll2/s;

    .line 41
    .line 42
    const/4 v0, 0x1

    .line 43
    invoke-direct {p1, p0, v0}, Ll2/s;-><init>(Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Lv2/q;->i:Ll2/s;

    .line 47
    .line 48
    invoke-static {}, Ljp/v1;->b()Landroidx/collection/q0;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    iput-object p1, p0, Lv2/q;->k:Landroidx/collection/q0;

    .line 53
    .line 54
    new-instance p1, Ljava/util/HashMap;

    .line 55
    .line 56
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Lv2/q;->l:Ljava/util/HashMap;

    .line 60
    .line 61
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;Lay0/a;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lv2/q;->b:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v3, v0, Lv2/q;->c:Landroidx/collection/h0;

    .line 8
    .line 9
    iget v4, v0, Lv2/q;->d:I

    .line 10
    .line 11
    iput-object v1, v0, Lv2/q;->b:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v5, v0, Lv2/q;->f:Landroidx/collection/q0;

    .line 14
    .line 15
    invoke-virtual {v5, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Landroidx/collection/h0;

    .line 20
    .line 21
    iput-object v1, v0, Lv2/q;->c:Landroidx/collection/h0;

    .line 22
    .line 23
    iget v1, v0, Lv2/q;->d:I

    .line 24
    .line 25
    const/4 v5, -0x1

    .line 26
    if-ne v1, v5, :cond_0

    .line 27
    .line 28
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {v1}, Lv2/f;->g()J

    .line 33
    .line 34
    .line 35
    move-result-wide v5

    .line 36
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    iput v1, v0, Lv2/q;->d:I

    .line 41
    .line 42
    :cond_0
    iget-object v1, v0, Lv2/q;->i:Ll2/s;

    .line 43
    .line 44
    invoke-static {}, Ll2/b;->g()Ln2/b;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    const/4 v6, 0x1

    .line 49
    :try_start_0
    invoke-virtual {v5, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    move-object/from16 v1, p2

    .line 53
    .line 54
    move-object/from16 v7, p3

    .line 55
    .line 56
    invoke-static {v7, v1}, Lgv/a;->k(Lay0/a;Lay0/k;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    .line 58
    .line 59
    iget v1, v5, Ln2/b;->f:I

    .line 60
    .line 61
    sub-int/2addr v1, v6

    .line 62
    invoke-virtual {v5, v1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    iget-object v1, v0, Lv2/q;->b:Ljava/lang/Object;

    .line 66
    .line 67
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget v5, v0, Lv2/q;->d:I

    .line 71
    .line 72
    iget-object v7, v0, Lv2/q;->c:Landroidx/collection/h0;

    .line 73
    .line 74
    if-eqz v7, :cond_7

    .line 75
    .line 76
    iget-object v8, v7, Landroidx/collection/h0;->a:[J

    .line 77
    .line 78
    array-length v9, v8

    .line 79
    add-int/lit8 v9, v9, -0x2

    .line 80
    .line 81
    if-ltz v9, :cond_7

    .line 82
    .line 83
    const/4 v11, 0x0

    .line 84
    :goto_0
    aget-wide v12, v8, v11

    .line 85
    .line 86
    not-long v14, v12

    .line 87
    const/16 v16, 0x7

    .line 88
    .line 89
    shl-long v14, v14, v16

    .line 90
    .line 91
    and-long/2addr v14, v12

    .line 92
    const-wide v16, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    and-long v14, v14, v16

    .line 98
    .line 99
    cmp-long v14, v14, v16

    .line 100
    .line 101
    if-eqz v14, :cond_6

    .line 102
    .line 103
    sub-int v14, v11, v9

    .line 104
    .line 105
    not-int v14, v14

    .line 106
    ushr-int/lit8 v14, v14, 0x1f

    .line 107
    .line 108
    const/16 v15, 0x8

    .line 109
    .line 110
    rsub-int/lit8 v14, v14, 0x8

    .line 111
    .line 112
    move/from16 p1, v6

    .line 113
    .line 114
    const/4 v6, 0x0

    .line 115
    :goto_1
    if-ge v6, v14, :cond_5

    .line 116
    .line 117
    const-wide/16 v16, 0xff

    .line 118
    .line 119
    and-long v16, v12, v16

    .line 120
    .line 121
    const-wide/16 v18, 0x80

    .line 122
    .line 123
    cmp-long v16, v16, v18

    .line 124
    .line 125
    if-gez v16, :cond_3

    .line 126
    .line 127
    shl-int/lit8 v16, v11, 0x3

    .line 128
    .line 129
    add-int v10, v16, v6

    .line 130
    .line 131
    move/from16 p3, v15

    .line 132
    .line 133
    iget-object v15, v7, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 134
    .line 135
    aget-object v15, v15, v10

    .line 136
    .line 137
    move/from16 v16, v6

    .line 138
    .line 139
    iget-object v6, v7, Landroidx/collection/h0;->c:[I

    .line 140
    .line 141
    aget v6, v6, v10

    .line 142
    .line 143
    if-eq v6, v5, :cond_1

    .line 144
    .line 145
    move/from16 v6, p1

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_1
    const/4 v6, 0x0

    .line 149
    :goto_2
    if-eqz v6, :cond_2

    .line 150
    .line 151
    invoke-virtual {v0, v1, v15}, Lv2/q;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    :cond_2
    if-eqz v6, :cond_4

    .line 155
    .line 156
    invoke-virtual {v7, v10}, Landroidx/collection/h0;->g(I)V

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_3
    move/from16 v16, v6

    .line 161
    .line 162
    move/from16 p3, v15

    .line 163
    .line 164
    :cond_4
    :goto_3
    shr-long v12, v12, p3

    .line 165
    .line 166
    add-int/lit8 v6, v16, 0x1

    .line 167
    .line 168
    move/from16 v15, p3

    .line 169
    .line 170
    goto :goto_1

    .line 171
    :cond_5
    move v6, v15

    .line 172
    if-ne v14, v6, :cond_7

    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_6
    move/from16 p1, v6

    .line 176
    .line 177
    :goto_4
    if-eq v11, v9, :cond_7

    .line 178
    .line 179
    add-int/lit8 v11, v11, 0x1

    .line 180
    .line 181
    move/from16 v6, p1

    .line 182
    .line 183
    goto :goto_0

    .line 184
    :cond_7
    iput-object v2, v0, Lv2/q;->b:Ljava/lang/Object;

    .line 185
    .line 186
    iput-object v3, v0, Lv2/q;->c:Landroidx/collection/h0;

    .line 187
    .line 188
    iput v4, v0, Lv2/q;->d:I

    .line 189
    .line 190
    return-void

    .line 191
    :catchall_0
    move-exception v0

    .line 192
    move/from16 p1, v6

    .line 193
    .line 194
    iget v1, v5, Ln2/b;->f:I

    .line 195
    .line 196
    add-int/lit8 v1, v1, -0x1

    .line 197
    .line 198
    invoke-virtual {v5, v1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    throw v0
.end method

.method public final b(Ljava/util/Set;)Z
    .locals 45

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v2, Ll2/x0;->i:Ll2/x0;

    .line 6
    .line 7
    instance-of v3, v1, Ln2/d;

    .line 8
    .line 9
    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.DerivedState<kotlin.Any?>"

    .line 10
    .line 11
    iget-object v5, v0, Lv2/q;->h:Ln2/b;

    .line 12
    .line 13
    const/4 v11, 0x2

    .line 14
    const/16 v16, 0x0

    .line 15
    .line 16
    const-wide/16 v17, 0x80

    .line 17
    .line 18
    iget-object v6, v0, Lv2/q;->k:Landroidx/collection/q0;

    .line 19
    .line 20
    iget-object v7, v0, Lv2/q;->l:Ljava/util/HashMap;

    .line 21
    .line 22
    const-wide/16 v19, 0xff

    .line 23
    .line 24
    iget-object v8, v0, Lv2/q;->e:Landroidx/collection/q0;

    .line 25
    .line 26
    iget-object v9, v0, Lv2/q;->g:Landroidx/collection/r0;

    .line 27
    .line 28
    if-eqz v3, :cond_21

    .line 29
    .line 30
    check-cast v1, Ln2/d;

    .line 31
    .line 32
    iget-object v1, v1, Ln2/d;->d:Landroidx/collection/r0;

    .line 33
    .line 34
    iget-object v3, v1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 35
    .line 36
    iget-object v1, v1, Landroidx/collection/r0;->a:[J

    .line 37
    .line 38
    const/16 v21, 0x7

    .line 39
    .line 40
    array-length v10, v1

    .line 41
    sub-int/2addr v10, v11

    .line 42
    if-ltz v10, :cond_20

    .line 43
    .line 44
    move/from16 v12, v16

    .line 45
    .line 46
    move v13, v12

    .line 47
    const-wide v22, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    :goto_0
    const/16 v24, 0x8

    .line 53
    .line 54
    aget-wide v14, v1, v12

    .line 55
    .line 56
    move/from16 p1, v12

    .line 57
    .line 58
    not-long v11, v14

    .line 59
    shl-long v11, v11, v21

    .line 60
    .line 61
    and-long/2addr v11, v14

    .line 62
    and-long v11, v11, v22

    .line 63
    .line 64
    cmp-long v11, v11, v22

    .line 65
    .line 66
    if-eqz v11, :cond_1f

    .line 67
    .line 68
    sub-int v12, p1, v10

    .line 69
    .line 70
    not-int v11, v12

    .line 71
    ushr-int/lit8 v11, v11, 0x1f

    .line 72
    .line 73
    rsub-int/lit8 v11, v11, 0x8

    .line 74
    .line 75
    move/from16 v12, v16

    .line 76
    .line 77
    :goto_1
    if-ge v12, v11, :cond_1e

    .line 78
    .line 79
    and-long v27, v14, v19

    .line 80
    .line 81
    cmp-long v27, v27, v17

    .line 82
    .line 83
    if-gez v27, :cond_1d

    .line 84
    .line 85
    shl-int/lit8 v27, p1, 0x3

    .line 86
    .line 87
    add-int v27, v27, v12

    .line 88
    .line 89
    move-object/from16 v28, v1

    .line 90
    .line 91
    aget-object v1, v3, v27

    .line 92
    .line 93
    move-object/from16 v27, v2

    .line 94
    .line 95
    instance-of v2, v1, Lv2/u;

    .line 96
    .line 97
    if-eqz v2, :cond_0

    .line 98
    .line 99
    move-object v2, v1

    .line 100
    check-cast v2, Lv2/u;

    .line 101
    .line 102
    move-object/from16 v29, v3

    .line 103
    .line 104
    const/4 v3, 0x2

    .line 105
    invoke-virtual {v2, v3}, Lv2/u;->a(I)Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-nez v2, :cond_1

    .line 110
    .line 111
    goto/16 :goto_11

    .line 112
    .line 113
    :cond_0
    move-object/from16 v29, v3

    .line 114
    .line 115
    :cond_1
    invoke-virtual {v6, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-eqz v2, :cond_17

    .line 120
    .line 121
    invoke-virtual {v6, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    if-eqz v2, :cond_15

    .line 126
    .line 127
    instance-of v3, v2, Landroidx/collection/r0;

    .line 128
    .line 129
    if-eqz v3, :cond_e

    .line 130
    .line 131
    check-cast v2, Landroidx/collection/r0;

    .line 132
    .line 133
    iget-object v3, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 134
    .line 135
    iget-object v2, v2, Landroidx/collection/r0;->a:[J

    .line 136
    .line 137
    move-object/from16 v30, v3

    .line 138
    .line 139
    array-length v3, v2

    .line 140
    const/16 v26, 0x2

    .line 141
    .line 142
    add-int/lit8 v3, v3, -0x2

    .line 143
    .line 144
    if-ltz v3, :cond_15

    .line 145
    .line 146
    move-object/from16 v31, v2

    .line 147
    .line 148
    move/from16 v32, v12

    .line 149
    .line 150
    move/from16 v33, v13

    .line 151
    .line 152
    move/from16 v2, v16

    .line 153
    .line 154
    :goto_2
    aget-wide v12, v31, v2

    .line 155
    .line 156
    move-wide/from16 v34, v14

    .line 157
    .line 158
    not-long v14, v12

    .line 159
    shl-long v14, v14, v21

    .line 160
    .line 161
    and-long/2addr v14, v12

    .line 162
    and-long v14, v14, v22

    .line 163
    .line 164
    cmp-long v14, v14, v22

    .line 165
    .line 166
    if-eqz v14, :cond_c

    .line 167
    .line 168
    sub-int v14, v2, v3

    .line 169
    .line 170
    not-int v14, v14

    .line 171
    ushr-int/lit8 v14, v14, 0x1f

    .line 172
    .line 173
    rsub-int/lit8 v14, v14, 0x8

    .line 174
    .line 175
    move/from16 v15, v16

    .line 176
    .line 177
    :goto_3
    if-ge v15, v14, :cond_b

    .line 178
    .line 179
    and-long v36, v12, v19

    .line 180
    .line 181
    cmp-long v36, v36, v17

    .line 182
    .line 183
    if-gez v36, :cond_a

    .line 184
    .line 185
    shl-int/lit8 v36, v2, 0x3

    .line 186
    .line 187
    add-int v36, v36, v15

    .line 188
    .line 189
    aget-object v36, v30, v36

    .line 190
    .line 191
    move-wide/from16 v37, v12

    .line 192
    .line 193
    move-object/from16 v12, v36

    .line 194
    .line 195
    check-cast v12, Ll2/h0;

    .line 196
    .line 197
    invoke-static {v12, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v7, v12}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v13

    .line 204
    move/from16 v36, v15

    .line 205
    .line 206
    iget-object v15, v12, Ll2/h0;->f:Ll2/n2;

    .line 207
    .line 208
    if-nez v15, :cond_2

    .line 209
    .line 210
    move-object/from16 v15, v27

    .line 211
    .line 212
    :cond_2
    invoke-virtual {v12}, Ll2/h0;->o()Ll2/g0;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    iget-object v0, v0, Ll2/g0;->f:Ljava/lang/Object;

    .line 217
    .line 218
    invoke-interface {v15, v0, v13}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v0

    .line 222
    if-nez v0, :cond_8

    .line 223
    .line 224
    invoke-virtual {v8, v12}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    if-eqz v0, :cond_6

    .line 229
    .line 230
    instance-of v12, v0, Landroidx/collection/r0;

    .line 231
    .line 232
    if-eqz v12, :cond_7

    .line 233
    .line 234
    check-cast v0, Landroidx/collection/r0;

    .line 235
    .line 236
    iget-object v12, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 237
    .line 238
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 239
    .line 240
    array-length v13, v0

    .line 241
    const/16 v26, 0x2

    .line 242
    .line 243
    add-int/lit8 v13, v13, -0x2

    .line 244
    .line 245
    if-ltz v13, :cond_6

    .line 246
    .line 247
    move/from16 v39, v10

    .line 248
    .line 249
    move/from16 v40, v11

    .line 250
    .line 251
    move/from16 v15, v16

    .line 252
    .line 253
    :goto_4
    aget-wide v10, v0, v15

    .line 254
    .line 255
    move-object/from16 v42, v0

    .line 256
    .line 257
    move-object/from16 v41, v1

    .line 258
    .line 259
    not-long v0, v10

    .line 260
    shl-long v0, v0, v21

    .line 261
    .line 262
    and-long/2addr v0, v10

    .line 263
    and-long v0, v0, v22

    .line 264
    .line 265
    cmp-long v0, v0, v22

    .line 266
    .line 267
    if-eqz v0, :cond_5

    .line 268
    .line 269
    sub-int v0, v15, v13

    .line 270
    .line 271
    not-int v0, v0

    .line 272
    ushr-int/lit8 v0, v0, 0x1f

    .line 273
    .line 274
    rsub-int/lit8 v0, v0, 0x8

    .line 275
    .line 276
    move/from16 v1, v16

    .line 277
    .line 278
    :goto_5
    if-ge v1, v0, :cond_4

    .line 279
    .line 280
    and-long v43, v10, v19

    .line 281
    .line 282
    cmp-long v43, v43, v17

    .line 283
    .line 284
    if-gez v43, :cond_3

    .line 285
    .line 286
    shl-int/lit8 v33, v15, 0x3

    .line 287
    .line 288
    add-int v33, v33, v1

    .line 289
    .line 290
    move/from16 v43, v1

    .line 291
    .line 292
    aget-object v1, v12, v33

    .line 293
    .line 294
    invoke-virtual {v9, v1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    const/16 v33, 0x1

    .line 298
    .line 299
    goto :goto_6

    .line 300
    :cond_3
    move/from16 v43, v1

    .line 301
    .line 302
    :goto_6
    shr-long v10, v10, v24

    .line 303
    .line 304
    add-int/lit8 v1, v43, 0x1

    .line 305
    .line 306
    goto :goto_5

    .line 307
    :cond_4
    move/from16 v1, v24

    .line 308
    .line 309
    if-ne v0, v1, :cond_9

    .line 310
    .line 311
    :cond_5
    if-eq v15, v13, :cond_9

    .line 312
    .line 313
    add-int/lit8 v15, v15, 0x1

    .line 314
    .line 315
    move-object/from16 v1, v41

    .line 316
    .line 317
    move-object/from16 v0, v42

    .line 318
    .line 319
    const/16 v24, 0x8

    .line 320
    .line 321
    goto :goto_4

    .line 322
    :cond_6
    move-object/from16 v41, v1

    .line 323
    .line 324
    move/from16 v39, v10

    .line 325
    .line 326
    move/from16 v40, v11

    .line 327
    .line 328
    goto :goto_7

    .line 329
    :cond_7
    move-object/from16 v41, v1

    .line 330
    .line 331
    move/from16 v39, v10

    .line 332
    .line 333
    move/from16 v40, v11

    .line 334
    .line 335
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    const/16 v33, 0x1

    .line 339
    .line 340
    goto :goto_7

    .line 341
    :cond_8
    move-object/from16 v41, v1

    .line 342
    .line 343
    move/from16 v39, v10

    .line 344
    .line 345
    move/from16 v40, v11

    .line 346
    .line 347
    invoke-virtual {v5, v12}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 348
    .line 349
    .line 350
    :cond_9
    :goto_7
    const/16 v1, 0x8

    .line 351
    .line 352
    goto :goto_8

    .line 353
    :cond_a
    move-object/from16 v41, v1

    .line 354
    .line 355
    move/from16 v39, v10

    .line 356
    .line 357
    move/from16 v40, v11

    .line 358
    .line 359
    move-wide/from16 v37, v12

    .line 360
    .line 361
    move/from16 v36, v15

    .line 362
    .line 363
    goto :goto_7

    .line 364
    :goto_8
    shr-long v12, v37, v1

    .line 365
    .line 366
    add-int/lit8 v15, v36, 0x1

    .line 367
    .line 368
    move-object/from16 v0, p0

    .line 369
    .line 370
    move/from16 v24, v1

    .line 371
    .line 372
    move/from16 v10, v39

    .line 373
    .line 374
    move/from16 v11, v40

    .line 375
    .line 376
    move-object/from16 v1, v41

    .line 377
    .line 378
    goto/16 :goto_3

    .line 379
    .line 380
    :cond_b
    move-object/from16 v41, v1

    .line 381
    .line 382
    move/from16 v39, v10

    .line 383
    .line 384
    move/from16 v40, v11

    .line 385
    .line 386
    move/from16 v1, v24

    .line 387
    .line 388
    if-ne v14, v1, :cond_d

    .line 389
    .line 390
    goto :goto_9

    .line 391
    :cond_c
    move-object/from16 v41, v1

    .line 392
    .line 393
    move/from16 v39, v10

    .line 394
    .line 395
    move/from16 v40, v11

    .line 396
    .line 397
    :goto_9
    if-eq v2, v3, :cond_d

    .line 398
    .line 399
    add-int/lit8 v2, v2, 0x1

    .line 400
    .line 401
    const/16 v24, 0x8

    .line 402
    .line 403
    move-object/from16 v0, p0

    .line 404
    .line 405
    move-wide/from16 v14, v34

    .line 406
    .line 407
    move/from16 v10, v39

    .line 408
    .line 409
    move/from16 v11, v40

    .line 410
    .line 411
    move-object/from16 v1, v41

    .line 412
    .line 413
    goto/16 :goto_2

    .line 414
    .line 415
    :cond_d
    move/from16 v13, v33

    .line 416
    .line 417
    goto/16 :goto_c

    .line 418
    .line 419
    :cond_e
    move-object/from16 v41, v1

    .line 420
    .line 421
    move/from16 v39, v10

    .line 422
    .line 423
    move/from16 v40, v11

    .line 424
    .line 425
    move/from16 v32, v12

    .line 426
    .line 427
    move-wide/from16 v34, v14

    .line 428
    .line 429
    check-cast v2, Ll2/h0;

    .line 430
    .line 431
    invoke-virtual {v7, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    iget-object v1, v2, Ll2/h0;->f:Ll2/n2;

    .line 436
    .line 437
    if-nez v1, :cond_f

    .line 438
    .line 439
    move-object/from16 v1, v27

    .line 440
    .line 441
    :cond_f
    invoke-virtual {v2}, Ll2/h0;->o()Ll2/g0;

    .line 442
    .line 443
    .line 444
    move-result-object v3

    .line 445
    iget-object v3, v3, Ll2/g0;->f:Ljava/lang/Object;

    .line 446
    .line 447
    invoke-interface {v1, v3, v0}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result v0

    .line 451
    if-nez v0, :cond_14

    .line 452
    .line 453
    invoke-virtual {v8, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    if-eqz v0, :cond_16

    .line 458
    .line 459
    instance-of v1, v0, Landroidx/collection/r0;

    .line 460
    .line 461
    if-eqz v1, :cond_13

    .line 462
    .line 463
    check-cast v0, Landroidx/collection/r0;

    .line 464
    .line 465
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 466
    .line 467
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 468
    .line 469
    array-length v2, v0

    .line 470
    const/16 v26, 0x2

    .line 471
    .line 472
    add-int/lit8 v2, v2, -0x2

    .line 473
    .line 474
    if-ltz v2, :cond_16

    .line 475
    .line 476
    move/from16 v3, v16

    .line 477
    .line 478
    :goto_a
    aget-wide v10, v0, v3

    .line 479
    .line 480
    not-long v14, v10

    .line 481
    shl-long v14, v14, v21

    .line 482
    .line 483
    and-long/2addr v14, v10

    .line 484
    and-long v14, v14, v22

    .line 485
    .line 486
    cmp-long v12, v14, v22

    .line 487
    .line 488
    if-eqz v12, :cond_12

    .line 489
    .line 490
    sub-int v12, v3, v2

    .line 491
    .line 492
    not-int v12, v12

    .line 493
    ushr-int/lit8 v12, v12, 0x1f

    .line 494
    .line 495
    const/16 v24, 0x8

    .line 496
    .line 497
    rsub-int/lit8 v14, v12, 0x8

    .line 498
    .line 499
    move/from16 v12, v16

    .line 500
    .line 501
    :goto_b
    if-ge v12, v14, :cond_11

    .line 502
    .line 503
    and-long v30, v10, v19

    .line 504
    .line 505
    cmp-long v15, v30, v17

    .line 506
    .line 507
    if-gez v15, :cond_10

    .line 508
    .line 509
    shl-int/lit8 v13, v3, 0x3

    .line 510
    .line 511
    add-int/2addr v13, v12

    .line 512
    aget-object v13, v1, v13

    .line 513
    .line 514
    invoke-virtual {v9, v13}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 515
    .line 516
    .line 517
    const/4 v13, 0x1

    .line 518
    :cond_10
    const/16 v15, 0x8

    .line 519
    .line 520
    shr-long/2addr v10, v15

    .line 521
    add-int/lit8 v12, v12, 0x1

    .line 522
    .line 523
    goto :goto_b

    .line 524
    :cond_11
    const/16 v15, 0x8

    .line 525
    .line 526
    if-ne v14, v15, :cond_16

    .line 527
    .line 528
    :cond_12
    if-eq v3, v2, :cond_16

    .line 529
    .line 530
    add-int/lit8 v3, v3, 0x1

    .line 531
    .line 532
    goto :goto_a

    .line 533
    :cond_13
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    const/4 v13, 0x1

    .line 537
    goto :goto_c

    .line 538
    :cond_14
    invoke-virtual {v5, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 539
    .line 540
    .line 541
    goto :goto_c

    .line 542
    :cond_15
    move-object/from16 v41, v1

    .line 543
    .line 544
    move/from16 v39, v10

    .line 545
    .line 546
    move/from16 v40, v11

    .line 547
    .line 548
    move/from16 v32, v12

    .line 549
    .line 550
    move-wide/from16 v34, v14

    .line 551
    .line 552
    :cond_16
    :goto_c
    move-object/from16 v0, v41

    .line 553
    .line 554
    goto :goto_d

    .line 555
    :cond_17
    move/from16 v39, v10

    .line 556
    .line 557
    move/from16 v40, v11

    .line 558
    .line 559
    move/from16 v32, v12

    .line 560
    .line 561
    move-wide/from16 v34, v14

    .line 562
    .line 563
    move-object v0, v1

    .line 564
    :goto_d
    invoke-virtual {v8, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    if-eqz v0, :cond_1c

    .line 569
    .line 570
    instance-of v1, v0, Landroidx/collection/r0;

    .line 571
    .line 572
    if-eqz v1, :cond_1b

    .line 573
    .line 574
    check-cast v0, Landroidx/collection/r0;

    .line 575
    .line 576
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 577
    .line 578
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 579
    .line 580
    array-length v2, v0

    .line 581
    const/16 v26, 0x2

    .line 582
    .line 583
    add-int/lit8 v2, v2, -0x2

    .line 584
    .line 585
    if-ltz v2, :cond_1c

    .line 586
    .line 587
    move/from16 v3, v16

    .line 588
    .line 589
    :goto_e
    aget-wide v10, v0, v3

    .line 590
    .line 591
    not-long v14, v10

    .line 592
    shl-long v14, v14, v21

    .line 593
    .line 594
    and-long/2addr v14, v10

    .line 595
    and-long v14, v14, v22

    .line 596
    .line 597
    cmp-long v12, v14, v22

    .line 598
    .line 599
    if-eqz v12, :cond_1a

    .line 600
    .line 601
    sub-int v12, v3, v2

    .line 602
    .line 603
    not-int v12, v12

    .line 604
    ushr-int/lit8 v12, v12, 0x1f

    .line 605
    .line 606
    const/16 v24, 0x8

    .line 607
    .line 608
    rsub-int/lit8 v14, v12, 0x8

    .line 609
    .line 610
    move/from16 v12, v16

    .line 611
    .line 612
    :goto_f
    if-ge v12, v14, :cond_19

    .line 613
    .line 614
    and-long v30, v10, v19

    .line 615
    .line 616
    cmp-long v15, v30, v17

    .line 617
    .line 618
    if-gez v15, :cond_18

    .line 619
    .line 620
    shl-int/lit8 v13, v3, 0x3

    .line 621
    .line 622
    add-int/2addr v13, v12

    .line 623
    aget-object v13, v1, v13

    .line 624
    .line 625
    invoke-virtual {v9, v13}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 626
    .line 627
    .line 628
    const/4 v13, 0x1

    .line 629
    :cond_18
    const/16 v15, 0x8

    .line 630
    .line 631
    shr-long/2addr v10, v15

    .line 632
    add-int/lit8 v12, v12, 0x1

    .line 633
    .line 634
    goto :goto_f

    .line 635
    :cond_19
    const/16 v15, 0x8

    .line 636
    .line 637
    if-ne v14, v15, :cond_1c

    .line 638
    .line 639
    :cond_1a
    if-eq v3, v2, :cond_1c

    .line 640
    .line 641
    add-int/lit8 v3, v3, 0x1

    .line 642
    .line 643
    goto :goto_e

    .line 644
    :cond_1b
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 645
    .line 646
    .line 647
    const/4 v13, 0x1

    .line 648
    :cond_1c
    :goto_10
    const/16 v15, 0x8

    .line 649
    .line 650
    goto :goto_12

    .line 651
    :cond_1d
    move-object/from16 v28, v1

    .line 652
    .line 653
    move-object/from16 v27, v2

    .line 654
    .line 655
    move-object/from16 v29, v3

    .line 656
    .line 657
    :goto_11
    move/from16 v39, v10

    .line 658
    .line 659
    move/from16 v40, v11

    .line 660
    .line 661
    move/from16 v32, v12

    .line 662
    .line 663
    move-wide/from16 v34, v14

    .line 664
    .line 665
    goto :goto_10

    .line 666
    :goto_12
    shr-long v0, v34, v15

    .line 667
    .line 668
    add-int/lit8 v12, v32, 0x1

    .line 669
    .line 670
    move/from16 v24, v15

    .line 671
    .line 672
    move-object/from16 v2, v27

    .line 673
    .line 674
    move-object/from16 v3, v29

    .line 675
    .line 676
    move/from16 v10, v39

    .line 677
    .line 678
    move/from16 v11, v40

    .line 679
    .line 680
    move-wide v14, v0

    .line 681
    move-object/from16 v1, v28

    .line 682
    .line 683
    move-object/from16 v0, p0

    .line 684
    .line 685
    goto/16 :goto_1

    .line 686
    .line 687
    :cond_1e
    move-object/from16 v28, v1

    .line 688
    .line 689
    move-object/from16 v27, v2

    .line 690
    .line 691
    move-object/from16 v29, v3

    .line 692
    .line 693
    move/from16 v39, v10

    .line 694
    .line 695
    move v14, v11

    .line 696
    move/from16 v15, v24

    .line 697
    .line 698
    if-ne v14, v15, :cond_3c

    .line 699
    .line 700
    move/from16 v10, v39

    .line 701
    .line 702
    :goto_13
    move/from16 v0, p1

    .line 703
    .line 704
    goto :goto_14

    .line 705
    :cond_1f
    move-object/from16 v28, v1

    .line 706
    .line 707
    move-object/from16 v27, v2

    .line 708
    .line 709
    move-object/from16 v29, v3

    .line 710
    .line 711
    goto :goto_13

    .line 712
    :goto_14
    if-eq v0, v10, :cond_3c

    .line 713
    .line 714
    add-int/lit8 v12, v0, 0x1

    .line 715
    .line 716
    move-object/from16 v2, v27

    .line 717
    .line 718
    move-object/from16 v1, v28

    .line 719
    .line 720
    move-object/from16 v3, v29

    .line 721
    .line 722
    const/4 v11, 0x2

    .line 723
    move-object/from16 v0, p0

    .line 724
    .line 725
    goto/16 :goto_0

    .line 726
    .line 727
    :cond_20
    const-wide v22, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 728
    .line 729
    .line 730
    .line 731
    .line 732
    move/from16 v13, v16

    .line 733
    .line 734
    goto/16 :goto_26

    .line 735
    .line 736
    :cond_21
    move-object/from16 v27, v2

    .line 737
    .line 738
    const/16 v21, 0x7

    .line 739
    .line 740
    const-wide v22, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 741
    .line 742
    .line 743
    .line 744
    .line 745
    move-object v0, v1

    .line 746
    check-cast v0, Ljava/lang/Iterable;

    .line 747
    .line 748
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 749
    .line 750
    .line 751
    move-result-object v0

    .line 752
    move/from16 v13, v16

    .line 753
    .line 754
    :goto_15
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 755
    .line 756
    .line 757
    move-result v1

    .line 758
    if-eqz v1, :cond_3c

    .line 759
    .line 760
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v1

    .line 764
    instance-of v2, v1, Lv2/u;

    .line 765
    .line 766
    if-eqz v2, :cond_22

    .line 767
    .line 768
    move-object v2, v1

    .line 769
    check-cast v2, Lv2/u;

    .line 770
    .line 771
    const/4 v3, 0x2

    .line 772
    invoke-virtual {v2, v3}, Lv2/u;->a(I)Z

    .line 773
    .line 774
    .line 775
    move-result v2

    .line 776
    if-nez v2, :cond_22

    .line 777
    .line 778
    move-object/from16 p1, v0

    .line 779
    .line 780
    move-object/from16 v30, v4

    .line 781
    .line 782
    move-object/from16 v31, v6

    .line 783
    .line 784
    goto/16 :goto_25

    .line 785
    .line 786
    :cond_22
    invoke-virtual {v6, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 787
    .line 788
    .line 789
    move-result v2

    .line 790
    if-eqz v2, :cond_35

    .line 791
    .line 792
    invoke-virtual {v6, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 793
    .line 794
    .line 795
    move-result-object v2

    .line 796
    if-eqz v2, :cond_35

    .line 797
    .line 798
    instance-of v3, v2, Landroidx/collection/r0;

    .line 799
    .line 800
    if-eqz v3, :cond_2e

    .line 801
    .line 802
    check-cast v2, Landroidx/collection/r0;

    .line 803
    .line 804
    iget-object v3, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 805
    .line 806
    iget-object v2, v2, Landroidx/collection/r0;->a:[J

    .line 807
    .line 808
    array-length v10, v2

    .line 809
    const/16 v26, 0x2

    .line 810
    .line 811
    add-int/lit8 v10, v10, -0x2

    .line 812
    .line 813
    if-ltz v10, :cond_35

    .line 814
    .line 815
    move/from16 v11, v16

    .line 816
    .line 817
    :goto_16
    aget-wide v14, v2, v11

    .line 818
    .line 819
    move-object/from16 v28, v2

    .line 820
    .line 821
    move-object v12, v3

    .line 822
    not-long v2, v14

    .line 823
    shl-long v2, v2, v21

    .line 824
    .line 825
    and-long/2addr v2, v14

    .line 826
    and-long v2, v2, v22

    .line 827
    .line 828
    cmp-long v2, v2, v22

    .line 829
    .line 830
    if-eqz v2, :cond_2d

    .line 831
    .line 832
    sub-int v2, v11, v10

    .line 833
    .line 834
    not-int v2, v2

    .line 835
    ushr-int/lit8 v2, v2, 0x1f

    .line 836
    .line 837
    const/16 v24, 0x8

    .line 838
    .line 839
    rsub-int/lit8 v2, v2, 0x8

    .line 840
    .line 841
    move/from16 v3, v16

    .line 842
    .line 843
    :goto_17
    if-ge v3, v2, :cond_2c

    .line 844
    .line 845
    and-long v29, v14, v19

    .line 846
    .line 847
    cmp-long v29, v29, v17

    .line 848
    .line 849
    if-gez v29, :cond_2a

    .line 850
    .line 851
    shl-int/lit8 v29, v11, 0x3

    .line 852
    .line 853
    add-int v29, v29, v3

    .line 854
    .line 855
    aget-object v29, v12, v29

    .line 856
    .line 857
    move-object/from16 p1, v0

    .line 858
    .line 859
    move-object/from16 v0, v29

    .line 860
    .line 861
    check-cast v0, Ll2/h0;

    .line 862
    .line 863
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 864
    .line 865
    .line 866
    move/from16 v29, v3

    .line 867
    .line 868
    invoke-virtual {v7, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 869
    .line 870
    .line 871
    move-result-object v3

    .line 872
    move-object/from16 v30, v4

    .line 873
    .line 874
    iget-object v4, v0, Ll2/h0;->f:Ll2/n2;

    .line 875
    .line 876
    if-nez v4, :cond_23

    .line 877
    .line 878
    move-object/from16 v4, v27

    .line 879
    .line 880
    :cond_23
    move-object/from16 v31, v6

    .line 881
    .line 882
    invoke-virtual {v0}, Ll2/h0;->o()Ll2/g0;

    .line 883
    .line 884
    .line 885
    move-result-object v6

    .line 886
    iget-object v6, v6, Ll2/g0;->f:Ljava/lang/Object;

    .line 887
    .line 888
    invoke-interface {v4, v6, v3}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 889
    .line 890
    .line 891
    move-result v3

    .line 892
    if-nez v3, :cond_29

    .line 893
    .line 894
    invoke-virtual {v8, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 895
    .line 896
    .line 897
    move-result-object v0

    .line 898
    if-eqz v0, :cond_2b

    .line 899
    .line 900
    instance-of v3, v0, Landroidx/collection/r0;

    .line 901
    .line 902
    if-eqz v3, :cond_28

    .line 903
    .line 904
    check-cast v0, Landroidx/collection/r0;

    .line 905
    .line 906
    iget-object v3, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 907
    .line 908
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 909
    .line 910
    array-length v4, v0

    .line 911
    const/16 v26, 0x2

    .line 912
    .line 913
    add-int/lit8 v4, v4, -0x2

    .line 914
    .line 915
    if-ltz v4, :cond_2b

    .line 916
    .line 917
    move-object/from16 v32, v12

    .line 918
    .line 919
    move/from16 v33, v13

    .line 920
    .line 921
    move/from16 v6, v16

    .line 922
    .line 923
    :goto_18
    aget-wide v12, v0, v6

    .line 924
    .line 925
    move-wide/from16 v34, v14

    .line 926
    .line 927
    not-long v14, v12

    .line 928
    shl-long v14, v14, v21

    .line 929
    .line 930
    and-long/2addr v14, v12

    .line 931
    and-long v14, v14, v22

    .line 932
    .line 933
    cmp-long v14, v14, v22

    .line 934
    .line 935
    if-eqz v14, :cond_26

    .line 936
    .line 937
    sub-int v14, v6, v4

    .line 938
    .line 939
    not-int v14, v14

    .line 940
    ushr-int/lit8 v14, v14, 0x1f

    .line 941
    .line 942
    const/16 v24, 0x8

    .line 943
    .line 944
    rsub-int/lit8 v14, v14, 0x8

    .line 945
    .line 946
    move/from16 v15, v16

    .line 947
    .line 948
    :goto_19
    if-ge v15, v14, :cond_25

    .line 949
    .line 950
    and-long v36, v12, v19

    .line 951
    .line 952
    cmp-long v36, v36, v17

    .line 953
    .line 954
    if-gez v36, :cond_24

    .line 955
    .line 956
    shl-int/lit8 v33, v6, 0x3

    .line 957
    .line 958
    add-int v33, v33, v15

    .line 959
    .line 960
    move-object/from16 v36, v0

    .line 961
    .line 962
    aget-object v0, v3, v33

    .line 963
    .line 964
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 965
    .line 966
    .line 967
    const/16 v33, 0x1

    .line 968
    .line 969
    :goto_1a
    const/16 v0, 0x8

    .line 970
    .line 971
    goto :goto_1b

    .line 972
    :cond_24
    move-object/from16 v36, v0

    .line 973
    .line 974
    goto :goto_1a

    .line 975
    :goto_1b
    shr-long/2addr v12, v0

    .line 976
    add-int/lit8 v15, v15, 0x1

    .line 977
    .line 978
    move-object/from16 v0, v36

    .line 979
    .line 980
    goto :goto_19

    .line 981
    :cond_25
    move-object/from16 v36, v0

    .line 982
    .line 983
    const/16 v0, 0x8

    .line 984
    .line 985
    if-ne v14, v0, :cond_27

    .line 986
    .line 987
    goto :goto_1c

    .line 988
    :cond_26
    move-object/from16 v36, v0

    .line 989
    .line 990
    :goto_1c
    if-eq v6, v4, :cond_27

    .line 991
    .line 992
    add-int/lit8 v6, v6, 0x1

    .line 993
    .line 994
    move-wide/from16 v14, v34

    .line 995
    .line 996
    move-object/from16 v0, v36

    .line 997
    .line 998
    goto :goto_18

    .line 999
    :cond_27
    move/from16 v13, v33

    .line 1000
    .line 1001
    goto :goto_1d

    .line 1002
    :cond_28
    move-object/from16 v32, v12

    .line 1003
    .line 1004
    move-wide/from16 v34, v14

    .line 1005
    .line 1006
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 1007
    .line 1008
    .line 1009
    const/4 v13, 0x1

    .line 1010
    goto :goto_1d

    .line 1011
    :cond_29
    move-object/from16 v32, v12

    .line 1012
    .line 1013
    move-wide/from16 v34, v14

    .line 1014
    .line 1015
    invoke-virtual {v5, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1016
    .line 1017
    .line 1018
    :goto_1d
    const/16 v15, 0x8

    .line 1019
    .line 1020
    goto :goto_1e

    .line 1021
    :cond_2a
    move-object/from16 p1, v0

    .line 1022
    .line 1023
    move/from16 v29, v3

    .line 1024
    .line 1025
    move-object/from16 v30, v4

    .line 1026
    .line 1027
    move-object/from16 v31, v6

    .line 1028
    .line 1029
    :cond_2b
    move-object/from16 v32, v12

    .line 1030
    .line 1031
    move-wide/from16 v34, v14

    .line 1032
    .line 1033
    goto :goto_1d

    .line 1034
    :goto_1e
    shr-long v3, v34, v15

    .line 1035
    .line 1036
    add-int/lit8 v0, v29, 0x1

    .line 1037
    .line 1038
    move-wide v14, v3

    .line 1039
    move-object/from16 v4, v30

    .line 1040
    .line 1041
    move-object/from16 v6, v31

    .line 1042
    .line 1043
    move-object/from16 v12, v32

    .line 1044
    .line 1045
    move v3, v0

    .line 1046
    move-object/from16 v0, p1

    .line 1047
    .line 1048
    goto/16 :goto_17

    .line 1049
    .line 1050
    :cond_2c
    move-object/from16 p1, v0

    .line 1051
    .line 1052
    move-object/from16 v30, v4

    .line 1053
    .line 1054
    move-object/from16 v31, v6

    .line 1055
    .line 1056
    move-object/from16 v32, v12

    .line 1057
    .line 1058
    const/16 v15, 0x8

    .line 1059
    .line 1060
    if-ne v2, v15, :cond_36

    .line 1061
    .line 1062
    goto :goto_1f

    .line 1063
    :cond_2d
    move-object/from16 p1, v0

    .line 1064
    .line 1065
    move-object/from16 v30, v4

    .line 1066
    .line 1067
    move-object/from16 v31, v6

    .line 1068
    .line 1069
    move-object/from16 v32, v12

    .line 1070
    .line 1071
    :goto_1f
    if-eq v11, v10, :cond_36

    .line 1072
    .line 1073
    add-int/lit8 v11, v11, 0x1

    .line 1074
    .line 1075
    move-object/from16 v0, p1

    .line 1076
    .line 1077
    move-object/from16 v2, v28

    .line 1078
    .line 1079
    move-object/from16 v4, v30

    .line 1080
    .line 1081
    move-object/from16 v6, v31

    .line 1082
    .line 1083
    move-object/from16 v3, v32

    .line 1084
    .line 1085
    goto/16 :goto_16

    .line 1086
    .line 1087
    :cond_2e
    move-object/from16 p1, v0

    .line 1088
    .line 1089
    move-object/from16 v30, v4

    .line 1090
    .line 1091
    move-object/from16 v31, v6

    .line 1092
    .line 1093
    check-cast v2, Ll2/h0;

    .line 1094
    .line 1095
    invoke-virtual {v7, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v0

    .line 1099
    iget-object v3, v2, Ll2/h0;->f:Ll2/n2;

    .line 1100
    .line 1101
    if-nez v3, :cond_2f

    .line 1102
    .line 1103
    move-object/from16 v3, v27

    .line 1104
    .line 1105
    :cond_2f
    invoke-virtual {v2}, Ll2/h0;->o()Ll2/g0;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v4

    .line 1109
    iget-object v4, v4, Ll2/g0;->f:Ljava/lang/Object;

    .line 1110
    .line 1111
    invoke-interface {v3, v4, v0}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1112
    .line 1113
    .line 1114
    move-result v0

    .line 1115
    if-nez v0, :cond_34

    .line 1116
    .line 1117
    invoke-virtual {v8, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v0

    .line 1121
    if-eqz v0, :cond_36

    .line 1122
    .line 1123
    instance-of v2, v0, Landroidx/collection/r0;

    .line 1124
    .line 1125
    if-eqz v2, :cond_33

    .line 1126
    .line 1127
    check-cast v0, Landroidx/collection/r0;

    .line 1128
    .line 1129
    iget-object v2, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 1130
    .line 1131
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 1132
    .line 1133
    array-length v3, v0

    .line 1134
    const/16 v26, 0x2

    .line 1135
    .line 1136
    add-int/lit8 v3, v3, -0x2

    .line 1137
    .line 1138
    if-ltz v3, :cond_36

    .line 1139
    .line 1140
    move/from16 v4, v16

    .line 1141
    .line 1142
    :goto_20
    aget-wide v10, v0, v4

    .line 1143
    .line 1144
    not-long v14, v10

    .line 1145
    shl-long v14, v14, v21

    .line 1146
    .line 1147
    and-long/2addr v14, v10

    .line 1148
    and-long v14, v14, v22

    .line 1149
    .line 1150
    cmp-long v6, v14, v22

    .line 1151
    .line 1152
    if-eqz v6, :cond_32

    .line 1153
    .line 1154
    sub-int v6, v4, v3

    .line 1155
    .line 1156
    not-int v6, v6

    .line 1157
    ushr-int/lit8 v6, v6, 0x1f

    .line 1158
    .line 1159
    const/16 v24, 0x8

    .line 1160
    .line 1161
    rsub-int/lit8 v14, v6, 0x8

    .line 1162
    .line 1163
    move/from16 v6, v16

    .line 1164
    .line 1165
    :goto_21
    if-ge v6, v14, :cond_31

    .line 1166
    .line 1167
    and-long v28, v10, v19

    .line 1168
    .line 1169
    cmp-long v12, v28, v17

    .line 1170
    .line 1171
    if-gez v12, :cond_30

    .line 1172
    .line 1173
    shl-int/lit8 v12, v4, 0x3

    .line 1174
    .line 1175
    add-int/2addr v12, v6

    .line 1176
    aget-object v12, v2, v12

    .line 1177
    .line 1178
    invoke-virtual {v9, v12}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 1179
    .line 1180
    .line 1181
    const/4 v13, 0x1

    .line 1182
    :cond_30
    const/16 v15, 0x8

    .line 1183
    .line 1184
    shr-long/2addr v10, v15

    .line 1185
    add-int/lit8 v6, v6, 0x1

    .line 1186
    .line 1187
    goto :goto_21

    .line 1188
    :cond_31
    const/16 v15, 0x8

    .line 1189
    .line 1190
    if-ne v14, v15, :cond_36

    .line 1191
    .line 1192
    :cond_32
    if-eq v4, v3, :cond_36

    .line 1193
    .line 1194
    add-int/lit8 v4, v4, 0x1

    .line 1195
    .line 1196
    goto :goto_20

    .line 1197
    :cond_33
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 1198
    .line 1199
    .line 1200
    const/4 v13, 0x1

    .line 1201
    goto :goto_22

    .line 1202
    :cond_34
    invoke-virtual {v5, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 1203
    .line 1204
    .line 1205
    goto :goto_22

    .line 1206
    :cond_35
    move-object/from16 p1, v0

    .line 1207
    .line 1208
    move-object/from16 v30, v4

    .line 1209
    .line 1210
    move-object/from16 v31, v6

    .line 1211
    .line 1212
    :cond_36
    :goto_22
    invoke-virtual {v8, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1213
    .line 1214
    .line 1215
    move-result-object v0

    .line 1216
    if-eqz v0, :cond_3b

    .line 1217
    .line 1218
    instance-of v1, v0, Landroidx/collection/r0;

    .line 1219
    .line 1220
    if-eqz v1, :cond_3a

    .line 1221
    .line 1222
    check-cast v0, Landroidx/collection/r0;

    .line 1223
    .line 1224
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 1225
    .line 1226
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 1227
    .line 1228
    array-length v2, v0

    .line 1229
    const/16 v26, 0x2

    .line 1230
    .line 1231
    add-int/lit8 v2, v2, -0x2

    .line 1232
    .line 1233
    if-ltz v2, :cond_3b

    .line 1234
    .line 1235
    move/from16 v3, v16

    .line 1236
    .line 1237
    :goto_23
    aget-wide v10, v0, v3

    .line 1238
    .line 1239
    not-long v14, v10

    .line 1240
    shl-long v14, v14, v21

    .line 1241
    .line 1242
    and-long/2addr v14, v10

    .line 1243
    and-long v14, v14, v22

    .line 1244
    .line 1245
    cmp-long v4, v14, v22

    .line 1246
    .line 1247
    if-eqz v4, :cond_39

    .line 1248
    .line 1249
    sub-int v4, v3, v2

    .line 1250
    .line 1251
    not-int v4, v4

    .line 1252
    ushr-int/lit8 v4, v4, 0x1f

    .line 1253
    .line 1254
    const/16 v24, 0x8

    .line 1255
    .line 1256
    rsub-int/lit8 v14, v4, 0x8

    .line 1257
    .line 1258
    move/from16 v4, v16

    .line 1259
    .line 1260
    :goto_24
    if-ge v4, v14, :cond_38

    .line 1261
    .line 1262
    and-long v28, v10, v19

    .line 1263
    .line 1264
    cmp-long v6, v28, v17

    .line 1265
    .line 1266
    if-gez v6, :cond_37

    .line 1267
    .line 1268
    shl-int/lit8 v6, v3, 0x3

    .line 1269
    .line 1270
    add-int/2addr v6, v4

    .line 1271
    aget-object v6, v1, v6

    .line 1272
    .line 1273
    invoke-virtual {v9, v6}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 1274
    .line 1275
    .line 1276
    const/4 v13, 0x1

    .line 1277
    :cond_37
    const/16 v15, 0x8

    .line 1278
    .line 1279
    shr-long/2addr v10, v15

    .line 1280
    add-int/lit8 v4, v4, 0x1

    .line 1281
    .line 1282
    goto :goto_24

    .line 1283
    :cond_38
    const/16 v15, 0x8

    .line 1284
    .line 1285
    if-ne v14, v15, :cond_3b

    .line 1286
    .line 1287
    :cond_39
    if-eq v3, v2, :cond_3b

    .line 1288
    .line 1289
    add-int/lit8 v3, v3, 0x1

    .line 1290
    .line 1291
    goto :goto_23

    .line 1292
    :cond_3a
    invoke-virtual {v9, v0}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 1293
    .line 1294
    .line 1295
    const/4 v13, 0x1

    .line 1296
    :cond_3b
    :goto_25
    move-object/from16 v0, p1

    .line 1297
    .line 1298
    move-object/from16 v4, v30

    .line 1299
    .line 1300
    move-object/from16 v6, v31

    .line 1301
    .line 1302
    goto/16 :goto_15

    .line 1303
    .line 1304
    :cond_3c
    :goto_26
    iget v0, v5, Ln2/b;->f:I

    .line 1305
    .line 1306
    if-eqz v0, :cond_47

    .line 1307
    .line 1308
    iget-object v1, v5, Ln2/b;->d:[Ljava/lang/Object;

    .line 1309
    .line 1310
    move/from16 v2, v16

    .line 1311
    .line 1312
    :goto_27
    if-ge v2, v0, :cond_46

    .line 1313
    .line 1314
    aget-object v3, v1, v2

    .line 1315
    .line 1316
    check-cast v3, Ll2/h0;

    .line 1317
    .line 1318
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v4

    .line 1322
    invoke-virtual {v4}, Lv2/f;->g()J

    .line 1323
    .line 1324
    .line 1325
    move-result-wide v6

    .line 1326
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 1327
    .line 1328
    .line 1329
    move-result v4

    .line 1330
    invoke-virtual {v8, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v6

    .line 1334
    if-eqz v6, :cond_44

    .line 1335
    .line 1336
    instance-of v7, v6, Landroidx/collection/r0;

    .line 1337
    .line 1338
    move-object/from16 v9, p0

    .line 1339
    .line 1340
    iget-object v10, v9, Lv2/q;->f:Landroidx/collection/q0;

    .line 1341
    .line 1342
    if-eqz v7, :cond_42

    .line 1343
    .line 1344
    check-cast v6, Landroidx/collection/r0;

    .line 1345
    .line 1346
    iget-object v7, v6, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 1347
    .line 1348
    iget-object v6, v6, Landroidx/collection/r0;->a:[J

    .line 1349
    .line 1350
    array-length v11, v6

    .line 1351
    const/16 v26, 0x2

    .line 1352
    .line 1353
    add-int/lit8 v11, v11, -0x2

    .line 1354
    .line 1355
    if-ltz v11, :cond_41

    .line 1356
    .line 1357
    move/from16 v12, v16

    .line 1358
    .line 1359
    :goto_28
    aget-wide v14, v6, v12

    .line 1360
    .line 1361
    move/from16 v25, v0

    .line 1362
    .line 1363
    move-object/from16 v27, v1

    .line 1364
    .line 1365
    not-long v0, v14

    .line 1366
    shl-long v0, v0, v21

    .line 1367
    .line 1368
    and-long/2addr v0, v14

    .line 1369
    and-long v0, v0, v22

    .line 1370
    .line 1371
    cmp-long v0, v0, v22

    .line 1372
    .line 1373
    if-eqz v0, :cond_40

    .line 1374
    .line 1375
    sub-int v0, v12, v11

    .line 1376
    .line 1377
    not-int v0, v0

    .line 1378
    ushr-int/lit8 v0, v0, 0x1f

    .line 1379
    .line 1380
    const/16 v24, 0x8

    .line 1381
    .line 1382
    rsub-int/lit8 v0, v0, 0x8

    .line 1383
    .line 1384
    move/from16 v1, v16

    .line 1385
    .line 1386
    :goto_29
    if-ge v1, v0, :cond_3f

    .line 1387
    .line 1388
    and-long v28, v14, v19

    .line 1389
    .line 1390
    cmp-long v28, v28, v17

    .line 1391
    .line 1392
    if-gez v28, :cond_3e

    .line 1393
    .line 1394
    shl-int/lit8 v28, v12, 0x3

    .line 1395
    .line 1396
    add-int v28, v28, v1

    .line 1397
    .line 1398
    move/from16 v29, v1

    .line 1399
    .line 1400
    aget-object v1, v7, v28

    .line 1401
    .line 1402
    invoke-virtual {v10, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v28

    .line 1406
    check-cast v28, Landroidx/collection/h0;

    .line 1407
    .line 1408
    move/from16 v30, v2

    .line 1409
    .line 1410
    if-nez v28, :cond_3d

    .line 1411
    .line 1412
    new-instance v2, Landroidx/collection/h0;

    .line 1413
    .line 1414
    invoke-direct {v2}, Landroidx/collection/h0;-><init>()V

    .line 1415
    .line 1416
    .line 1417
    invoke-virtual {v10, v1, v2}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1418
    .line 1419
    .line 1420
    goto :goto_2a

    .line 1421
    :cond_3d
    move-object/from16 v2, v28

    .line 1422
    .line 1423
    :goto_2a
    invoke-virtual {v9, v3, v4, v1, v2}, Lv2/q;->c(Ljava/lang/Object;ILjava/lang/Object;Landroidx/collection/h0;)V

    .line 1424
    .line 1425
    .line 1426
    :goto_2b
    const/16 v1, 0x8

    .line 1427
    .line 1428
    goto :goto_2c

    .line 1429
    :cond_3e
    move/from16 v29, v1

    .line 1430
    .line 1431
    move/from16 v30, v2

    .line 1432
    .line 1433
    goto :goto_2b

    .line 1434
    :goto_2c
    shr-long/2addr v14, v1

    .line 1435
    add-int/lit8 v2, v29, 0x1

    .line 1436
    .line 1437
    move v1, v2

    .line 1438
    move/from16 v2, v30

    .line 1439
    .line 1440
    goto :goto_29

    .line 1441
    :cond_3f
    move/from16 v30, v2

    .line 1442
    .line 1443
    const/16 v1, 0x8

    .line 1444
    .line 1445
    if-ne v0, v1, :cond_45

    .line 1446
    .line 1447
    goto :goto_2d

    .line 1448
    :cond_40
    move/from16 v30, v2

    .line 1449
    .line 1450
    const/16 v1, 0x8

    .line 1451
    .line 1452
    :goto_2d
    if-eq v12, v11, :cond_45

    .line 1453
    .line 1454
    add-int/lit8 v12, v12, 0x1

    .line 1455
    .line 1456
    move/from16 v0, v25

    .line 1457
    .line 1458
    move-object/from16 v1, v27

    .line 1459
    .line 1460
    move/from16 v2, v30

    .line 1461
    .line 1462
    goto :goto_28

    .line 1463
    :cond_41
    move/from16 v25, v0

    .line 1464
    .line 1465
    move-object/from16 v27, v1

    .line 1466
    .line 1467
    move/from16 v30, v2

    .line 1468
    .line 1469
    const/16 v1, 0x8

    .line 1470
    .line 1471
    goto :goto_2e

    .line 1472
    :cond_42
    move/from16 v25, v0

    .line 1473
    .line 1474
    move-object/from16 v27, v1

    .line 1475
    .line 1476
    move/from16 v30, v2

    .line 1477
    .line 1478
    const/16 v1, 0x8

    .line 1479
    .line 1480
    const/16 v26, 0x2

    .line 1481
    .line 1482
    invoke-virtual {v10, v6}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1483
    .line 1484
    .line 1485
    move-result-object v0

    .line 1486
    check-cast v0, Landroidx/collection/h0;

    .line 1487
    .line 1488
    if-nez v0, :cond_43

    .line 1489
    .line 1490
    new-instance v0, Landroidx/collection/h0;

    .line 1491
    .line 1492
    invoke-direct {v0}, Landroidx/collection/h0;-><init>()V

    .line 1493
    .line 1494
    .line 1495
    invoke-virtual {v10, v6, v0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1496
    .line 1497
    .line 1498
    :cond_43
    invoke-virtual {v9, v3, v4, v6, v0}, Lv2/q;->c(Ljava/lang/Object;ILjava/lang/Object;Landroidx/collection/h0;)V

    .line 1499
    .line 1500
    .line 1501
    goto :goto_2e

    .line 1502
    :cond_44
    move/from16 v25, v0

    .line 1503
    .line 1504
    move-object/from16 v27, v1

    .line 1505
    .line 1506
    move/from16 v30, v2

    .line 1507
    .line 1508
    const/16 v1, 0x8

    .line 1509
    .line 1510
    const/16 v26, 0x2

    .line 1511
    .line 1512
    move-object/from16 v9, p0

    .line 1513
    .line 1514
    :cond_45
    :goto_2e
    add-int/lit8 v2, v30, 0x1

    .line 1515
    .line 1516
    move/from16 v0, v25

    .line 1517
    .line 1518
    move-object/from16 v1, v27

    .line 1519
    .line 1520
    goto/16 :goto_27

    .line 1521
    .line 1522
    :cond_46
    invoke-virtual {v5}, Ln2/b;->i()V

    .line 1523
    .line 1524
    .line 1525
    :cond_47
    return v13
.end method

.method public final c(Ljava/lang/Object;ILjava/lang/Object;Landroidx/collection/h0;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p4

    .line 8
    .line 9
    iget v4, v0, Lv2/q;->j:I

    .line 10
    .line 11
    if-lez v4, :cond_0

    .line 12
    .line 13
    goto/16 :goto_3

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v3, v1}, Landroidx/collection/h0;->c(Ljava/lang/Object;)I

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    if-gez v4, :cond_1

    .line 20
    .line 21
    not-int v4, v4

    .line 22
    const/4 v6, -0x1

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    iget-object v6, v3, Landroidx/collection/h0;->c:[I

    .line 25
    .line 26
    aget v6, v6, v4

    .line 27
    .line 28
    :goto_0
    iget-object v7, v3, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 29
    .line 30
    aput-object v1, v7, v4

    .line 31
    .line 32
    iget-object v3, v3, Landroidx/collection/h0;->c:[I

    .line 33
    .line 34
    aput v2, v3, v4

    .line 35
    .line 36
    instance-of v3, v1, Ll2/h0;

    .line 37
    .line 38
    const/4 v4, 0x2

    .line 39
    if-eqz v3, :cond_6

    .line 40
    .line 41
    if-eq v6, v2, :cond_6

    .line 42
    .line 43
    move-object v2, v1

    .line 44
    check-cast v2, Ll2/h0;

    .line 45
    .line 46
    invoke-virtual {v2}, Ll2/h0;->o()Ll2/g0;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    iget-object v3, v0, Lv2/q;->l:Ljava/util/HashMap;

    .line 51
    .line 52
    iget-object v7, v2, Ll2/g0;->f:Ljava/lang/Object;

    .line 53
    .line 54
    invoke-virtual {v3, v1, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    iget-object v2, v2, Ll2/g0;->e:Landroidx/collection/h0;

    .line 58
    .line 59
    iget-object v3, v0, Lv2/q;->k:Landroidx/collection/q0;

    .line 60
    .line 61
    invoke-static {v3, v1}, Ljp/v1;->j(Landroidx/collection/q0;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object v7, v2, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 65
    .line 66
    iget-object v2, v2, Landroidx/collection/h0;->a:[J

    .line 67
    .line 68
    array-length v8, v2

    .line 69
    sub-int/2addr v8, v4

    .line 70
    if-ltz v8, :cond_6

    .line 71
    .line 72
    const/4 v10, 0x0

    .line 73
    :goto_1
    aget-wide v11, v2, v10

    .line 74
    .line 75
    not-long v13, v11

    .line 76
    const/4 v15, 0x7

    .line 77
    shl-long/2addr v13, v15

    .line 78
    and-long/2addr v13, v11

    .line 79
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 80
    .line 81
    .line 82
    .line 83
    .line 84
    and-long/2addr v13, v15

    .line 85
    cmp-long v13, v13, v15

    .line 86
    .line 87
    if-eqz v13, :cond_5

    .line 88
    .line 89
    sub-int v13, v10, v8

    .line 90
    .line 91
    not-int v13, v13

    .line 92
    ushr-int/lit8 v13, v13, 0x1f

    .line 93
    .line 94
    const/16 v14, 0x8

    .line 95
    .line 96
    rsub-int/lit8 v13, v13, 0x8

    .line 97
    .line 98
    const/4 v15, 0x0

    .line 99
    :goto_2
    if-ge v15, v13, :cond_4

    .line 100
    .line 101
    const-wide/16 v16, 0xff

    .line 102
    .line 103
    and-long v16, v11, v16

    .line 104
    .line 105
    const-wide/16 v18, 0x80

    .line 106
    .line 107
    cmp-long v16, v16, v18

    .line 108
    .line 109
    if-gez v16, :cond_3

    .line 110
    .line 111
    shl-int/lit8 v16, v10, 0x3

    .line 112
    .line 113
    add-int v16, v16, v15

    .line 114
    .line 115
    aget-object v16, v7, v16

    .line 116
    .line 117
    move-object/from16 v9, v16

    .line 118
    .line 119
    check-cast v9, Lv2/t;

    .line 120
    .line 121
    instance-of v5, v9, Lv2/u;

    .line 122
    .line 123
    if-eqz v5, :cond_2

    .line 124
    .line 125
    move-object v5, v9

    .line 126
    check-cast v5, Lv2/u;

    .line 127
    .line 128
    invoke-virtual {v5, v4}, Lv2/u;->b(I)V

    .line 129
    .line 130
    .line 131
    :cond_2
    invoke-static {v3, v9, v1}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    :cond_3
    shr-long/2addr v11, v14

    .line 135
    add-int/lit8 v15, v15, 0x1

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_4
    if-ne v13, v14, :cond_6

    .line 139
    .line 140
    :cond_5
    if-eq v10, v8, :cond_6

    .line 141
    .line 142
    add-int/lit8 v10, v10, 0x1

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_6
    const/4 v2, -0x1

    .line 146
    if-ne v6, v2, :cond_8

    .line 147
    .line 148
    instance-of v2, v1, Lv2/u;

    .line 149
    .line 150
    if-eqz v2, :cond_7

    .line 151
    .line 152
    move-object v2, v1

    .line 153
    check-cast v2, Lv2/u;

    .line 154
    .line 155
    invoke-virtual {v2, v4}, Lv2/u;->b(I)V

    .line 156
    .line 157
    .line 158
    :cond_7
    iget-object v0, v0, Lv2/q;->e:Landroidx/collection/q0;

    .line 159
    .line 160
    move-object/from16 v2, p3

    .line 161
    .line 162
    invoke-static {v0, v1, v2}, Ljp/v1;->a(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    :cond_8
    :goto_3
    return-void
.end method

.method public final d(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lv2/q;->e:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-static {v0, p2, p1}, Ljp/v1;->i(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    instance-of p1, p2, Ll2/h0;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    iget-object p1, p0, Lv2/q;->k:Landroidx/collection/q0;

    .line 17
    .line 18
    invoke-static {p1, p2}, Ljp/v1;->j(Landroidx/collection/q0;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lv2/q;->l:Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public final e()V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lv2/q;->f:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v2, v1, Landroidx/collection/q0;->a:[J

    .line 6
    .line 7
    array-length v3, v2

    .line 8
    add-int/lit8 v3, v3, -0x2

    .line 9
    .line 10
    if-ltz v3, :cond_9

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    :goto_0
    aget-wide v6, v2, v5

    .line 14
    .line 15
    not-long v8, v6

    .line 16
    const/4 v10, 0x7

    .line 17
    shl-long/2addr v8, v10

    .line 18
    and-long/2addr v8, v6

    .line 19
    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    and-long/2addr v8, v11

    .line 25
    cmp-long v8, v8, v11

    .line 26
    .line 27
    if-eqz v8, :cond_8

    .line 28
    .line 29
    sub-int v8, v5, v3

    .line 30
    .line 31
    not-int v8, v8

    .line 32
    ushr-int/lit8 v8, v8, 0x1f

    .line 33
    .line 34
    const/16 v9, 0x8

    .line 35
    .line 36
    rsub-int/lit8 v8, v8, 0x8

    .line 37
    .line 38
    const/4 v13, 0x0

    .line 39
    :goto_1
    if-ge v13, v8, :cond_7

    .line 40
    .line 41
    const-wide/16 v14, 0xff

    .line 42
    .line 43
    and-long v16, v6, v14

    .line 44
    .line 45
    const-wide/16 v18, 0x80

    .line 46
    .line 47
    cmp-long v16, v16, v18

    .line 48
    .line 49
    if-gez v16, :cond_6

    .line 50
    .line 51
    shl-int/lit8 v16, v5, 0x3

    .line 52
    .line 53
    add-int v4, v16, v13

    .line 54
    .line 55
    move/from16 v16, v10

    .line 56
    .line 57
    iget-object v10, v1, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 58
    .line 59
    aget-object v10, v10, v4

    .line 60
    .line 61
    move-wide/from16 v20, v11

    .line 62
    .line 63
    iget-object v11, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 64
    .line 65
    aget-object v11, v11, v4

    .line 66
    .line 67
    check-cast v11, Landroidx/collection/h0;

    .line 68
    .line 69
    const-string v12, "null cannot be cast to non-null type androidx.compose.ui.node.OwnerScope"

    .line 70
    .line 71
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    move-object v12, v10

    .line 75
    check-cast v12, Lv3/p1;

    .line 76
    .line 77
    invoke-interface {v12}, Lv3/p1;->e0()Z

    .line 78
    .line 79
    .line 80
    move-result v12

    .line 81
    if-nez v12, :cond_3

    .line 82
    .line 83
    move-wide/from16 v22, v14

    .line 84
    .line 85
    iget-object v14, v11, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 86
    .line 87
    iget-object v15, v11, Landroidx/collection/h0;->c:[I

    .line 88
    .line 89
    iget-object v11, v11, Landroidx/collection/h0;->a:[J

    .line 90
    .line 91
    move/from16 v24, v9

    .line 92
    .line 93
    array-length v9, v11

    .line 94
    add-int/lit8 v9, v9, -0x2

    .line 95
    .line 96
    if-ltz v9, :cond_3

    .line 97
    .line 98
    move-object/from16 v25, v2

    .line 99
    .line 100
    move-wide/from16 v26, v6

    .line 101
    .line 102
    const/4 v2, 0x0

    .line 103
    :goto_2
    aget-wide v6, v11, v2

    .line 104
    .line 105
    move-object/from16 v29, v11

    .line 106
    .line 107
    move/from16 v28, v12

    .line 108
    .line 109
    not-long v11, v6

    .line 110
    shl-long v11, v11, v16

    .line 111
    .line 112
    and-long/2addr v11, v6

    .line 113
    and-long v11, v11, v20

    .line 114
    .line 115
    cmp-long v11, v11, v20

    .line 116
    .line 117
    if-eqz v11, :cond_2

    .line 118
    .line 119
    sub-int v11, v2, v9

    .line 120
    .line 121
    not-int v11, v11

    .line 122
    ushr-int/lit8 v11, v11, 0x1f

    .line 123
    .line 124
    rsub-int/lit8 v11, v11, 0x8

    .line 125
    .line 126
    const/4 v12, 0x0

    .line 127
    :goto_3
    if-ge v12, v11, :cond_1

    .line 128
    .line 129
    and-long v30, v6, v22

    .line 130
    .line 131
    cmp-long v30, v30, v18

    .line 132
    .line 133
    if-gez v30, :cond_0

    .line 134
    .line 135
    shl-int/lit8 v30, v2, 0x3

    .line 136
    .line 137
    add-int v30, v30, v12

    .line 138
    .line 139
    move-wide/from16 v31, v6

    .line 140
    .line 141
    aget-object v6, v14, v30

    .line 142
    .line 143
    aget v7, v15, v30

    .line 144
    .line 145
    invoke-virtual {v0, v10, v6}, Lv2/q;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_0
    move-wide/from16 v31, v6

    .line 150
    .line 151
    :goto_4
    shr-long v6, v31, v24

    .line 152
    .line 153
    add-int/lit8 v12, v12, 0x1

    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_1
    move/from16 v6, v24

    .line 157
    .line 158
    if-ne v11, v6, :cond_4

    .line 159
    .line 160
    :cond_2
    if-eq v2, v9, :cond_4

    .line 161
    .line 162
    add-int/lit8 v2, v2, 0x1

    .line 163
    .line 164
    move/from16 v12, v28

    .line 165
    .line 166
    move-object/from16 v11, v29

    .line 167
    .line 168
    const/16 v24, 0x8

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_3
    move-object/from16 v25, v2

    .line 172
    .line 173
    move-wide/from16 v26, v6

    .line 174
    .line 175
    move/from16 v28, v12

    .line 176
    .line 177
    :cond_4
    if-nez v28, :cond_5

    .line 178
    .line 179
    invoke-virtual {v1, v4}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    :cond_5
    const/16 v6, 0x8

    .line 183
    .line 184
    goto :goto_5

    .line 185
    :cond_6
    move-object/from16 v25, v2

    .line 186
    .line 187
    move-wide/from16 v26, v6

    .line 188
    .line 189
    move/from16 v16, v10

    .line 190
    .line 191
    move-wide/from16 v20, v11

    .line 192
    .line 193
    move v6, v9

    .line 194
    :goto_5
    shr-long v9, v26, v6

    .line 195
    .line 196
    add-int/lit8 v13, v13, 0x1

    .line 197
    .line 198
    move-wide v11, v9

    .line 199
    move v9, v6

    .line 200
    move-wide v6, v11

    .line 201
    move/from16 v10, v16

    .line 202
    .line 203
    move-wide/from16 v11, v20

    .line 204
    .line 205
    move-object/from16 v2, v25

    .line 206
    .line 207
    goto/16 :goto_1

    .line 208
    .line 209
    :cond_7
    move-object/from16 v25, v2

    .line 210
    .line 211
    move v6, v9

    .line 212
    if-ne v8, v6, :cond_9

    .line 213
    .line 214
    goto :goto_6

    .line 215
    :cond_8
    move-object/from16 v25, v2

    .line 216
    .line 217
    :goto_6
    if-eq v5, v3, :cond_9

    .line 218
    .line 219
    add-int/lit8 v5, v5, 0x1

    .line 220
    .line 221
    move-object/from16 v2, v25

    .line 222
    .line 223
    goto/16 :goto_0

    .line 224
    .line 225
    :cond_9
    return-void
.end method
