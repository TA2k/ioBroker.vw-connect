.class public final Lol/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lil/j;

.field public final b:Lpv/g;

.field public final c:Lpv/g;


# direct methods
.method public constructor <init>(Lil/j;Lpv/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lol/f;->a:Lil/j;

    .line 5
    .line 6
    iput-object p2, p0, Lol/f;->b:Lpv/g;

    .line 7
    .line 8
    new-instance v0, Lpv/g;

    .line 9
    .line 10
    invoke-direct {v0, p1, p2}, Lpv/g;-><init>(Lil/j;Lpv/g;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lol/f;->c:Lpv/g;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lol/f;Lnl/m;Lil/c;Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p7

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    instance-of v1, v0, Lol/b;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    move-object v1, v0

    .line 11
    check-cast v1, Lol/b;

    .line 12
    .line 13
    iget v2, v1, Lol/b;->n:I

    .line 14
    .line 15
    const/high16 v3, -0x80000000

    .line 16
    .line 17
    and-int v4, v2, v3

    .line 18
    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    sub-int/2addr v2, v3

    .line 22
    iput v2, v1, Lol/b;->n:I

    .line 23
    .line 24
    move-object/from16 v2, p0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v1, Lol/b;

    .line 28
    .line 29
    move-object/from16 v2, p0

    .line 30
    .line 31
    invoke-direct {v1, v2, v0}, Lol/b;-><init>(Lol/f;Lrx0/c;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget-object v0, v1, Lol/b;->l:Ljava/lang/Object;

    .line 35
    .line 36
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    iget v4, v1, Lol/b;->n:I

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    const/4 v6, 0x1

    .line 42
    if-eqz v4, :cond_2

    .line 43
    .line 44
    if-ne v4, v6, :cond_1

    .line 45
    .line 46
    iget v2, v1, Lol/b;->k:I

    .line 47
    .line 48
    iget-object v4, v1, Lol/b;->j:Lil/d;

    .line 49
    .line 50
    iget-object v7, v1, Lol/b;->i:Ltl/l;

    .line 51
    .line 52
    iget-object v8, v1, Lol/b;->h:Ljava/lang/Object;

    .line 53
    .line 54
    iget-object v9, v1, Lol/b;->g:Ltl/h;

    .line 55
    .line 56
    iget-object v10, v1, Lol/b;->f:Lil/c;

    .line 57
    .line 58
    iget-object v11, v1, Lol/b;->e:Lnl/m;

    .line 59
    .line 60
    iget-object v12, v1, Lol/b;->d:Lol/f;

    .line 61
    .line 62
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object/from16 v16, v12

    .line 66
    .line 67
    move-object v12, v1

    .line 68
    move-object v1, v10

    .line 69
    move v10, v2

    .line 70
    move-object/from16 v2, v16

    .line 71
    .line 72
    move-object/from16 v16, v9

    .line 73
    .line 74
    move-object v9, v4

    .line 75
    move-object/from16 v4, v16

    .line 76
    .line 77
    move-object/from16 v16, v8

    .line 78
    .line 79
    move-object v8, v7

    .line 80
    move-object/from16 v7, v16

    .line 81
    .line 82
    goto/16 :goto_3

    .line 83
    .line 84
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 87
    .line 88
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw v0

    .line 92
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    const/4 v0, 0x0

    .line 96
    move-object/from16 v4, p3

    .line 97
    .line 98
    move-object/from16 v7, p4

    .line 99
    .line 100
    move-object/from16 v8, p5

    .line 101
    .line 102
    move-object/from16 v9, p6

    .line 103
    .line 104
    move v10, v0

    .line 105
    move-object v11, v1

    .line 106
    move-object/from16 v0, p1

    .line 107
    .line 108
    move-object/from16 v1, p2

    .line 109
    .line 110
    :goto_1
    iget-object v12, v2, Lol/f;->a:Lil/j;

    .line 111
    .line 112
    iget-object v12, v1, Lil/c;->e:Ljava/util/List;

    .line 113
    .line 114
    invoke-interface {v12}, Ljava/util/List;->size()I

    .line 115
    .line 116
    .line 117
    move-result v13

    .line 118
    if-ge v10, v13, :cond_3

    .line 119
    .line 120
    invoke-interface {v12, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v12

    .line 124
    check-cast v12, Lkl/b;

    .line 125
    .line 126
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    new-instance v13, Lkl/d;

    .line 130
    .line 131
    iget-object v14, v0, Lnl/m;->a:Lkl/l;

    .line 132
    .line 133
    iget-object v15, v12, Lkl/b;->b:Lez0/i;

    .line 134
    .line 135
    iget-object v12, v12, Lkl/b;->a:Lkl/h;

    .line 136
    .line 137
    invoke-direct {v13, v14, v8, v15, v12}, Lkl/d;-><init>(Lkl/l;Ltl/l;Lez0/e;Lkl/h;)V

    .line 138
    .line 139
    .line 140
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 141
    .line 142
    .line 143
    move-result-object v10

    .line 144
    new-instance v12, Llx0/l;

    .line 145
    .line 146
    invoke-direct {v12, v13, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_3
    move-object v12, v5

    .line 151
    :goto_2
    if-eqz v12, :cond_8

    .line 152
    .line 153
    iget-object v10, v12, Llx0/l;->d:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v10, Lkl/d;

    .line 156
    .line 157
    iget-object v12, v12, Llx0/l;->e:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v12, Ljava/lang/Number;

    .line 160
    .line 161
    invoke-virtual {v12}, Ljava/lang/Number;->intValue()I

    .line 162
    .line 163
    .line 164
    move-result v12

    .line 165
    add-int/2addr v12, v6

    .line 166
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    iput-object v2, v11, Lol/b;->d:Lol/f;

    .line 170
    .line 171
    iput-object v0, v11, Lol/b;->e:Lnl/m;

    .line 172
    .line 173
    iput-object v1, v11, Lol/b;->f:Lil/c;

    .line 174
    .line 175
    iput-object v4, v11, Lol/b;->g:Ltl/h;

    .line 176
    .line 177
    iput-object v7, v11, Lol/b;->h:Ljava/lang/Object;

    .line 178
    .line 179
    iput-object v8, v11, Lol/b;->i:Ltl/l;

    .line 180
    .line 181
    iput-object v9, v11, Lol/b;->j:Lil/d;

    .line 182
    .line 183
    iput v12, v11, Lol/b;->k:I

    .line 184
    .line 185
    iput v6, v11, Lol/b;->n:I

    .line 186
    .line 187
    invoke-virtual {v10, v11}, Lkl/d;->a(Lrx0/c;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v10

    .line 191
    if-ne v10, v3, :cond_4

    .line 192
    .line 193
    return-object v3

    .line 194
    :cond_4
    move-object/from16 v16, v11

    .line 195
    .line 196
    move-object v11, v0

    .line 197
    move-object v0, v10

    .line 198
    move v10, v12

    .line 199
    move-object/from16 v12, v16

    .line 200
    .line 201
    :goto_3
    check-cast v0, Lkl/f;

    .line 202
    .line 203
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 204
    .line 205
    .line 206
    if-eqz v0, :cond_7

    .line 207
    .line 208
    new-instance v1, Lol/a;

    .line 209
    .line 210
    iget-object v2, v0, Lkl/f;->a:Landroid/graphics/drawable/BitmapDrawable;

    .line 211
    .line 212
    iget-boolean v0, v0, Lkl/f;->b:Z

    .line 213
    .line 214
    iget-object v3, v11, Lnl/m;->c:Lkl/e;

    .line 215
    .line 216
    iget-object v4, v11, Lnl/m;->a:Lkl/l;

    .line 217
    .line 218
    instance-of v6, v4, Lkl/k;

    .line 219
    .line 220
    if-eqz v6, :cond_5

    .line 221
    .line 222
    check-cast v4, Lkl/k;

    .line 223
    .line 224
    goto :goto_4

    .line 225
    :cond_5
    move-object v4, v5

    .line 226
    :goto_4
    if-eqz v4, :cond_6

    .line 227
    .line 228
    iget-object v5, v4, Lkl/k;->f:Ljava/lang/String;

    .line 229
    .line 230
    :cond_6
    invoke-direct {v1, v2, v0, v3, v5}, Lol/a;-><init>(Landroid/graphics/drawable/Drawable;ZLkl/e;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    return-object v1

    .line 234
    :cond_7
    move-object v0, v11

    .line 235
    move-object v11, v12

    .line 236
    goto :goto_1

    .line 237
    :cond_8
    const-string v0, "Unable to create a decoder that supports: "

    .line 238
    .line 239
    invoke-static {v7, v0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 244
    .line 245
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    throw v1
.end method

.method public static final b(Lol/f;Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;Lrx0/c;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p5

    .line 4
    .line 5
    instance-of v2, v1, Lol/c;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lol/c;

    .line 11
    .line 12
    iget v3, v2, Lol/c;->n:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lol/c;->n:I

    .line 22
    .line 23
    :goto_0
    move-object v6, v2

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    new-instance v2, Lol/c;

    .line 26
    .line 27
    invoke-direct {v2, v0, v1}, Lol/c;-><init>(Lol/f;Lrx0/c;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :goto_1
    iget-object v1, v6, Lol/c;->l:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v2, v6, Lol/c;->n:I

    .line 36
    .line 37
    const/4 v8, 0x3

    .line 38
    const/4 v9, 0x2

    .line 39
    const/4 v3, 0x1

    .line 40
    const/4 v10, 0x0

    .line 41
    if-eqz v2, :cond_4

    .line 42
    .line 43
    if-eq v2, v3, :cond_3

    .line 44
    .line 45
    if-eq v2, v9, :cond_2

    .line 46
    .line 47
    if-ne v2, v8, :cond_1

    .line 48
    .line 49
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_9

    .line 53
    .line 54
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_2
    iget-object v2, v6, Lol/c;->h:Lkotlin/jvm/internal/f0;

    .line 63
    .line 64
    iget-object v0, v6, Lol/c;->g:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Lkotlin/jvm/internal/f0;

    .line 67
    .line 68
    iget-object v3, v6, Lol/c;->f:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v3, Lil/d;

    .line 71
    .line 72
    iget-object v4, v6, Lol/c;->e:Ltl/h;

    .line 73
    .line 74
    iget-object v5, v6, Lol/c;->d:Lol/f;

    .line 75
    .line 76
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    .line 78
    .line 79
    goto/16 :goto_3

    .line 80
    .line 81
    :catchall_0
    move-exception v0

    .line 82
    goto/16 :goto_a

    .line 83
    .line 84
    :cond_3
    iget-object v0, v6, Lol/c;->k:Lkotlin/jvm/internal/f0;

    .line 85
    .line 86
    iget-object v2, v6, Lol/c;->j:Lkotlin/jvm/internal/f0;

    .line 87
    .line 88
    iget-object v3, v6, Lol/c;->i:Lkotlin/jvm/internal/f0;

    .line 89
    .line 90
    iget-object v4, v6, Lol/c;->h:Lkotlin/jvm/internal/f0;

    .line 91
    .line 92
    iget-object v5, v6, Lol/c;->g:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v5, Lil/d;

    .line 95
    .line 96
    iget-object v11, v6, Lol/c;->f:Ljava/lang/Object;

    .line 97
    .line 98
    iget-object v12, v6, Lol/c;->e:Ltl/h;

    .line 99
    .line 100
    iget-object v13, v6, Lol/c;->d:Lol/f;

    .line 101
    .line 102
    :try_start_1
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 103
    .line 104
    .line 105
    move-object/from16 v17, v3

    .line 106
    .line 107
    move-object/from16 v20, v4

    .line 108
    .line 109
    move-object/from16 v21, v5

    .line 110
    .line 111
    move-object/from16 v19, v11

    .line 112
    .line 113
    move-object v15, v13

    .line 114
    goto :goto_2

    .line 115
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    new-instance v11, Lkotlin/jvm/internal/f0;

    .line 119
    .line 120
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 121
    .line 122
    .line 123
    move-object/from16 v1, p3

    .line 124
    .line 125
    iput-object v1, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 126
    .line 127
    new-instance v12, Lkotlin/jvm/internal/f0;

    .line 128
    .line 129
    invoke-direct {v12}, Ljava/lang/Object;-><init>()V

    .line 130
    .line 131
    .line 132
    iget-object v1, v0, Lol/f;->a:Lil/j;

    .line 133
    .line 134
    iget-object v1, v1, Lil/j;->d:Lil/c;

    .line 135
    .line 136
    iput-object v1, v12, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 137
    .line 138
    new-instance v13, Lkotlin/jvm/internal/f0;

    .line 139
    .line 140
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 141
    .line 142
    .line 143
    :try_start_2
    iget-object v1, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v1, Ltl/l;

    .line 146
    .line 147
    iget-object v1, v1, Ltl/l;->b:Landroid/graphics/Bitmap$Config;

    .line 148
    .line 149
    sget-object v1, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 150
    .line 151
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    iget-object v1, v12, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v1, Lil/c;

    .line 157
    .line 158
    iget-object v2, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 159
    .line 160
    move-object v4, v2

    .line 161
    check-cast v4, Ltl/l;

    .line 162
    .line 163
    iput-object v0, v6, Lol/c;->d:Lol/f;

    .line 164
    .line 165
    move-object/from16 v2, p1

    .line 166
    .line 167
    iput-object v2, v6, Lol/c;->e:Ltl/h;

    .line 168
    .line 169
    move-object/from16 v5, p2

    .line 170
    .line 171
    iput-object v5, v6, Lol/c;->f:Ljava/lang/Object;

    .line 172
    .line 173
    move-object/from16 v14, p4

    .line 174
    .line 175
    iput-object v14, v6, Lol/c;->g:Ljava/lang/Object;

    .line 176
    .line 177
    iput-object v11, v6, Lol/c;->h:Lkotlin/jvm/internal/f0;

    .line 178
    .line 179
    iput-object v12, v6, Lol/c;->i:Lkotlin/jvm/internal/f0;

    .line 180
    .line 181
    iput-object v13, v6, Lol/c;->j:Lkotlin/jvm/internal/f0;

    .line 182
    .line 183
    iput-object v13, v6, Lol/c;->k:Lkotlin/jvm/internal/f0;

    .line 184
    .line 185
    iput v3, v6, Lol/c;->n:I

    .line 186
    .line 187
    move-object v3, v5

    .line 188
    move-object v5, v14

    .line 189
    invoke-virtual/range {v0 .. v6}, Lol/f;->c(Lil/c;Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;Lrx0/c;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 193
    if-ne v1, v7, :cond_5

    .line 194
    .line 195
    goto/16 :goto_8

    .line 196
    .line 197
    :cond_5
    move-object/from16 v15, p0

    .line 198
    .line 199
    move-object/from16 v19, p2

    .line 200
    .line 201
    move-object/from16 v21, p4

    .line 202
    .line 203
    move-object/from16 v20, v11

    .line 204
    .line 205
    move-object/from16 v17, v12

    .line 206
    .line 207
    move-object v0, v13

    .line 208
    move-object v2, v0

    .line 209
    move-object/from16 v12, p1

    .line 210
    .line 211
    :goto_2
    :try_start_3
    iput-object v1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 212
    .line 213
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 214
    .line 215
    move-object v1, v0

    .line 216
    check-cast v1, Lnl/e;

    .line 217
    .line 218
    instance-of v3, v1, Lnl/m;

    .line 219
    .line 220
    if-eqz v3, :cond_7

    .line 221
    .line 222
    iget-object v0, v12, Ltl/h;->s:Lvy0/x;

    .line 223
    .line 224
    new-instance v14, Le1/z0;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 225
    .line 226
    const/16 v22, 0x0

    .line 227
    .line 228
    const/16 v23, 0x6

    .line 229
    .line 230
    move-object/from16 v16, v2

    .line 231
    .line 232
    move-object/from16 v18, v12

    .line 233
    .line 234
    :try_start_4
    invoke-direct/range {v14 .. v23}, Le1/z0;-><init>(Ljava/lang/Object;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/jvm/internal/f0;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 235
    .line 236
    .line 237
    move-object/from16 v4, v18

    .line 238
    .line 239
    move-object/from16 v11, v20

    .line 240
    .line 241
    move-object/from16 v3, v21

    .line 242
    .line 243
    :try_start_5
    iput-object v15, v6, Lol/c;->d:Lol/f;

    .line 244
    .line 245
    iput-object v4, v6, Lol/c;->e:Ltl/h;

    .line 246
    .line 247
    iput-object v3, v6, Lol/c;->f:Ljava/lang/Object;

    .line 248
    .line 249
    iput-object v11, v6, Lol/c;->g:Ljava/lang/Object;

    .line 250
    .line 251
    iput-object v2, v6, Lol/c;->h:Lkotlin/jvm/internal/f0;

    .line 252
    .line 253
    iput-object v10, v6, Lol/c;->i:Lkotlin/jvm/internal/f0;

    .line 254
    .line 255
    iput-object v10, v6, Lol/c;->j:Lkotlin/jvm/internal/f0;

    .line 256
    .line 257
    iput-object v10, v6, Lol/c;->k:Lkotlin/jvm/internal/f0;

    .line 258
    .line 259
    iput v9, v6, Lol/c;->n:I

    .line 260
    .line 261
    invoke-static {v0, v14, v6}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v1

    .line 265
    if-ne v1, v7, :cond_6

    .line 266
    .line 267
    goto/16 :goto_8

    .line 268
    .line 269
    :cond_6
    move-object v0, v11

    .line 270
    move-object v5, v15

    .line 271
    :goto_3
    check-cast v1, Lol/a;

    .line 272
    .line 273
    move-object v11, v0

    .line 274
    move-object/from16 v17, v5

    .line 275
    .line 276
    :goto_4
    move-object/from16 v21, v3

    .line 277
    .line 278
    move-object v12, v4

    .line 279
    goto :goto_5

    .line 280
    :catchall_1
    move-exception v0

    .line 281
    move-object/from16 v2, v16

    .line 282
    .line 283
    goto/16 :goto_a

    .line 284
    .line 285
    :cond_7
    move-object v4, v12

    .line 286
    move-object/from16 v11, v20

    .line 287
    .line 288
    move-object/from16 v3, v21

    .line 289
    .line 290
    instance-of v1, v1, Lnl/d;

    .line 291
    .line 292
    if-eqz v1, :cond_f

    .line 293
    .line 294
    new-instance v1, Lol/a;

    .line 295
    .line 296
    move-object v5, v0

    .line 297
    check-cast v5, Lnl/d;

    .line 298
    .line 299
    iget-object v5, v5, Lnl/d;->a:Landroid/graphics/drawable/Drawable;

    .line 300
    .line 301
    move-object v9, v0

    .line 302
    check-cast v9, Lnl/d;

    .line 303
    .line 304
    iget-boolean v9, v9, Lnl/d;->b:Z

    .line 305
    .line 306
    check-cast v0, Lnl/d;

    .line 307
    .line 308
    iget-object v0, v0, Lnl/d;->c:Lkl/e;

    .line 309
    .line 310
    invoke-direct {v1, v5, v9, v0, v10}, Lol/a;-><init>(Landroid/graphics/drawable/Drawable;ZLkl/e;Ljava/lang/String;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 311
    .line 312
    .line 313
    move-object/from16 v17, v15

    .line 314
    .line 315
    goto :goto_4

    .line 316
    :goto_5
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 317
    .line 318
    instance-of v2, v0, Lnl/m;

    .line 319
    .line 320
    if-eqz v2, :cond_8

    .line 321
    .line 322
    check-cast v0, Lnl/m;

    .line 323
    .line 324
    goto :goto_6

    .line 325
    :cond_8
    move-object v0, v10

    .line 326
    :goto_6
    if-eqz v0, :cond_9

    .line 327
    .line 328
    iget-object v0, v0, Lnl/m;->a:Lkl/l;

    .line 329
    .line 330
    invoke-static {v0}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 331
    .line 332
    .line 333
    :cond_9
    iget-object v0, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 334
    .line 335
    move-object/from16 v19, v0

    .line 336
    .line 337
    check-cast v19, Ltl/l;

    .line 338
    .line 339
    iput-object v10, v6, Lol/c;->d:Lol/f;

    .line 340
    .line 341
    iput-object v10, v6, Lol/c;->e:Ltl/h;

    .line 342
    .line 343
    iput-object v10, v6, Lol/c;->f:Ljava/lang/Object;

    .line 344
    .line 345
    iput-object v10, v6, Lol/c;->g:Ljava/lang/Object;

    .line 346
    .line 347
    iput-object v10, v6, Lol/c;->h:Lkotlin/jvm/internal/f0;

    .line 348
    .line 349
    iput-object v10, v6, Lol/c;->i:Lkotlin/jvm/internal/f0;

    .line 350
    .line 351
    iput-object v10, v6, Lol/c;->j:Lkotlin/jvm/internal/f0;

    .line 352
    .line 353
    iput-object v10, v6, Lol/c;->k:Lkotlin/jvm/internal/f0;

    .line 354
    .line 355
    iput v8, v6, Lol/c;->n:I

    .line 356
    .line 357
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 358
    .line 359
    .line 360
    iget-object v0, v12, Ltl/h;->f:Ljava/util/List;

    .line 361
    .line 362
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 363
    .line 364
    .line 365
    move-result v2

    .line 366
    if-eqz v2, :cond_a

    .line 367
    .line 368
    goto :goto_7

    .line 369
    :cond_a
    iget-object v2, v1, Lol/a;->a:Landroid/graphics/drawable/Drawable;

    .line 370
    .line 371
    instance-of v2, v2, Landroid/graphics/drawable/BitmapDrawable;

    .line 372
    .line 373
    if-nez v2, :cond_b

    .line 374
    .line 375
    iget-boolean v2, v12, Ltl/h;->j:Z

    .line 376
    .line 377
    if-nez v2, :cond_b

    .line 378
    .line 379
    goto :goto_7

    .line 380
    :cond_b
    iget-object v2, v12, Ltl/h;->t:Lvy0/x;

    .line 381
    .line 382
    new-instance v16, Ldw0/f;

    .line 383
    .line 384
    const/16 v23, 0x0

    .line 385
    .line 386
    move-object/from16 v20, v0

    .line 387
    .line 388
    move-object/from16 v18, v1

    .line 389
    .line 390
    move-object/from16 v22, v12

    .line 391
    .line 392
    invoke-direct/range {v16 .. v23}, Ldw0/f;-><init>(Lol/f;Lol/a;Ltl/l;Ljava/util/List;Lil/d;Ltl/h;Lkotlin/coroutines/Continuation;)V

    .line 393
    .line 394
    .line 395
    move-object/from16 v0, v16

    .line 396
    .line 397
    invoke-static {v2, v0, v6}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    move-object v1, v0

    .line 402
    :goto_7
    if-ne v1, v7, :cond_c

    .line 403
    .line 404
    :goto_8
    return-object v7

    .line 405
    :cond_c
    :goto_9
    check-cast v1, Lol/a;

    .line 406
    .line 407
    iget-object v0, v1, Lol/a;->a:Landroid/graphics/drawable/Drawable;

    .line 408
    .line 409
    instance-of v2, v0, Landroid/graphics/drawable/BitmapDrawable;

    .line 410
    .line 411
    if-eqz v2, :cond_d

    .line 412
    .line 413
    move-object v10, v0

    .line 414
    check-cast v10, Landroid/graphics/drawable/BitmapDrawable;

    .line 415
    .line 416
    :cond_d
    if-eqz v10, :cond_e

    .line 417
    .line 418
    invoke-virtual {v10}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    if-eqz v0, :cond_e

    .line 423
    .line 424
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->prepareToDraw()V

    .line 425
    .line 426
    .line 427
    :cond_e
    return-object v1

    .line 428
    :cond_f
    :try_start_6
    new-instance v0, La8/r0;

    .line 429
    .line 430
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 431
    .line 432
    .line 433
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 434
    :catchall_2
    move-exception v0

    .line 435
    move-object v2, v13

    .line 436
    :goto_a
    iget-object v1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 437
    .line 438
    instance-of v2, v1, Lnl/m;

    .line 439
    .line 440
    if-eqz v2, :cond_10

    .line 441
    .line 442
    move-object v10, v1

    .line 443
    check-cast v10, Lnl/m;

    .line 444
    .line 445
    :cond_10
    if-eqz v10, :cond_11

    .line 446
    .line 447
    iget-object v1, v10, Lnl/m;->a:Lkl/l;

    .line 448
    .line 449
    invoke-static {v1}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 450
    .line 451
    .line 452
    :cond_11
    throw v0
.end method


# virtual methods
.method public final c(Lil/c;Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p6

    .line 2
    .line 3
    instance-of v1, v0, Lol/d;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lol/d;

    .line 9
    .line 10
    iget v2, v1, Lol/d;->m:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lol/d;->m:I

    .line 20
    .line 21
    move-object/from16 v2, p0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lol/d;

    .line 25
    .line 26
    move-object/from16 v2, p0

    .line 27
    .line 28
    invoke-direct {v1, v2, v0}, Lol/d;-><init>(Lol/f;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v0, v1, Lol/d;->k:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v4, v1, Lol/d;->m:I

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    const/4 v6, 0x1

    .line 39
    if-eqz v4, :cond_2

    .line 40
    .line 41
    if-ne v4, v6, :cond_1

    .line 42
    .line 43
    iget v2, v1, Lol/d;->j:I

    .line 44
    .line 45
    iget-object v4, v1, Lol/d;->i:Lil/d;

    .line 46
    .line 47
    iget-object v7, v1, Lol/d;->h:Ltl/l;

    .line 48
    .line 49
    iget-object v8, v1, Lol/d;->g:Ljava/lang/Object;

    .line 50
    .line 51
    iget-object v9, v1, Lol/d;->f:Ltl/h;

    .line 52
    .line 53
    iget-object v10, v1, Lol/d;->e:Lil/c;

    .line 54
    .line 55
    iget-object v11, v1, Lol/d;->d:Lol/f;

    .line 56
    .line 57
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    move-object/from16 v16, v11

    .line 61
    .line 62
    move-object v11, v1

    .line 63
    move-object v1, v9

    .line 64
    move v9, v2

    .line 65
    move-object/from16 v2, v16

    .line 66
    .line 67
    move-object/from16 v16, v8

    .line 68
    .line 69
    move-object v8, v4

    .line 70
    move-object/from16 v4, v16

    .line 71
    .line 72
    goto/16 :goto_4

    .line 73
    .line 74
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 77
    .line 78
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw v0

    .line 82
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    const/4 v0, 0x0

    .line 86
    move-object/from16 v4, p3

    .line 87
    .line 88
    move-object/from16 v7, p4

    .line 89
    .line 90
    move-object/from16 v8, p5

    .line 91
    .line 92
    move v9, v0

    .line 93
    move-object v10, v1

    .line 94
    move-object/from16 v0, p1

    .line 95
    .line 96
    move-object/from16 v1, p2

    .line 97
    .line 98
    :goto_1
    iget-object v11, v2, Lol/f;->a:Lil/j;

    .line 99
    .line 100
    iget-object v11, v0, Lil/c;->d:Ljava/util/List;

    .line 101
    .line 102
    invoke-interface {v11}, Ljava/util/List;->size()I

    .line 103
    .line 104
    .line 105
    move-result v12

    .line 106
    :goto_2
    if-ge v9, v12, :cond_4

    .line 107
    .line 108
    invoke-interface {v11, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v13

    .line 112
    check-cast v13, Llx0/l;

    .line 113
    .line 114
    iget-object v14, v13, Llx0/l;->d:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v14, Lnl/f;

    .line 117
    .line 118
    iget-object v13, v13, Llx0/l;->e:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v13, Ljava/lang/Class;

    .line 121
    .line 122
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    move-result-object v15

    .line 126
    invoke-virtual {v13, v15}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 127
    .line 128
    .line 129
    move-result v13

    .line 130
    if-eqz v13, :cond_3

    .line 131
    .line 132
    const-string v13, "null cannot be cast to non-null type coil.fetch.Fetcher.Factory<kotlin.Any>"

    .line 133
    .line 134
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    invoke-interface {v14, v4, v7}, Lnl/f;->a(Ljava/lang/Object;Ltl/l;)Lnl/g;

    .line 138
    .line 139
    .line 140
    move-result-object v13

    .line 141
    if-eqz v13, :cond_3

    .line 142
    .line 143
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 144
    .line 145
    .line 146
    move-result-object v9

    .line 147
    new-instance v11, Llx0/l;

    .line 148
    .line 149
    invoke-direct {v11, v13, v9}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_3
    add-int/lit8 v9, v9, 0x1

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_4
    move-object v11, v5

    .line 157
    :goto_3
    if-eqz v11, :cond_9

    .line 158
    .line 159
    iget-object v9, v11, Llx0/l;->d:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v9, Lnl/g;

    .line 162
    .line 163
    iget-object v11, v11, Llx0/l;->e:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v11, Ljava/lang/Number;

    .line 166
    .line 167
    invoke-virtual {v11}, Ljava/lang/Number;->intValue()I

    .line 168
    .line 169
    .line 170
    move-result v11

    .line 171
    add-int/2addr v11, v6

    .line 172
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    iput-object v2, v10, Lol/d;->d:Lol/f;

    .line 176
    .line 177
    iput-object v0, v10, Lol/d;->e:Lil/c;

    .line 178
    .line 179
    iput-object v1, v10, Lol/d;->f:Ltl/h;

    .line 180
    .line 181
    iput-object v4, v10, Lol/d;->g:Ljava/lang/Object;

    .line 182
    .line 183
    iput-object v7, v10, Lol/d;->h:Ltl/l;

    .line 184
    .line 185
    iput-object v8, v10, Lol/d;->i:Lil/d;

    .line 186
    .line 187
    iput v11, v10, Lol/d;->j:I

    .line 188
    .line 189
    iput v6, v10, Lol/d;->m:I

    .line 190
    .line 191
    invoke-interface {v9, v10}, Lnl/g;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v9

    .line 195
    if-ne v9, v3, :cond_5

    .line 196
    .line 197
    return-object v3

    .line 198
    :cond_5
    move-object/from16 v16, v10

    .line 199
    .line 200
    move-object v10, v0

    .line 201
    move-object v0, v9

    .line 202
    move v9, v11

    .line 203
    move-object/from16 v11, v16

    .line 204
    .line 205
    :goto_4
    move-object v12, v0

    .line 206
    check-cast v12, Lnl/e;

    .line 207
    .line 208
    :try_start_0
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 209
    .line 210
    .line 211
    if-eqz v12, :cond_6

    .line 212
    .line 213
    return-object v12

    .line 214
    :cond_6
    move-object v0, v10

    .line 215
    move-object v10, v11

    .line 216
    goto :goto_1

    .line 217
    :catchall_0
    move-exception v0

    .line 218
    instance-of v1, v12, Lnl/m;

    .line 219
    .line 220
    if-eqz v1, :cond_7

    .line 221
    .line 222
    move-object v5, v12

    .line 223
    check-cast v5, Lnl/m;

    .line 224
    .line 225
    :cond_7
    if-eqz v5, :cond_8

    .line 226
    .line 227
    iget-object v1, v5, Lnl/m;->a:Lkl/l;

    .line 228
    .line 229
    invoke-static {v1}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 230
    .line 231
    .line 232
    :cond_8
    throw v0

    .line 233
    :cond_9
    const-string v0, "Unable to create a fetcher that supports: "

    .line 234
    .line 235
    invoke-static {v4, v0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 240
    .line 241
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    throw v1
.end method

.method public final d(Lb0/n1;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    iget-object v2, v1, Lol/f;->c:Lpv/g;

    .line 8
    .line 9
    instance-of v3, v0, Lol/e;

    .line 10
    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lol/e;

    .line 15
    .line 16
    iget v4, v3, Lol/e;->h:I

    .line 17
    .line 18
    const/high16 v5, -0x80000000

    .line 19
    .line 20
    and-int v6, v4, v5

    .line 21
    .line 22
    if-eqz v6, :cond_0

    .line 23
    .line 24
    sub-int/2addr v4, v5

    .line 25
    iput v4, v3, Lol/e;->h:I

    .line 26
    .line 27
    :goto_0
    move-object v10, v3

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    new-instance v3, Lol/e;

    .line 30
    .line 31
    invoke-direct {v3, v1, v0}, Lol/e;-><init>(Lol/f;Lrx0/c;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :goto_1
    iget-object v0, v10, Lol/e;->f:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v11, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v3, v10, Lol/e;->h:I

    .line 40
    .line 41
    const/4 v12, 0x1

    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    if-ne v3, v12, :cond_1

    .line 45
    .line 46
    iget-object v1, v10, Lol/e;->e:Lb0/n1;

    .line 47
    .line 48
    iget-object v2, v10, Lol/e;->d:Lol/f;

    .line 49
    .line 50
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    .line 53
    return-object v0

    .line 54
    :catchall_0
    move-exception v0

    .line 55
    move-object v7, v1

    .line 56
    move-object v1, v2

    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :try_start_1
    iget-object v0, v7, Lb0/n1;->h:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Ltl/h;

    .line 73
    .line 74
    iget-object v3, v0, Ltl/h;->b:Ljava/lang/Object;

    .line 75
    .line 76
    iget-object v4, v7, Lb0/n1;->i:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v4, Lul/g;

    .line 79
    .line 80
    sget-object v5, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 81
    .line 82
    iget-object v5, v7, Lb0/n1;->j:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v5, Lil/d;

    .line 85
    .line 86
    iget-object v6, v1, Lol/f;->b:Lpv/g;

    .line 87
    .line 88
    invoke-virtual {v6, v0, v4}, Lpv/g;->n(Ltl/h;Lul/g;)Ltl/l;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    iget-object v8, v6, Ltl/l;->e:Lul/f;

    .line 93
    .line 94
    iget-object v9, v1, Lol/f;->a:Lil/j;

    .line 95
    .line 96
    iget-object v9, v9, Lil/j;->d:Lil/c;

    .line 97
    .line 98
    iget-object v9, v9, Lil/c;->b:Ljava/util/List;

    .line 99
    .line 100
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 101
    .line 102
    .line 103
    move-result v13
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 104
    const/4 v14, 0x0

    .line 105
    :goto_2
    if-ge v14, v13, :cond_4

    .line 106
    .line 107
    :try_start_2
    invoke-interface {v9, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v15

    .line 111
    check-cast v15, Llx0/l;

    .line 112
    .line 113
    iget-object v12, v15, Llx0/l;->d:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v12, Lql/a;

    .line 116
    .line 117
    iget-object v15, v15, Llx0/l;->e:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v15, Ljava/lang/Class;

    .line 120
    .line 121
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    invoke-virtual {v15, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    if-eqz v1, :cond_3

    .line 130
    .line 131
    const-string v1, "null cannot be cast to non-null type coil.map.Mapper<kotlin.Any, *>"

    .line 132
    .line 133
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v12, v3, v6}, Lql/a;->a(Ljava/lang/Object;Ltl/l;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    if-eqz v1, :cond_3

    .line 141
    .line 142
    move-object v3, v1

    .line 143
    :cond_3
    add-int/lit8 v14, v14, 0x1

    .line 144
    .line 145
    const/4 v12, 0x1

    .line 146
    move-object/from16 v1, p0

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_4
    move-object v1, v6

    .line 150
    invoke-virtual {v2, v0, v3, v1, v5}, Lpv/g;->j(Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;)Lrl/a;

    .line 151
    .line 152
    .line 153
    move-result-object v6

    .line 154
    if-eqz v6, :cond_5

    .line 155
    .line 156
    invoke-virtual {v2, v0, v6, v4, v8}, Lpv/g;->f(Ltl/h;Lrl/a;Lul/g;Lul/f;)Lrl/b;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    goto :goto_3

    .line 161
    :catchall_1
    move-exception v0

    .line 162
    move-object/from16 v1, p0

    .line 163
    .line 164
    goto :goto_4

    .line 165
    :cond_5
    const/4 v2, 0x0

    .line 166
    :goto_3
    if-eqz v2, :cond_6

    .line 167
    .line 168
    invoke-static {v7, v0, v6, v2}, Lpv/g;->k(Lb0/n1;Ltl/h;Lrl/a;Lrl/b;)Ltl/n;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    return-object v0

    .line 173
    :cond_6
    iget-object v12, v0, Ltl/h;->r:Lvy0/x;

    .line 174
    .line 175
    move-object v2, v0

    .line 176
    new-instance v0, Le1/z0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 177
    .line 178
    const/4 v8, 0x0

    .line 179
    const/4 v9, 0x7

    .line 180
    move-object v4, v1

    .line 181
    move-object/from16 v1, p0

    .line 182
    .line 183
    :try_start_3
    invoke-direct/range {v0 .. v9}, Le1/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 184
    .line 185
    .line 186
    iput-object v1, v10, Lol/e;->d:Lol/f;

    .line 187
    .line 188
    iput-object v7, v10, Lol/e;->e:Lb0/n1;

    .line 189
    .line 190
    const/4 v2, 0x1

    .line 191
    iput v2, v10, Lol/e;->h:I

    .line 192
    .line 193
    invoke-static {v12, v0, v10}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 197
    if-ne v0, v11, :cond_7

    .line 198
    .line 199
    return-object v11

    .line 200
    :cond_7
    return-object v0

    .line 201
    :catchall_2
    move-exception v0

    .line 202
    :goto_4
    instance-of v2, v0, Ljava/util/concurrent/CancellationException;

    .line 203
    .line 204
    if-nez v2, :cond_8

    .line 205
    .line 206
    iget-object v1, v1, Lol/f;->b:Lpv/g;

    .line 207
    .line 208
    iget-object v1, v7, Lb0/n1;->h:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v1, Ltl/h;

    .line 211
    .line 212
    invoke-static {v1, v0}, Lpv/g;->b(Ltl/h;Ljava/lang/Throwable;)Ltl/d;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    return-object v0

    .line 217
    :cond_8
    throw v0
.end method
