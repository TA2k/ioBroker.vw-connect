.class public final Lem/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyl/r;

.field public final b:Lvv0/d;

.field public final c:Lhm/c;

.field public final d:Lhm/c;


# direct methods
.method public constructor <init>(Lyl/r;Lvv0/d;Lhm/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lem/f;->a:Lyl/r;

    .line 5
    .line 6
    iput-object p2, p0, Lem/f;->b:Lvv0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lem/f;->c:Lhm/c;

    .line 9
    .line 10
    new-instance p2, Lhm/c;

    .line 11
    .line 12
    invoke-direct {p2, p1, p3}, Lhm/c;-><init>(Lyl/r;Lhm/c;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Lem/f;->d:Lhm/c;

    .line 16
    .line 17
    return-void
.end method

.method public static final a(Lem/f;Ldm/i;Lyl/d;Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p7, Lem/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p7

    .line 6
    check-cast v0, Lem/b;

    .line 7
    .line 8
    iget v1, v0, Lem/b;->m:I

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
    iput v1, v0, Lem/b;->m:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lem/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p7}, Lem/b;-><init>(Lem/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lem/b;->k:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p7, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lem/b;->m:I

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    const/4 v3, 0x1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    if-ne v1, v3, :cond_1

    .line 36
    .line 37
    iget p1, v0, Lem/b;->j:I

    .line 38
    .line 39
    iget-object p2, v0, Lem/b;->i:Lyl/f;

    .line 40
    .line 41
    iget-object p3, v0, Lem/b;->h:Lmm/n;

    .line 42
    .line 43
    iget-object p4, v0, Lem/b;->g:Ljava/lang/Object;

    .line 44
    .line 45
    iget-object p5, v0, Lem/b;->f:Lmm/g;

    .line 46
    .line 47
    iget-object p6, v0, Lem/b;->e:Lyl/d;

    .line 48
    .line 49
    iget-object v1, v0, Lem/b;->d:Ldm/i;

    .line 50
    .line 51
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    move-object v5, p6

    .line 55
    move-object p6, p2

    .line 56
    move-object p2, v5

    .line 57
    move-object v5, p5

    .line 58
    move-object p5, p3

    .line 59
    move-object p3, v5

    .line 60
    goto :goto_4

    .line 61
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    const/4 p0, 0x0

    .line 73
    :goto_1
    iget-object v1, p2, Lyl/d;->g:Llx0/q;

    .line 74
    .line 75
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Ljava/util/List;

    .line 80
    .line 81
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    :goto_2
    if-ge p0, v1, :cond_4

    .line 86
    .line 87
    iget-object v4, p2, Lyl/d;->g:Llx0/q;

    .line 88
    .line 89
    invoke-virtual {v4}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    check-cast v4, Ljava/util/List;

    .line 94
    .line 95
    invoke-interface {v4, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    check-cast v4, Lbm/j;

    .line 100
    .line 101
    invoke-interface {v4, p1, p5}, Lbm/j;->a(Ldm/i;Lmm/n;)Lbm/k;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    if-eqz v4, :cond_3

    .line 106
    .line 107
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    new-instance v1, Llx0/l;

    .line 112
    .line 113
    invoke-direct {v1, v4, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_3
    add-int/lit8 p0, p0, 0x1

    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_4
    move-object v1, v2

    .line 121
    :goto_3
    if-eqz v1, :cond_9

    .line 122
    .line 123
    iget-object p0, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Lbm/k;

    .line 126
    .line 127
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v1, Ljava/lang/Number;

    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    add-int/2addr v1, v3

    .line 136
    invoke-virtual {p6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    iput-object p1, v0, Lem/b;->d:Ldm/i;

    .line 140
    .line 141
    iput-object p2, v0, Lem/b;->e:Lyl/d;

    .line 142
    .line 143
    iput-object p3, v0, Lem/b;->f:Lmm/g;

    .line 144
    .line 145
    iput-object p4, v0, Lem/b;->g:Ljava/lang/Object;

    .line 146
    .line 147
    iput-object p5, v0, Lem/b;->h:Lmm/n;

    .line 148
    .line 149
    iput-object p6, v0, Lem/b;->i:Lyl/f;

    .line 150
    .line 151
    iput v1, v0, Lem/b;->j:I

    .line 152
    .line 153
    iput v3, v0, Lem/b;->m:I

    .line 154
    .line 155
    invoke-interface {p0, v0}, Lbm/k;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, p7, :cond_5

    .line 160
    .line 161
    return-object p7

    .line 162
    :cond_5
    move v5, v1

    .line 163
    move-object v1, p1

    .line 164
    move p1, v5

    .line 165
    :goto_4
    check-cast p0, Lbm/i;

    .line 166
    .line 167
    invoke-virtual {p6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    if-eqz p0, :cond_8

    .line 171
    .line 172
    new-instance p1, Lem/a;

    .line 173
    .line 174
    iget-object p2, p0, Lbm/i;->a:Lyl/j;

    .line 175
    .line 176
    iget-boolean p0, p0, Lbm/i;->b:Z

    .line 177
    .line 178
    iget-object p3, v1, Ldm/i;->c:Lbm/h;

    .line 179
    .line 180
    iget-object p4, v1, Ldm/i;->a:Lbm/q;

    .line 181
    .line 182
    instance-of p5, p4, Lbm/p;

    .line 183
    .line 184
    if-eqz p5, :cond_6

    .line 185
    .line 186
    check-cast p4, Lbm/p;

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_6
    move-object p4, v2

    .line 190
    :goto_5
    if-eqz p4, :cond_7

    .line 191
    .line 192
    iget-object v2, p4, Lbm/p;->f:Ljava/lang/String;

    .line 193
    .line 194
    :cond_7
    invoke-direct {p1, p2, p0, p3, v2}, Lem/a;-><init>(Lyl/j;ZLbm/h;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    return-object p1

    .line 198
    :cond_8
    move p0, p1

    .line 199
    move-object p1, v1

    .line 200
    goto :goto_1

    .line 201
    :cond_9
    const-string p0, "Unable to create a decoder that supports: "

    .line 202
    .line 203
    invoke-static {p4, p0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 208
    .line 209
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    throw p1
.end method

.method public static final b(Lem/f;Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p5

    .line 4
    .line 5
    instance-of v2, v1, Lem/c;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lem/c;

    .line 11
    .line 12
    iget v3, v2, Lem/c;->m:I

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
    iput v3, v2, Lem/c;->m:I

    .line 22
    .line 23
    :goto_0
    move-object v6, v2

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    new-instance v2, Lem/c;

    .line 26
    .line 27
    invoke-direct {v2, v0, v1}, Lem/c;-><init>(Lem/f;Lrx0/c;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :goto_1
    iget-object v1, v6, Lem/c;->k:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v2, v6, Lem/c;->m:I

    .line 36
    .line 37
    const/4 v11, 0x3

    .line 38
    const/4 v12, 0x2

    .line 39
    const/4 v3, 0x1

    .line 40
    const/4 v13, 0x0

    .line 41
    if-eqz v2, :cond_4

    .line 42
    .line 43
    if-eq v2, v3, :cond_3

    .line 44
    .line 45
    if-eq v2, v12, :cond_2

    .line 46
    .line 47
    if-ne v2, v11, :cond_1

    .line 48
    .line 49
    iget-object v0, v6, Lem/c;->j:Lkotlin/jvm/internal/f0;

    .line 50
    .line 51
    check-cast v0, Lem/a;

    .line 52
    .line 53
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_9

    .line 57
    .line 58
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw v0

    .line 66
    :cond_2
    iget-object v2, v6, Lem/c;->i:Lkotlin/jvm/internal/f0;

    .line 67
    .line 68
    iget-object v0, v6, Lem/c;->g:Lkotlin/jvm/internal/f0;

    .line 69
    .line 70
    iget-object v3, v6, Lem/c;->f:Lyl/f;

    .line 71
    .line 72
    iget-object v4, v6, Lem/c;->d:Lmm/g;

    .line 73
    .line 74
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    .line 76
    .line 77
    move-object v14, v6

    .line 78
    goto/16 :goto_3

    .line 79
    .line 80
    :catchall_0
    move-exception v0

    .line 81
    goto/16 :goto_a

    .line 82
    .line 83
    :cond_3
    iget-object v2, v6, Lem/c;->j:Lkotlin/jvm/internal/f0;

    .line 84
    .line 85
    iget-object v3, v6, Lem/c;->i:Lkotlin/jvm/internal/f0;

    .line 86
    .line 87
    iget-object v4, v6, Lem/c;->h:Lkotlin/jvm/internal/f0;

    .line 88
    .line 89
    iget-object v5, v6, Lem/c;->g:Lkotlin/jvm/internal/f0;

    .line 90
    .line 91
    iget-object v7, v6, Lem/c;->f:Lyl/f;

    .line 92
    .line 93
    iget-object v8, v6, Lem/c;->e:Ljava/lang/Object;

    .line 94
    .line 95
    iget-object v9, v6, Lem/c;->d:Lmm/g;

    .line 96
    .line 97
    :try_start_1
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 98
    .line 99
    .line 100
    move-object v14, v6

    .line 101
    move-object v6, v5

    .line 102
    move-object v5, v8

    .line 103
    move-object v8, v4

    .line 104
    move-object v4, v9

    .line 105
    goto/16 :goto_2

    .line 106
    .line 107
    :catchall_1
    move-exception v0

    .line 108
    move-object v2, v3

    .line 109
    goto/16 :goto_a

    .line 110
    .line 111
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    new-instance v7, Lkotlin/jvm/internal/f0;

    .line 115
    .line 116
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 117
    .line 118
    .line 119
    move-object/from16 v1, p3

    .line 120
    .line 121
    iput-object v1, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 122
    .line 123
    new-instance v8, Lkotlin/jvm/internal/f0;

    .line 124
    .line 125
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 126
    .line 127
    .line 128
    iget-object v1, v0, Lem/f;->a:Lyl/r;

    .line 129
    .line 130
    iget-object v1, v1, Lyl/r;->d:Lyl/d;

    .line 131
    .line 132
    iput-object v1, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 133
    .line 134
    new-instance v9, Lkotlin/jvm/internal/f0;

    .line 135
    .line 136
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 137
    .line 138
    .line 139
    :try_start_2
    iget-object v1, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v1, Lmm/n;

    .line 142
    .line 143
    iget-object v2, v1, Lmm/n;->j:Lyl/i;

    .line 144
    .line 145
    sget-object v2, Lmm/i;->b:Ld8/c;

    .line 146
    .line 147
    invoke-static {v1, v2}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    check-cast v2, Landroid/graphics/Bitmap$Config;

    .line 152
    .line 153
    sget-object v2, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 154
    .line 155
    iput-object v1, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 156
    .line 157
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    iget-object v1, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v1, Lyl/d;

    .line 163
    .line 164
    iget-object v2, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 165
    .line 166
    move-object v4, v2

    .line 167
    check-cast v4, Lmm/n;

    .line 168
    .line 169
    move-object/from16 v2, p1

    .line 170
    .line 171
    iput-object v2, v6, Lem/c;->d:Lmm/g;

    .line 172
    .line 173
    move-object/from16 v5, p2

    .line 174
    .line 175
    iput-object v5, v6, Lem/c;->e:Ljava/lang/Object;

    .line 176
    .line 177
    move-object/from16 v14, p4

    .line 178
    .line 179
    iput-object v14, v6, Lem/c;->f:Lyl/f;

    .line 180
    .line 181
    iput-object v7, v6, Lem/c;->g:Lkotlin/jvm/internal/f0;

    .line 182
    .line 183
    iput-object v8, v6, Lem/c;->h:Lkotlin/jvm/internal/f0;

    .line 184
    .line 185
    iput-object v9, v6, Lem/c;->i:Lkotlin/jvm/internal/f0;

    .line 186
    .line 187
    iput-object v9, v6, Lem/c;->j:Lkotlin/jvm/internal/f0;

    .line 188
    .line 189
    iput v3, v6, Lem/c;->m:I

    .line 190
    .line 191
    move-object v3, v5

    .line 192
    move-object v5, v14

    .line 193
    invoke-virtual/range {v0 .. v6}, Lem/f;->c(Lyl/d;Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 197
    move-object v14, v6

    .line 198
    if-ne v1, v10, :cond_5

    .line 199
    .line 200
    goto/16 :goto_8

    .line 201
    .line 202
    :cond_5
    move-object/from16 v4, p1

    .line 203
    .line 204
    move-object/from16 v5, p2

    .line 205
    .line 206
    move-object v6, v7

    .line 207
    move-object v2, v9

    .line 208
    move-object v3, v2

    .line 209
    move-object/from16 v7, p4

    .line 210
    .line 211
    :goto_2
    :try_start_3
    iput-object v1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 212
    .line 213
    iget-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 214
    .line 215
    move-object v1, v0

    .line 216
    check-cast v1, Ldm/e;

    .line 217
    .line 218
    instance-of v2, v1, Ldm/i;

    .line 219
    .line 220
    if-eqz v2, :cond_7

    .line 221
    .line 222
    iget-object v15, v4, Lmm/g;->h:Lpx0/g;

    .line 223
    .line 224
    new-instance v0, Le1/z0;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 225
    .line 226
    move-object v2, v3

    .line 227
    move-object v3, v8

    .line 228
    const/4 v8, 0x0

    .line 229
    const/4 v9, 0x1

    .line 230
    move-object/from16 v1, p0

    .line 231
    .line 232
    :try_start_4
    invoke-direct/range {v0 .. v9}, Le1/z0;-><init>(Ljava/lang/Object;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/jvm/internal/f0;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 233
    .line 234
    .line 235
    iput-object v4, v14, Lem/c;->d:Lmm/g;

    .line 236
    .line 237
    iput-object v13, v14, Lem/c;->e:Ljava/lang/Object;

    .line 238
    .line 239
    iput-object v7, v14, Lem/c;->f:Lyl/f;

    .line 240
    .line 241
    iput-object v6, v14, Lem/c;->g:Lkotlin/jvm/internal/f0;

    .line 242
    .line 243
    iput-object v13, v14, Lem/c;->h:Lkotlin/jvm/internal/f0;

    .line 244
    .line 245
    iput-object v2, v14, Lem/c;->i:Lkotlin/jvm/internal/f0;

    .line 246
    .line 247
    iput-object v13, v14, Lem/c;->j:Lkotlin/jvm/internal/f0;

    .line 248
    .line 249
    iput v12, v14, Lem/c;->m:I

    .line 250
    .line 251
    invoke-static {v15, v0, v14}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    if-ne v1, v10, :cond_6

    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_6
    move-object v0, v6

    .line 259
    move-object v3, v7

    .line 260
    :goto_3
    check-cast v1, Lem/a;

    .line 261
    .line 262
    move-object v6, v0

    .line 263
    move-object v7, v3

    .line 264
    :goto_4
    move-object v3, v2

    .line 265
    goto :goto_5

    .line 266
    :cond_7
    move-object v2, v3

    .line 267
    instance-of v1, v1, Ldm/h;

    .line 268
    .line 269
    if-eqz v1, :cond_c

    .line 270
    .line 271
    new-instance v1, Lem/a;

    .line 272
    .line 273
    move-object v3, v0

    .line 274
    check-cast v3, Ldm/h;

    .line 275
    .line 276
    iget-object v3, v3, Ldm/h;->a:Lyl/j;

    .line 277
    .line 278
    move-object v5, v0

    .line 279
    check-cast v5, Ldm/h;

    .line 280
    .line 281
    iget-boolean v5, v5, Ldm/h;->b:Z

    .line 282
    .line 283
    check-cast v0, Ldm/h;

    .line 284
    .line 285
    iget-object v0, v0, Ldm/h;->c:Lbm/h;

    .line 286
    .line 287
    invoke-direct {v1, v3, v5, v0, v13}, Lem/a;-><init>(Lyl/j;ZLbm/h;Ljava/lang/String;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 288
    .line 289
    .line 290
    goto :goto_4

    .line 291
    :goto_5
    iget-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 292
    .line 293
    instance-of v2, v0, Ldm/i;

    .line 294
    .line 295
    if-eqz v2, :cond_8

    .line 296
    .line 297
    check-cast v0, Ldm/i;

    .line 298
    .line 299
    goto :goto_6

    .line 300
    :cond_8
    move-object v0, v13

    .line 301
    :goto_6
    if-eqz v0, :cond_9

    .line 302
    .line 303
    iget-object v0, v0, Ldm/i;->a:Lbm/q;

    .line 304
    .line 305
    if-eqz v0, :cond_9

    .line 306
    .line 307
    :try_start_5
    invoke-static {v0}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_5
    .catch Ljava/lang/RuntimeException; {:try_start_5 .. :try_end_5} :catch_0
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_1

    .line 308
    .line 309
    .line 310
    goto :goto_7

    .line 311
    :catch_0
    move-exception v0

    .line 312
    throw v0

    .line 313
    :catch_1
    :cond_9
    :goto_7
    iget-object v0, v6, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 314
    .line 315
    check-cast v0, Lmm/n;

    .line 316
    .line 317
    iput-object v13, v14, Lem/c;->d:Lmm/g;

    .line 318
    .line 319
    iput-object v13, v14, Lem/c;->e:Ljava/lang/Object;

    .line 320
    .line 321
    iput-object v13, v14, Lem/c;->f:Lyl/f;

    .line 322
    .line 323
    iput-object v13, v14, Lem/c;->g:Lkotlin/jvm/internal/f0;

    .line 324
    .line 325
    iput-object v13, v14, Lem/c;->h:Lkotlin/jvm/internal/f0;

    .line 326
    .line 327
    iput-object v13, v14, Lem/c;->i:Lkotlin/jvm/internal/f0;

    .line 328
    .line 329
    iput-object v13, v14, Lem/c;->j:Lkotlin/jvm/internal/f0;

    .line 330
    .line 331
    iput v11, v14, Lem/c;->m:I

    .line 332
    .line 333
    invoke-static {v1, v4, v0, v7, v14}, Lkp/k6;->c(Lem/a;Lmm/g;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    if-ne v1, v10, :cond_a

    .line 338
    .line 339
    :goto_8
    return-object v10

    .line 340
    :cond_a
    :goto_9
    check-cast v1, Lem/a;

    .line 341
    .line 342
    iget-object v0, v1, Lem/a;->a:Lyl/j;

    .line 343
    .line 344
    sget-object v2, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 345
    .line 346
    instance-of v2, v0, Lyl/a;

    .line 347
    .line 348
    if-eqz v2, :cond_b

    .line 349
    .line 350
    check-cast v0, Lyl/a;

    .line 351
    .line 352
    iget-object v0, v0, Lyl/a;->a:Landroid/graphics/Bitmap;

    .line 353
    .line 354
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->prepareToDraw()V

    .line 355
    .line 356
    .line 357
    :cond_b
    return-object v1

    .line 358
    :cond_c
    :try_start_6
    new-instance v0, La8/r0;

    .line 359
    .line 360
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 361
    .line 362
    .line 363
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 364
    :catchall_2
    move-exception v0

    .line 365
    move-object v2, v9

    .line 366
    :goto_a
    iget-object v1, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 367
    .line 368
    instance-of v2, v1, Ldm/i;

    .line 369
    .line 370
    if-eqz v2, :cond_d

    .line 371
    .line 372
    move-object v13, v1

    .line 373
    check-cast v13, Ldm/i;

    .line 374
    .line 375
    :cond_d
    if-eqz v13, :cond_e

    .line 376
    .line 377
    iget-object v1, v13, Ldm/i;->a:Lbm/q;

    .line 378
    .line 379
    if-eqz v1, :cond_e

    .line 380
    .line 381
    :try_start_7
    invoke-static {v1}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_7
    .catch Ljava/lang/RuntimeException; {:try_start_7 .. :try_end_7} :catch_2
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_3

    .line 382
    .line 383
    .line 384
    goto :goto_b

    .line 385
    :catch_2
    move-exception v0

    .line 386
    throw v0

    .line 387
    :catch_3
    :cond_e
    :goto_b
    throw v0
.end method


# virtual methods
.method public final c(Lyl/d;Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p6, Lem/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p6

    .line 6
    check-cast v0, Lem/d;

    .line 7
    .line 8
    iget v1, v0, Lem/d;->l:I

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
    iput v1, v0, Lem/d;->l:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lem/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p6}, Lem/d;-><init>(Lem/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p6, v0, Lem/d;->j:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lem/d;->l:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget p1, v0, Lem/d;->i:I

    .line 38
    .line 39
    iget-object p2, v0, Lem/d;->h:Lyl/f;

    .line 40
    .line 41
    iget-object p3, v0, Lem/d;->g:Lmm/n;

    .line 42
    .line 43
    iget-object p4, v0, Lem/d;->f:Ljava/lang/Object;

    .line 44
    .line 45
    iget-object p5, v0, Lem/d;->e:Lmm/g;

    .line 46
    .line 47
    iget-object v2, v0, Lem/d;->d:Lyl/d;

    .line 48
    .line 49
    invoke-static {p6}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    move-object v7, v2

    .line 53
    move v2, p1

    .line 54
    move-object p1, v7

    .line 55
    move-object v7, p5

    .line 56
    move-object p5, p2

    .line 57
    move-object p2, v7

    .line 58
    move-object v7, p4

    .line 59
    move-object p4, p3

    .line 60
    move-object p3, v7

    .line 61
    goto/16 :goto_4

    .line 62
    .line 63
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_2
    invoke-static {p6}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const/4 p6, 0x0

    .line 75
    :goto_1
    iget-object v2, p1, Lyl/d;->f:Llx0/q;

    .line 76
    .line 77
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    check-cast v2, Ljava/util/List;

    .line 82
    .line 83
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    :goto_2
    if-ge p6, v2, :cond_4

    .line 88
    .line 89
    iget-object v5, p1, Lyl/d;->f:Llx0/q;

    .line 90
    .line 91
    invoke-virtual {v5}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    check-cast v5, Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {v5, p6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    check-cast v5, Llx0/l;

    .line 102
    .line 103
    iget-object v6, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v6, Ldm/f;

    .line 106
    .line 107
    iget-object v5, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v5, Lhy0/d;

    .line 110
    .line 111
    invoke-interface {v5, p3}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    if-eqz v5, :cond_3

    .line 116
    .line 117
    const-string v5, "null cannot be cast to non-null type coil3.fetch.Fetcher.Factory<kotlin.Any>"

    .line 118
    .line 119
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object v5, p0, Lem/f;->a:Lyl/r;

    .line 123
    .line 124
    invoke-interface {v6, p3, p4, v5}, Ldm/f;->a(Ljava/lang/Object;Lmm/n;Lyl/r;)Ldm/g;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    if-eqz v5, :cond_3

    .line 129
    .line 130
    invoke-static {p6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 131
    .line 132
    .line 133
    move-result-object p6

    .line 134
    new-instance v2, Llx0/l;

    .line 135
    .line 136
    invoke-direct {v2, v5, p6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_3
    add-int/lit8 p6, p6, 0x1

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_4
    move-object v2, v3

    .line 144
    :goto_3
    if-eqz v2, :cond_9

    .line 145
    .line 146
    iget-object p6, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast p6, Ldm/g;

    .line 149
    .line 150
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v2, Ljava/lang/Number;

    .line 153
    .line 154
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    add-int/2addr v2, v4

    .line 159
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    iput-object p1, v0, Lem/d;->d:Lyl/d;

    .line 163
    .line 164
    iput-object p2, v0, Lem/d;->e:Lmm/g;

    .line 165
    .line 166
    iput-object p3, v0, Lem/d;->f:Ljava/lang/Object;

    .line 167
    .line 168
    iput-object p4, v0, Lem/d;->g:Lmm/n;

    .line 169
    .line 170
    iput-object p5, v0, Lem/d;->h:Lyl/f;

    .line 171
    .line 172
    iput v2, v0, Lem/d;->i:I

    .line 173
    .line 174
    iput v4, v0, Lem/d;->l:I

    .line 175
    .line 176
    invoke-interface {p6, v0}, Ldm/g;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p6

    .line 180
    if-ne p6, v1, :cond_5

    .line 181
    .line 182
    return-object v1

    .line 183
    :cond_5
    :goto_4
    check-cast p6, Ldm/e;

    .line 184
    .line 185
    :try_start_0
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 186
    .line 187
    .line 188
    if-eqz p6, :cond_6

    .line 189
    .line 190
    return-object p6

    .line 191
    :cond_6
    move p6, v2

    .line 192
    goto :goto_1

    .line 193
    :catchall_0
    move-exception p0

    .line 194
    instance-of p1, p6, Ldm/i;

    .line 195
    .line 196
    if-eqz p1, :cond_7

    .line 197
    .line 198
    move-object v3, p6

    .line 199
    check-cast v3, Ldm/i;

    .line 200
    .line 201
    :cond_7
    if-eqz v3, :cond_8

    .line 202
    .line 203
    iget-object p1, v3, Ldm/i;->a:Lbm/q;

    .line 204
    .line 205
    if-eqz p1, :cond_8

    .line 206
    .line 207
    :try_start_1
    invoke-static {p1}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 208
    .line 209
    .line 210
    goto :goto_5

    .line 211
    :catch_0
    move-exception p0

    .line 212
    throw p0

    .line 213
    :catch_1
    :cond_8
    :goto_5
    throw p0

    .line 214
    :cond_9
    const-string p0, "Unable to create a fetcher that supports: "

    .line 215
    .line 216
    invoke-static {p3, p0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 221
    .line 222
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    throw p1
.end method

.method public final d(Lb0/n1;Lrx0/c;)Ljava/lang/Object;
    .locals 21

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
    iget-object v2, v1, Lem/f;->d:Lhm/c;

    .line 8
    .line 9
    instance-of v3, v0, Lem/e;

    .line 10
    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lem/e;

    .line 15
    .line 16
    iget v4, v3, Lem/e;->g:I

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
    iput v4, v3, Lem/e;->g:I

    .line 26
    .line 27
    :goto_0
    move-object v10, v3

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    new-instance v3, Lem/e;

    .line 30
    .line 31
    invoke-direct {v3, v1, v0}, Lem/e;-><init>(Lem/f;Lrx0/c;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :goto_1
    iget-object v0, v10, Lem/e;->e:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v11, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v3, v10, Lem/e;->g:I

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
    iget-object v1, v10, Lem/e;->d:Lb0/n1;

    .line 47
    .line 48
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    .line 50
    .line 51
    return-object v0

    .line 52
    :catchall_0
    move-exception v0

    .line 53
    move-object v7, v1

    .line 54
    goto/16 :goto_6

    .line 55
    .line 56
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw v0

    .line 64
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :try_start_1
    iget-object v0, v7, Lb0/n1;->h:Ljava/lang/Object;

    .line 68
    .line 69
    move-object v15, v0

    .line 70
    check-cast v15, Lmm/g;

    .line 71
    .line 72
    iget-object v0, v15, Lmm/g;->b:Ljava/lang/Object;

    .line 73
    .line 74
    iget-object v3, v7, Lb0/n1;->i:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v3, Lnm/h;

    .line 77
    .line 78
    iget-object v4, v7, Lb0/n1;->j:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v5, v4

    .line 81
    check-cast v5, Lyl/f;

    .line 82
    .line 83
    iget-object v4, v1, Lem/f;->c:Lhm/c;

    .line 84
    .line 85
    invoke-virtual {v4, v15, v3}, Lhm/c;->c(Lmm/g;Lnm/h;)Lmm/n;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    iget-object v6, v4, Lmm/n;->c:Lnm/g;

    .line 90
    .line 91
    iget-object v8, v1, Lem/f;->a:Lyl/r;

    .line 92
    .line 93
    iget-object v8, v8, Lyl/r;->d:Lyl/d;

    .line 94
    .line 95
    iget-object v8, v8, Lyl/d;->b:Ljava/util/List;

    .line 96
    .line 97
    move-object v9, v8

    .line 98
    check-cast v9, Ljava/util/Collection;

    .line 99
    .line 100
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 101
    .line 102
    .line 103
    move-result v9

    .line 104
    const/4 v14, 0x0

    .line 105
    :goto_2
    if-ge v14, v9, :cond_4

    .line 106
    .line 107
    invoke-interface {v8, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v16

    .line 111
    move-object/from16 v13, v16

    .line 112
    .line 113
    check-cast v13, Llx0/l;

    .line 114
    .line 115
    iget-object v12, v13, Llx0/l;->d:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v12, Lgm/a;

    .line 118
    .line 119
    iget-object v13, v13, Llx0/l;->e:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v13, Lhy0/d;

    .line 122
    .line 123
    invoke-interface {v13, v0}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v13

    .line 127
    if-eqz v13, :cond_3

    .line 128
    .line 129
    const-string v13, "null cannot be cast to non-null type coil3.map.Mapper<kotlin.Any, *>"

    .line 130
    .line 131
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v12, v0, v4}, Lgm/a;->a(Ljava/lang/Object;Lmm/n;)Lyl/t;

    .line 135
    .line 136
    .line 137
    move-result-object v12

    .line 138
    if-eqz v12, :cond_3

    .line 139
    .line 140
    move-object v0, v12

    .line 141
    :cond_3
    add-int/lit8 v14, v14, 0x1

    .line 142
    .line 143
    const/4 v12, 0x1

    .line 144
    goto :goto_2

    .line 145
    :cond_4
    invoke-virtual {v2, v15, v0, v4, v5}, Lhm/c;->b(Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;)Lhm/a;

    .line 146
    .line 147
    .line 148
    move-result-object v8

    .line 149
    const/4 v9, 0x0

    .line 150
    if-eqz v8, :cond_5

    .line 151
    .line 152
    invoke-virtual {v2, v15, v8, v3, v6}, Lhm/c;->a(Lmm/g;Lhm/a;Lnm/h;Lnm/g;)Lhm/b;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    goto :goto_3

    .line 157
    :catchall_1
    move-exception v0

    .line 158
    goto :goto_6

    .line 159
    :cond_5
    move-object v2, v9

    .line 160
    :goto_3
    if-eqz v2, :cond_9

    .line 161
    .line 162
    iget-object v0, v2, Lhm/b;->b:Ljava/util/Map;

    .line 163
    .line 164
    new-instance v13, Lmm/p;

    .line 165
    .line 166
    iget-object v14, v2, Lhm/b;->a:Lyl/j;

    .line 167
    .line 168
    sget-object v16, Lbm/h;->d:Lbm/h;

    .line 169
    .line 170
    const-string v1, "coil#disk_cache_key"

    .line 171
    .line 172
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    instance-of v2, v1, Ljava/lang/String;

    .line 177
    .line 178
    if-eqz v2, :cond_6

    .line 179
    .line 180
    check-cast v1, Ljava/lang/String;

    .line 181
    .line 182
    move-object/from16 v18, v1

    .line 183
    .line 184
    goto :goto_4

    .line 185
    :cond_6
    move-object/from16 v18, v9

    .line 186
    .line 187
    :goto_4
    const-string v1, "coil#is_sampled"

    .line 188
    .line 189
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    instance-of v1, v0, Ljava/lang/Boolean;

    .line 194
    .line 195
    if-eqz v1, :cond_7

    .line 196
    .line 197
    move-object v9, v0

    .line 198
    check-cast v9, Ljava/lang/Boolean;

    .line 199
    .line 200
    :cond_7
    if-eqz v9, :cond_8

    .line 201
    .line 202
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    move/from16 v19, v0

    .line 207
    .line 208
    goto :goto_5

    .line 209
    :cond_8
    const/16 v19, 0x0

    .line 210
    .line 211
    :goto_5
    iget-boolean v0, v7, Lb0/n1;->e:Z

    .line 212
    .line 213
    move/from16 v20, v0

    .line 214
    .line 215
    move-object/from16 v17, v8

    .line 216
    .line 217
    invoke-direct/range {v13 .. v20}, Lmm/p;-><init>(Lyl/j;Lmm/g;Lbm/h;Lhm/a;Ljava/lang/String;ZZ)V

    .line 218
    .line 219
    .line 220
    return-object v13

    .line 221
    :cond_9
    move-object/from16 v17, v8

    .line 222
    .line 223
    iget-object v12, v15, Lmm/g;->g:Lpx0/g;

    .line 224
    .line 225
    move-object v3, v0

    .line 226
    new-instance v0, Le1/z0;

    .line 227
    .line 228
    const/4 v8, 0x0

    .line 229
    const/4 v9, 0x2

    .line 230
    move-object v2, v15

    .line 231
    move-object/from16 v6, v17

    .line 232
    .line 233
    invoke-direct/range {v0 .. v9}, Le1/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 234
    .line 235
    .line 236
    iput-object v7, v10, Lem/e;->d:Lb0/n1;

    .line 237
    .line 238
    const/4 v1, 0x1

    .line 239
    iput v1, v10, Lem/e;->g:I

    .line 240
    .line 241
    invoke-static {v12, v0, v10}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 245
    if-ne v0, v11, :cond_a

    .line 246
    .line 247
    return-object v11

    .line 248
    :cond_a
    return-object v0

    .line 249
    :goto_6
    instance-of v1, v0, Ljava/util/concurrent/CancellationException;

    .line 250
    .line 251
    if-nez v1, :cond_b

    .line 252
    .line 253
    iget-object v1, v7, Lb0/n1;->h:Ljava/lang/Object;

    .line 254
    .line 255
    check-cast v1, Lmm/g;

    .line 256
    .line 257
    invoke-static {v1, v0}, Lkp/k8;->a(Lmm/g;Ljava/lang/Throwable;)Lmm/c;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    return-object v0

    .line 262
    :cond_b
    throw v0
.end method
