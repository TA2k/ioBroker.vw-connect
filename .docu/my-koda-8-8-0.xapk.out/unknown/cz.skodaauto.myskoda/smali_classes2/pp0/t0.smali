.class public final Lpp0/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/b0;

.field public final b:Lpp0/c0;

.field public final c:Lnp0/c;

.field public final d:Lpp0/v0;

.field public final e:Lsf0/a;

.field public final f:Lpp0/l0;


# direct methods
.method public constructor <init>(Lkf0/b0;Lpp0/c0;Lnp0/c;Lpp0/v0;Lsf0/a;Lpp0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/t0;->a:Lkf0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/t0;->b:Lpp0/c0;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/t0;->c:Lnp0/c;

    .line 9
    .line 10
    iput-object p4, p0, Lpp0/t0;->d:Lpp0/v0;

    .line 11
    .line 12
    iput-object p5, p0, Lpp0/t0;->e:Lsf0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lpp0/t0;->f:Lpp0/l0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lpp0/t0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lpp0/r0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lpp0/r0;

    .line 11
    .line 12
    iget v3, v2, Lpp0/r0;->h:I

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
    iput v3, v2, Lpp0/r0;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lpp0/r0;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lpp0/r0;-><init>(Lpp0/t0;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lpp0/r0;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lpp0/r0;->h:I

    .line 34
    .line 35
    const/4 v5, 0x4

    .line 36
    const/4 v6, 0x3

    .line 37
    const/4 v7, 0x2

    .line 38
    const/4 v8, 0x1

    .line 39
    const/4 v9, 0x0

    .line 40
    if-eqz v4, :cond_5

    .line 41
    .line 42
    if-eq v4, v8, :cond_4

    .line 43
    .line 44
    if-eq v4, v7, :cond_3

    .line 45
    .line 46
    if-eq v4, v6, :cond_2

    .line 47
    .line 48
    if-ne v4, v5, :cond_1

    .line 49
    .line 50
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object v1

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
    iget-object v4, v2, Lpp0/r0;->e:Lqp0/o;

    .line 63
    .line 64
    iget-object v6, v2, Lpp0/r0;->d:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_3
    iget-object v4, v2, Lpp0/r0;->d:Ljava/lang/String;

    .line 71
    .line 72
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_5
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iget-object v1, v0, Lpp0/t0;->a:Lkf0/b0;

    .line 84
    .line 85
    invoke-virtual {v1}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Lyy0/i;

    .line 90
    .line 91
    iput v8, v2, Lpp0/r0;->h:I

    .line 92
    .line 93
    invoke-static {v1, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    if-ne v1, v3, :cond_6

    .line 98
    .line 99
    goto/16 :goto_5

    .line 100
    .line 101
    :cond_6
    :goto_1
    check-cast v1, Lss0/j0;

    .line 102
    .line 103
    if-eqz v1, :cond_7

    .line 104
    .line 105
    iget-object v1, v1, Lss0/j0;->d:Ljava/lang/String;

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_7
    move-object v1, v9

    .line 109
    :goto_2
    iget-object v4, v0, Lpp0/t0;->b:Lpp0/c0;

    .line 110
    .line 111
    check-cast v4, Lnp0/b;

    .line 112
    .line 113
    iget-object v4, v4, Lnp0/b;->g:Lyy0/l1;

    .line 114
    .line 115
    iput-object v1, v2, Lpp0/r0;->d:Ljava/lang/String;

    .line 116
    .line 117
    iput v7, v2, Lpp0/r0;->h:I

    .line 118
    .line 119
    invoke-static {v4, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    if-ne v4, v3, :cond_8

    .line 124
    .line 125
    goto/16 :goto_5

    .line 126
    .line 127
    :cond_8
    move-object/from16 v16, v4

    .line 128
    .line 129
    move-object v4, v1

    .line 130
    move-object/from16 v1, v16

    .line 131
    .line 132
    :goto_3
    check-cast v1, Lqp0/o;

    .line 133
    .line 134
    iget-object v7, v0, Lpp0/t0;->f:Lpp0/l0;

    .line 135
    .line 136
    invoke-virtual {v7}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v7

    .line 140
    check-cast v7, Lyy0/i;

    .line 141
    .line 142
    iput-object v4, v2, Lpp0/r0;->d:Ljava/lang/String;

    .line 143
    .line 144
    iput-object v1, v2, Lpp0/r0;->e:Lqp0/o;

    .line 145
    .line 146
    iput v6, v2, Lpp0/r0;->h:I

    .line 147
    .line 148
    invoke-static {v7, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    if-ne v6, v3, :cond_9

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_9
    move-object/from16 v16, v4

    .line 156
    .line 157
    move-object v4, v1

    .line 158
    move-object v1, v6

    .line 159
    move-object/from16 v6, v16

    .line 160
    .line 161
    :goto_4
    check-cast v1, Lqp0/r;

    .line 162
    .line 163
    if-nez v6, :cond_a

    .line 164
    .line 165
    new-instance v10, Lne0/c;

    .line 166
    .line 167
    new-instance v11, Ljava/lang/IllegalStateException;

    .line 168
    .line 169
    const-string v0, "No active vin"

    .line 170
    .line 171
    invoke-direct {v11, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    const/4 v14, 0x0

    .line 175
    const/16 v15, 0x1e

    .line 176
    .line 177
    const/4 v12, 0x0

    .line 178
    const/4 v13, 0x0

    .line 179
    invoke-direct/range {v10 .. v15}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 180
    .line 181
    .line 182
    return-object v10

    .line 183
    :cond_a
    if-nez v4, :cond_b

    .line 184
    .line 185
    new-instance v0, Lne0/c;

    .line 186
    .line 187
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 188
    .line 189
    const-string v2, "No active route"

    .line 190
    .line 191
    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    const/4 v4, 0x0

    .line 195
    const/16 v5, 0x1e

    .line 196
    .line 197
    const/4 v2, 0x0

    .line 198
    const/4 v3, 0x0

    .line 199
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 200
    .line 201
    .line 202
    return-object v0

    .line 203
    :cond_b
    if-nez v1, :cond_c

    .line 204
    .line 205
    new-instance v1, Lne0/c;

    .line 206
    .line 207
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 208
    .line 209
    const-string v0, "Missing route settings"

    .line 210
    .line 211
    invoke-direct {v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    const/4 v5, 0x0

    .line 215
    const/16 v6, 0x1e

    .line 216
    .line 217
    const/4 v3, 0x0

    .line 218
    const/4 v4, 0x0

    .line 219
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 220
    .line 221
    .line 222
    return-object v1

    .line 223
    :cond_c
    iget-object v7, v4, Lqp0/o;->a:Ljava/util/List;

    .line 224
    .line 225
    check-cast v7, Ljava/lang/Iterable;

    .line 226
    .line 227
    invoke-static {v7, v8}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 228
    .line 229
    .line 230
    move-result-object v7

    .line 231
    iget-boolean v4, v4, Lqp0/o;->h:Z

    .line 232
    .line 233
    if-eqz v4, :cond_d

    .line 234
    .line 235
    invoke-static {v7}, Ljp/eg;->d(Ljava/util/List;)Ljava/util/ArrayList;

    .line 236
    .line 237
    .line 238
    move-result-object v7

    .line 239
    :cond_d
    iput-object v9, v2, Lpp0/r0;->d:Ljava/lang/String;

    .line 240
    .line 241
    iput-object v9, v2, Lpp0/r0;->e:Lqp0/o;

    .line 242
    .line 243
    iput v5, v2, Lpp0/r0;->h:I

    .line 244
    .line 245
    invoke-virtual {v0, v6, v7, v1, v2}, Lpp0/t0;->c(Ljava/lang/String;Ljava/util/List;Lqp0/r;Lrx0/c;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    if-ne v0, v3, :cond_e

    .line 250
    .line 251
    :goto_5
    return-object v3

    .line 252
    :cond_e
    return-object v0
.end method

.method public final c(Ljava/lang/String;Ljava/util/List;Lqp0/r;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    instance-of v2, v1, Lpp0/s0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lpp0/s0;

    .line 11
    .line 12
    iget v3, v2, Lpp0/s0;->i:I

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
    iput v3, v2, Lpp0/s0;->i:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lpp0/s0;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lpp0/s0;-><init>(Lpp0/t0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lpp0/s0;->g:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lpp0/s0;->i:I

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    const/4 v6, 0x2

    .line 37
    if-eqz v4, :cond_3

    .line 38
    .line 39
    if-eq v4, v5, :cond_2

    .line 40
    .line 41
    if-ne v4, v6, :cond_1

    .line 42
    .line 43
    iget-object v0, v2, Lpp0/s0;->e:Ljava/util/List;

    .line 44
    .line 45
    check-cast v0, Ljava/util/List;

    .line 46
    .line 47
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-object v1

    .line 51
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    iget-object v4, v2, Lpp0/s0;->f:Lqp0/r;

    .line 60
    .line 61
    iget-object v5, v2, Lpp0/s0;->e:Ljava/util/List;

    .line 62
    .line 63
    check-cast v5, Ljava/util/List;

    .line 64
    .line 65
    iget-object v8, v2, Lpp0/s0;->d:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    move-object v1, v8

    .line 71
    goto :goto_4

    .line 72
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    move-object/from16 v1, p1

    .line 76
    .line 77
    iput-object v1, v2, Lpp0/s0;->d:Ljava/lang/String;

    .line 78
    .line 79
    move-object/from16 v4, p2

    .line 80
    .line 81
    check-cast v4, Ljava/util/List;

    .line 82
    .line 83
    iput-object v4, v2, Lpp0/s0;->e:Ljava/util/List;

    .line 84
    .line 85
    move-object/from16 v4, p3

    .line 86
    .line 87
    iput-object v4, v2, Lpp0/s0;->f:Lqp0/r;

    .line 88
    .line 89
    iput v5, v2, Lpp0/s0;->i:I

    .line 90
    .line 91
    move-object/from16 v5, p2

    .line 92
    .line 93
    check-cast v5, Ljava/lang/Iterable;

    .line 94
    .line 95
    new-instance v8, Ljava/util/ArrayList;

    .line 96
    .line 97
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 98
    .line 99
    .line 100
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 101
    .line 102
    .line 103
    move-result-object v5

    .line 104
    :cond_4
    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result v9

    .line 108
    if-eqz v9, :cond_6

    .line 109
    .line 110
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v9

    .line 114
    check-cast v9, Lqp0/b0;

    .line 115
    .line 116
    iget-object v9, v9, Lqp0/b0;->l:Ljava/lang/String;

    .line 117
    .line 118
    if-eqz v9, :cond_5

    .line 119
    .line 120
    new-instance v10, Ldk0/a;

    .line 121
    .line 122
    sget-object v11, Ldk0/b;->f:Ldk0/b;

    .line 123
    .line 124
    invoke-direct {v10, v9, v11}, Ldk0/a;-><init>(Ljava/lang/String;Ldk0/b;)V

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_5
    const/4 v10, 0x0

    .line 129
    :goto_2
    if-eqz v10, :cond_4

    .line 130
    .line 131
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_6
    iget-object v5, v0, Lpp0/t0;->d:Lpp0/v0;

    .line 136
    .line 137
    invoke-virtual {v5, v8, v2}, Lpp0/v0;->b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v5

    .line 141
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 142
    .line 143
    if-ne v5, v8, :cond_7

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_7
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    :goto_3
    if-ne v5, v3, :cond_8

    .line 149
    .line 150
    goto/16 :goto_9

    .line 151
    .line 152
    :cond_8
    move-object/from16 v5, p2

    .line 153
    .line 154
    :goto_4
    check-cast v5, Ljava/lang/Iterable;

    .line 155
    .line 156
    new-instance v8, Ljava/util/ArrayList;

    .line 157
    .line 158
    const/16 v9, 0xa

    .line 159
    .line 160
    invoke-static {v5, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 161
    .line 162
    .line 163
    move-result v9

    .line 164
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 165
    .line 166
    .line 167
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    :goto_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 172
    .line 173
    .line 174
    move-result v9

    .line 175
    const-string v10, "<this>"

    .line 176
    .line 177
    if-eqz v9, :cond_d

    .line 178
    .line 179
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v9

    .line 183
    check-cast v9, Lqp0/b0;

    .line 184
    .line 185
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    new-instance v11, Lqp0/l;

    .line 189
    .line 190
    iget-object v10, v9, Lqp0/b0;->a:Ljava/lang/String;

    .line 191
    .line 192
    const-string v12, ""

    .line 193
    .line 194
    if-nez v10, :cond_9

    .line 195
    .line 196
    move-object v10, v12

    .line 197
    :cond_9
    iget-object v13, v9, Lqp0/b0;->b:Ljava/lang/String;

    .line 198
    .line 199
    if-nez v13, :cond_a

    .line 200
    .line 201
    move-object v13, v12

    .line 202
    :cond_a
    iget-object v14, v9, Lqp0/b0;->c:Lqp0/t0;

    .line 203
    .line 204
    iget-object v12, v9, Lqp0/b0;->d:Lxj0/f;

    .line 205
    .line 206
    if-nez v12, :cond_b

    .line 207
    .line 208
    new-instance v12, Lxj0/f;

    .line 209
    .line 210
    const-wide/16 v6, 0x0

    .line 211
    .line 212
    invoke-direct {v12, v6, v7, v6, v7}, Lxj0/f;-><init>(DD)V

    .line 213
    .line 214
    .line 215
    :cond_b
    move-object v15, v12

    .line 216
    iget-object v6, v9, Lqp0/b0;->e:Lbl0/a;

    .line 217
    .line 218
    iget-object v7, v9, Lqp0/b0;->j:Lmy0/c;

    .line 219
    .line 220
    move-object/from16 p1, v5

    .line 221
    .line 222
    move-object/from16 v16, v6

    .line 223
    .line 224
    if-eqz v7, :cond_c

    .line 225
    .line 226
    iget-wide v5, v7, Lmy0/c;->d:J

    .line 227
    .line 228
    sget-object v7, Lmy0/e;->h:Lmy0/e;

    .line 229
    .line 230
    invoke-static {v5, v6, v7}, Lmy0/c;->n(JLmy0/e;)J

    .line 231
    .line 232
    .line 233
    move-result-wide v5

    .line 234
    long-to-int v5, v5

    .line 235
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 236
    .line 237
    .line 238
    move-result-object v5

    .line 239
    move-object/from16 v17, v5

    .line 240
    .line 241
    :goto_6
    move-object v12, v10

    .line 242
    goto :goto_7

    .line 243
    :cond_c
    const/16 v17, 0x0

    .line 244
    .line 245
    goto :goto_6

    .line 246
    :goto_7
    invoke-direct/range {v11 .. v17}, Lqp0/l;-><init>(Ljava/lang/String;Ljava/lang/String;Lqp0/t0;Lxj0/f;Lbl0/a;Ljava/lang/Integer;)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    move-object/from16 v5, p1

    .line 253
    .line 254
    const/4 v6, 0x2

    .line 255
    goto :goto_5

    .line 256
    :cond_d
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    const/4 v5, 0x0

    .line 260
    invoke-static {v4, v5}, Ljp/cg;->c(Lqp0/r;Z)Ljava/util/List;

    .line 261
    .line 262
    .line 263
    move-result-object v5

    .line 264
    if-nez v5, :cond_e

    .line 265
    .line 266
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 267
    .line 268
    :cond_e
    iget-boolean v6, v4, Lqp0/r;->g:Z

    .line 269
    .line 270
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 271
    .line 272
    .line 273
    move-result-object v6

    .line 274
    iget-object v4, v4, Lqp0/r;->f:Lqr0/l;

    .line 275
    .line 276
    if-eqz v4, :cond_f

    .line 277
    .line 278
    new-instance v7, Lqp0/h;

    .line 279
    .line 280
    iget v4, v4, Lqr0/l;->d:I

    .line 281
    .line 282
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    invoke-direct {v7, v4}, Lqp0/h;-><init>(Ljava/lang/Integer;)V

    .line 287
    .line 288
    .line 289
    goto :goto_8

    .line 290
    :cond_f
    const/4 v7, 0x0

    .line 291
    :goto_8
    new-instance v4, Lqp0/k;

    .line 292
    .line 293
    invoke-direct {v4, v5, v6, v7}, Lqp0/k;-><init>(Ljava/util/List;Ljava/lang/Boolean;Lqp0/h;)V

    .line 294
    .line 295
    .line 296
    new-instance v5, Lqp0/y;

    .line 297
    .line 298
    invoke-direct {v5, v1, v8, v4}, Lqp0/y;-><init>(Ljava/lang/String;Ljava/util/ArrayList;Lqp0/k;)V

    .line 299
    .line 300
    .line 301
    iget-object v1, v0, Lpp0/t0;->c:Lnp0/c;

    .line 302
    .line 303
    iget-object v4, v1, Lnp0/c;->a:Lxl0/f;

    .line 304
    .line 305
    new-instance v6, Llo0/b;

    .line 306
    .line 307
    const/4 v7, 0x5

    .line 308
    const/4 v8, 0x0

    .line 309
    invoke-direct {v6, v7, v1, v5, v8}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v4, v6}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    iget-object v0, v0, Lpp0/t0;->e:Lsf0/a;

    .line 317
    .line 318
    invoke-static {v1, v0, v8}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 319
    .line 320
    .line 321
    move-result-object v0

    .line 322
    iput-object v8, v2, Lpp0/s0;->d:Ljava/lang/String;

    .line 323
    .line 324
    iput-object v8, v2, Lpp0/s0;->e:Ljava/util/List;

    .line 325
    .line 326
    iput-object v8, v2, Lpp0/s0;->f:Lqp0/r;

    .line 327
    .line 328
    const/4 v1, 0x2

    .line 329
    iput v1, v2, Lpp0/s0;->i:I

    .line 330
    .line 331
    invoke-static {v0, v2}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    if-ne v0, v3, :cond_10

    .line 336
    .line 337
    :goto_9
    return-object v3

    .line 338
    :cond_10
    return-object v0
.end method
