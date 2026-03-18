.class public final Lh7/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/LinkedHashMap;

.field public final synthetic b:Lh7/m;


# direct methods
.method public constructor <init>(Lh7/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh7/l;->b:Lh7/m;

    .line 5
    .line 6
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lh7/l;->a:Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lh7/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lh7/j;

    .line 7
    .line 8
    iget v1, v0, Lh7/j;->h:I

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
    iput v1, v0, Lh7/j;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh7/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lh7/j;-><init>(Lh7/l;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lh7/j;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh7/j;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p2, v0, Lh7/j;->e:Ljava/lang/String;

    .line 37
    .line 38
    iget-object p0, v0, Lh7/j;->d:Lh7/l;

    .line 39
    .line 40
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    const-string p3, "context"

    .line 56
    .line 57
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-static {p1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iget-object p3, p1, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 65
    .line 66
    iget-object p1, p1, Lfb/u;->d:Lob/a;

    .line 67
    .line 68
    const-string v2, "<this>"

    .line 69
    .line 70
    invoke-static {p3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const-string v2, "executor"

    .line 74
    .line 75
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v2, "name"

    .line 79
    .line 80
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    new-instance v2, Lif0/d;

    .line 84
    .line 85
    const/16 v4, 0x1c

    .line 86
    .line 87
    invoke-direct {v2, p2, v4}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    iget-object p1, p1, Lob/a;->a:Lla/a0;

    .line 91
    .line 92
    const-string v4, "getSerialTaskExecutor(...)"

    .line 93
    .line 94
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-instance v4, Llk/j;

    .line 98
    .line 99
    const/16 v5, 0x13

    .line 100
    .line 101
    invoke-direct {v4, v5, v2, p3}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    new-instance p3, Lbb/i;

    .line 105
    .line 106
    const/4 v2, 0x4

    .line 107
    const-string v5, "loadStatusFuture"

    .line 108
    .line 109
    invoke-direct {p3, p1, v5, v4, v2}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 110
    .line 111
    .line 112
    invoke-static {p3}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    iput-object p0, v0, Lh7/j;->d:Lh7/l;

    .line 117
    .line 118
    iput-object p2, v0, Lh7/j;->e:Ljava/lang/String;

    .line 119
    .line 120
    iput v3, v0, Lh7/j;->h:I

    .line 121
    .line 122
    invoke-static {p1, v0}, Llp/vf;->c(Lcom/google/common/util/concurrent/ListenableFuture;Lrx0/c;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p3

    .line 126
    if-ne p3, v1, :cond_3

    .line 127
    .line 128
    return-object v1

    .line 129
    :cond_3
    :goto_1
    check-cast p3, Ljava/lang/Iterable;

    .line 130
    .line 131
    instance-of p1, p3, Ljava/util/Collection;

    .line 132
    .line 133
    const/4 v0, 0x0

    .line 134
    if-eqz p1, :cond_5

    .line 135
    .line 136
    move-object p1, p3

    .line 137
    check-cast p1, Ljava/util/Collection;

    .line 138
    .line 139
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 140
    .line 141
    .line 142
    move-result p1

    .line 143
    if-eqz p1, :cond_5

    .line 144
    .line 145
    :cond_4
    move p1, v0

    .line 146
    goto :goto_2

    .line 147
    :cond_5
    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    :cond_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 152
    .line 153
    .line 154
    move-result p3

    .line 155
    if-eqz p3, :cond_4

    .line 156
    .line 157
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p3

    .line 161
    check-cast p3, Leb/i0;

    .line 162
    .line 163
    sget-object v1, Leb/h0;->e:Leb/h0;

    .line 164
    .line 165
    sget-object v2, Leb/h0;->d:Leb/h0;

    .line 166
    .line 167
    filled-new-array {v1, v2}, [Leb/h0;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    iget-object p3, p3, Leb/i0;->b:Leb/h0;

    .line 176
    .line 177
    invoke-interface {v1, p3}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result p3

    .line 181
    if-eqz p3, :cond_6

    .line 182
    .line 183
    move p1, v3

    .line 184
    :goto_2
    iget-object p0, p0, Lh7/l;->a:Ljava/util/LinkedHashMap;

    .line 185
    .line 186
    invoke-virtual {p0, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    check-cast p0, La7/n;

    .line 191
    .line 192
    if-eqz p0, :cond_7

    .line 193
    .line 194
    iget-object p0, p0, La7/n;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 195
    .line 196
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    goto :goto_3

    .line 201
    :cond_7
    move p0, v0

    .line 202
    :goto_3
    if-eqz p0, :cond_8

    .line 203
    .line 204
    if-eqz p1, :cond_8

    .line 205
    .line 206
    goto :goto_4

    .line 207
    :cond_8
    move v3, v0

    .line 208
    :goto_4
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    return-object p0
.end method

.method public final b(Landroid/content/Context;La7/n;Lrx0/c;)Ljava/lang/Object;
    .locals 21

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
    move-object/from16 v3, p3

    .line 8
    .line 9
    instance-of v4, v3, Lh7/k;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v3

    .line 14
    check-cast v4, Lh7/k;

    .line 15
    .line 16
    iget v5, v4, Lh7/k;->h:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lh7/k;->h:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lh7/k;

    .line 29
    .line 30
    invoke-direct {v4, v0, v3}, Lh7/k;-><init>(Lh7/l;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v3, v4, Lh7/k;->f:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lh7/k;->h:I

    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    const-string v8, "context"

    .line 41
    .line 42
    const-class v9, Landroidx/glance/session/SessionWorker;

    .line 43
    .line 44
    const/4 v10, 0x1

    .line 45
    if-eqz v6, :cond_2

    .line 46
    .line 47
    if-ne v6, v10, :cond_1

    .line 48
    .line 49
    iget-object v0, v4, Lh7/k;->e:Landroid/content/Context;

    .line 50
    .line 51
    iget-object v1, v4, Lh7/k;->d:Lh7/l;

    .line 52
    .line 53
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move-object/from16 v20, v1

    .line 57
    .line 58
    move-object v1, v0

    .line 59
    move-object/from16 v0, v20

    .line 60
    .line 61
    goto/16 :goto_1

    .line 62
    .line 63
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_2
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iget-object v3, v2, La7/n;->a:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v6, v0, Lh7/l;->a:Ljava/util/LinkedHashMap;

    .line 77
    .line 78
    invoke-interface {v6, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    check-cast v2, La7/n;

    .line 83
    .line 84
    const/4 v6, 0x0

    .line 85
    if-eqz v2, :cond_3

    .line 86
    .line 87
    iget-object v11, v2, La7/n;->c:Lxy0/j;

    .line 88
    .line 89
    invoke-virtual {v11, v7}, Lxy0/j;->h(Ljava/lang/Throwable;)Z

    .line 90
    .line 91
    .line 92
    iget-object v11, v2, La7/n;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 93
    .line 94
    invoke-virtual {v11, v6}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 95
    .line 96
    .line 97
    iget-object v2, v2, La7/n;->l:Lvy0/k1;

    .line 98
    .line 99
    invoke-virtual {v2, v7}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 100
    .line 101
    .line 102
    :cond_3
    new-instance v2, Leb/y;

    .line 103
    .line 104
    const/4 v11, 0x0

    .line 105
    invoke-direct {v2, v11, v9}, Leb/y;-><init>(ILjava/lang/Class;)V

    .line 106
    .line 107
    .line 108
    new-instance v11, Llx0/l;

    .line 109
    .line 110
    const-string v12, "KEY"

    .line 111
    .line 112
    invoke-direct {v11, v12, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    filled-new-array {v11}, [Llx0/l;

    .line 116
    .line 117
    .line 118
    move-result-object v11

    .line 119
    new-instance v12, Leb/c0;

    .line 120
    .line 121
    invoke-direct {v12}, Leb/c0;-><init>()V

    .line 122
    .line 123
    .line 124
    aget-object v6, v11, v6

    .line 125
    .line 126
    iget-object v11, v6, Llx0/l;->d:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v11, Ljava/lang/String;

    .line 129
    .line 130
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 131
    .line 132
    invoke-virtual {v12, v6, v11}, Leb/c0;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    new-instance v6, Leb/h;

    .line 136
    .line 137
    iget-object v11, v12, Leb/c0;->a:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v11, Ljava/util/LinkedHashMap;

    .line 140
    .line 141
    invoke-direct {v6, v11}, Leb/h;-><init>(Ljava/util/LinkedHashMap;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v6}, Lkp/b6;->d(Leb/h;)[B

    .line 145
    .line 146
    .line 147
    iget-object v11, v2, Leb/j0;->f:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v11, Lmb/o;

    .line 150
    .line 151
    iput-object v6, v11, Lmb/o;->e:Leb/h;

    .line 152
    .line 153
    invoke-virtual {v2}, Leb/j0;->h()Leb/k0;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    check-cast v2, Leb/z;

    .line 158
    .line 159
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-static {v1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 163
    .line 164
    .line 165
    move-result-object v6

    .line 166
    sget-object v11, Leb/m;->d:Leb/m;

    .line 167
    .line 168
    invoke-virtual {v6, v3, v11, v2}, Lkp/g6;->a(Ljava/lang/String;Leb/m;Leb/z;)Leb/c0;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    iget-object v2, v2, Leb/c0;->a:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v2, Ly4/k;

    .line 175
    .line 176
    iput-object v0, v4, Lh7/k;->d:Lh7/l;

    .line 177
    .line 178
    iput-object v1, v4, Lh7/k;->e:Landroid/content/Context;

    .line 179
    .line 180
    iput v10, v4, Lh7/k;->h:I

    .line 181
    .line 182
    invoke-static {v2, v4}, Llp/vf;->c(Lcom/google/common/util/concurrent/ListenableFuture;Lrx0/c;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    if-ne v2, v5, :cond_4

    .line 187
    .line 188
    return-object v5

    .line 189
    :cond_4
    :goto_1
    iget-object v0, v0, Lh7/l;->b:Lh7/m;

    .line 190
    .line 191
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    invoke-static {v1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    sget-object v1, Leb/m;->e:Leb/m;

    .line 199
    .line 200
    new-instance v2, Leb/y;

    .line 201
    .line 202
    const/4 v3, 0x0

    .line 203
    invoke-direct {v2, v3, v9}, Leb/y;-><init>(ILjava/lang/Class;)V

    .line 204
    .line 205
    .line 206
    sget-object v3, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 207
    .line 208
    const-string v4, "timeUnit"

    .line 209
    .line 210
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    iget-object v4, v2, Leb/j0;->f:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v4, Lmb/o;

    .line 216
    .line 217
    const-wide/16 v5, 0xe42

    .line 218
    .line 219
    invoke-virtual {v3, v5, v6}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 220
    .line 221
    .line 222
    move-result-wide v5

    .line 223
    iput-wide v5, v4, Lmb/o;->g:J

    .line 224
    .line 225
    const-wide v3, 0x7fffffffffffffffL

    .line 226
    .line 227
    .line 228
    .line 229
    .line 230
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 231
    .line 232
    .line 233
    move-result-wide v5

    .line 234
    sub-long/2addr v3, v5

    .line 235
    iget-object v5, v2, Leb/j0;->f:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v5, Lmb/o;

    .line 238
    .line 239
    iget-wide v5, v5, Lmb/o;->g:J

    .line 240
    .line 241
    cmp-long v3, v3, v5

    .line 242
    .line 243
    if-lez v3, :cond_5

    .line 244
    .line 245
    new-instance v9, Lnb/d;

    .line 246
    .line 247
    invoke-direct {v9, v7}, Lnb/d;-><init>(Landroid/net/NetworkRequest;)V

    .line 248
    .line 249
    .line 250
    sget-object v10, Leb/x;->d:Leb/x;

    .line 251
    .line 252
    new-instance v3, Ljava/util/LinkedHashSet;

    .line 253
    .line 254
    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 255
    .line 256
    .line 257
    invoke-static {v3}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 258
    .line 259
    .line 260
    move-result-object v19

    .line 261
    new-instance v8, Leb/e;

    .line 262
    .line 263
    const/4 v11, 0x1

    .line 264
    const/4 v12, 0x0

    .line 265
    const/4 v13, 0x0

    .line 266
    const/4 v14, 0x0

    .line 267
    const-wide/16 v15, -0x1

    .line 268
    .line 269
    move-wide/from16 v17, v15

    .line 270
    .line 271
    invoke-direct/range {v8 .. v19}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 272
    .line 273
    .line 274
    iget-object v3, v2, Leb/j0;->f:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v3, Lmb/o;

    .line 277
    .line 278
    iput-object v8, v3, Lmb/o;->j:Leb/e;

    .line 279
    .line 280
    invoke-virtual {v2}, Leb/j0;->h()Leb/k0;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    check-cast v2, Leb/z;

    .line 285
    .line 286
    const-string v3, "sessionWorkerKeepEnabled"

    .line 287
    .line 288
    invoke-virtual {v0, v3, v1, v2}, Lkp/g6;->a(Ljava/lang/String;Leb/m;Leb/z;)Leb/c0;

    .line 289
    .line 290
    .line 291
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    return-object v0

    .line 294
    :cond_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 295
    .line 296
    const-string v1, "The given initial delay is too large and will cause an overflow!"

    .line 297
    .line 298
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    throw v0
.end method
