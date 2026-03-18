.class public abstract Ln3/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lcom/google/common/util/concurrent/ListenableFuture;)V
    .locals 2

    .line 1
    invoke-interface {p0}, Ljava/util/concurrent/Future;->isDone()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    :goto_0
    :try_start_0
    invoke-interface {p0}, Ljava/util/concurrent/Future;->get()Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V

    .line 29
    .line 30
    .line 31
    :cond_1
    throw p0

    .line 32
    :catch_0
    const/4 v0, 0x1

    .line 33
    goto :goto_0

    .line 34
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const-string v1, "Future was expected to be done: %s"

    .line 41
    .line 42
    invoke-static {v1, p0}, Lkp/j9;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0
.end method

.method public static final b(Landroid/view/KeyEvent;)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljp/x1;->a(I)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public static final c(Landroid/view/KeyEvent;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/KeyEvent;->getAction()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_0
    return v0

    .line 13
    :cond_1
    const/4 p0, 0x2

    .line 14
    return p0
.end method

.method public static final d(Ljava/util/List;Lij0/a;Lxf0/a;)Ljava/util/ArrayList;
    .locals 12

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "drawableResource"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p0, :cond_a

    .line 13
    .line 14
    check-cast p0, Ljava/lang/Iterable;

    .line 15
    .line 16
    new-instance v1, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    move-object v3, v2

    .line 36
    check-cast v3, Lcq0/j;

    .line 37
    .line 38
    iget-object v3, v3, Lcq0/j;->e:Lcq0/l;

    .line 39
    .line 40
    sget-object v4, Lcq0/l;->i:Lcq0/l;

    .line 41
    .line 42
    if-eq v3, v4, :cond_0

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    new-instance p0, Ljava/util/ArrayList;

    .line 49
    .line 50
    const/16 v2, 0xa

    .line 51
    .line 52
    invoke-static {v1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    invoke-direct {p0, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eqz v3, :cond_9

    .line 68
    .line 69
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    check-cast v3, Lcq0/j;

    .line 74
    .line 75
    const-string v4, "<this>"

    .line 76
    .line 77
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget-object v6, v3, Lcq0/j;->a:Ljava/lang/String;

    .line 81
    .line 82
    iget-object v4, v3, Lcq0/j;->e:Lcq0/l;

    .line 83
    .line 84
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    const/4 v7, 0x0

    .line 89
    if-eqz v5, :cond_6

    .line 90
    .line 91
    const/4 v8, 0x1

    .line 92
    if-eq v5, v8, :cond_6

    .line 93
    .line 94
    const/4 v8, 0x2

    .line 95
    if-eq v5, v8, :cond_5

    .line 96
    .line 97
    const/4 v8, 0x3

    .line 98
    if-eq v5, v8, :cond_4

    .line 99
    .line 100
    const/4 v8, 0x4

    .line 101
    if-eq v5, v8, :cond_3

    .line 102
    .line 103
    const/4 v7, 0x5

    .line 104
    if-ne v5, v7, :cond_2

    .line 105
    .line 106
    const-string v5, ""

    .line 107
    .line 108
    :goto_2
    move-object v7, v5

    .line 109
    goto :goto_3

    .line 110
    :cond_2
    new-instance p0, La8/r0;

    .line 111
    .line 112
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_3
    new-array v5, v7, [Ljava/lang/Object;

    .line 117
    .line 118
    move-object v7, p1

    .line 119
    check-cast v7, Ljj0/f;

    .line 120
    .line 121
    const v8, 0x7f121188

    .line 122
    .line 123
    .line 124
    invoke-virtual {v7, v8, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    goto :goto_2

    .line 129
    :cond_4
    new-array v5, v7, [Ljava/lang/Object;

    .line 130
    .line 131
    move-object v7, p1

    .line 132
    check-cast v7, Ljj0/f;

    .line 133
    .line 134
    const v8, 0x7f121186

    .line 135
    .line 136
    .line 137
    invoke-virtual {v7, v8, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v5

    .line 141
    goto :goto_2

    .line 142
    :cond_5
    new-array v5, v7, [Ljava/lang/Object;

    .line 143
    .line 144
    move-object v7, p1

    .line 145
    check-cast v7, Ljj0/f;

    .line 146
    .line 147
    const v8, 0x7f121185

    .line 148
    .line 149
    .line 150
    invoke-virtual {v7, v8, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    goto :goto_2

    .line 155
    :cond_6
    new-array v5, v7, [Ljava/lang/Object;

    .line 156
    .line 157
    move-object v7, p1

    .line 158
    check-cast v7, Ljj0/f;

    .line 159
    .line 160
    const v8, 0x7f121187

    .line 161
    .line 162
    .line 163
    invoke-virtual {v7, v8, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    goto :goto_2

    .line 168
    :goto_3
    iget-object v5, v3, Lcq0/j;->h:Ljava/time/OffsetDateTime;

    .line 169
    .line 170
    iget-object v8, v3, Lcq0/j;->m:Ljava/time/OffsetDateTime;

    .line 171
    .line 172
    invoke-static {v4, p1, v5, v8}, Lnv/c;->b(Lcq0/l;Lij0/a;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;)Llp/ie;

    .line 173
    .line 174
    .line 175
    move-result-object v8

    .line 176
    iget-object v9, v3, Lcq0/j;->b:Ljava/lang/String;

    .line 177
    .line 178
    iget-object v4, v3, Lcq0/j;->c:Ljava/util/List;

    .line 179
    .line 180
    if-eqz v4, :cond_8

    .line 181
    .line 182
    check-cast v4, Ljava/lang/Iterable;

    .line 183
    .line 184
    new-instance v5, Ljava/util/ArrayList;

    .line 185
    .line 186
    invoke-static {v4, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 187
    .line 188
    .line 189
    move-result v10

    .line 190
    invoke-direct {v5, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 191
    .line 192
    .line 193
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 194
    .line 195
    .line 196
    move-result-object v4

    .line 197
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 198
    .line 199
    .line 200
    move-result v10

    .line 201
    if-eqz v10, :cond_7

    .line 202
    .line 203
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v10

    .line 207
    check-cast v10, Lcq0/r;

    .line 208
    .line 209
    iget-boolean v11, v3, Lcq0/j;->p:Z

    .line 210
    .line 211
    invoke-static {v10, p2, v11}, Ly70/v1;->b(Lcq0/r;Lxf0/a;Z)Ly70/m0;

    .line 212
    .line 213
    .line 214
    move-result-object v10

    .line 215
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_7
    move-object v10, v5

    .line 220
    goto :goto_5

    .line 221
    :cond_8
    move-object v10, v0

    .line 222
    :goto_5
    new-instance v5, Ly70/f0;

    .line 223
    .line 224
    invoke-direct/range {v5 .. v10}, Ly70/f0;-><init>(Ljava/lang/String;Ljava/lang/String;Llp/ie;Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    goto/16 :goto_1

    .line 231
    .line 232
    :cond_9
    return-object p0

    .line 233
    :cond_a
    return-object v0
.end method
