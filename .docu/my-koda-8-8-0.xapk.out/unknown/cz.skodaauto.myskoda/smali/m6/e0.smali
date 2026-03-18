.class public final Lm6/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/a;


# instance fields
.field public final a:Ljava/io/File;

.field public final b:Lm6/u0;

.field public final c:Lm6/i0;

.field public final d:La7/j;

.field public final e:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final f:Lez0/c;


# direct methods
.method public constructor <init>(Ljava/io/File;Lm6/u0;Lm6/i0;La7/j;)V
    .locals 1

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "coordinator"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lm6/e0;->a:Ljava/io/File;

    .line 15
    .line 16
    iput-object p2, p0, Lm6/e0;->b:Lm6/u0;

    .line 17
    .line 18
    iput-object p3, p0, Lm6/e0;->c:Lm6/i0;

    .line 19
    .line 20
    iput-object p4, p0, Lm6/e0;->d:La7/j;

    .line 21
    .line 22
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lm6/e0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 29
    .line 30
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lm6/e0;->f:Lez0/c;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final a(Lkn/o;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lm6/c0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm6/c0;

    .line 7
    .line 8
    iget v1, v0, Lm6/c0;->i:I

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
    iput v1, v0, Lm6/c0;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/c0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lm6/c0;-><init>(Lm6/e0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm6/c0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/c0;->i:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-boolean p0, v0, Lm6/c0;->f:Z

    .line 38
    .line 39
    iget-object p1, v0, Lm6/c0;->e:Lm6/z;

    .line 40
    .line 41
    iget-object v0, v0, Lm6/c0;->d:Lm6/e0;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :catchall_0
    move-exception p2

    .line 48
    move-object v7, p2

    .line 49
    move p2, p0

    .line 50
    move-object p0, v0

    .line 51
    move-object v0, v7

    .line 52
    goto :goto_3

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object p2, p0, Lm6/e0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 65
    .line 66
    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-nez p2, :cond_7

    .line 71
    .line 72
    iget-object p2, p0, Lm6/e0;->f:Lez0/c;

    .line 73
    .line 74
    invoke-virtual {p2}, Lez0/c;->tryLock()Z

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    :try_start_1
    new-instance v2, Lm6/z;

    .line 79
    .line 80
    iget-object v5, p0, Lm6/e0;->a:Ljava/io/File;

    .line 81
    .line 82
    iget-object v6, p0, Lm6/e0;->b:Lm6/u0;

    .line 83
    .line 84
    invoke-direct {v2, v5, v6}, Lm6/z;-><init>(Ljava/io/File;Lm6/u0;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_5

    .line 85
    .line 86
    .line 87
    :try_start_2
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    iput-object p0, v0, Lm6/c0;->d:Lm6/e0;

    .line 92
    .line 93
    iput-object v2, v0, Lm6/c0;->e:Lm6/z;

    .line 94
    .line 95
    iput-boolean p2, v0, Lm6/c0;->f:Z

    .line 96
    .line 97
    iput v3, v0, Lm6/c0;->i:I

    .line 98
    .line 99
    invoke-virtual {p1, v2, v5, v0}, Lkn/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 103
    if-ne p1, v1, :cond_3

    .line 104
    .line 105
    return-object v1

    .line 106
    :cond_3
    move-object v0, p0

    .line 107
    move p0, p2

    .line 108
    move-object p2, p1

    .line 109
    move-object p1, v2

    .line 110
    :goto_1
    :try_start_3
    invoke-interface {p1}, Lm6/a;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 111
    .line 112
    .line 113
    move-object p1, v4

    .line 114
    goto :goto_2

    .line 115
    :catchall_1
    move-exception p1

    .line 116
    :goto_2
    if-nez p1, :cond_5

    .line 117
    .line 118
    if-eqz p0, :cond_4

    .line 119
    .line 120
    iget-object p0, v0, Lm6/e0;->f:Lez0/c;

    .line 121
    .line 122
    invoke-virtual {p0, v4}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_4
    return-object p2

    .line 126
    :cond_5
    :try_start_4
    throw p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 127
    :catchall_2
    move-exception p1

    .line 128
    move p2, p0

    .line 129
    move-object p0, v0

    .line 130
    goto :goto_5

    .line 131
    :catchall_3
    move-exception p1

    .line 132
    move-object v0, p1

    .line 133
    move-object p1, v2

    .line 134
    :goto_3
    :try_start_5
    invoke-interface {p1}, Lm6/a;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 135
    .line 136
    .line 137
    goto :goto_4

    .line 138
    :catchall_4
    move-exception p1

    .line 139
    :try_start_6
    invoke-static {v0, p1}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    :goto_4
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    .line 143
    :catchall_5
    move-exception p1

    .line 144
    :goto_5
    if-eqz p2, :cond_6

    .line 145
    .line 146
    iget-object p0, p0, Lm6/e0;->f:Lez0/c;

    .line 147
    .line 148
    invoke-virtual {p0, v4}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    :cond_6
    throw p1

    .line 152
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 153
    .line 154
    const-string p1, "StorageConnection has already been disposed."

    .line 155
    .line 156
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    throw p0
.end method

.method public final b(Lm6/v;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    const-string v0, "Unable to rename "

    .line 2
    .line 3
    instance-of v1, p2, Lm6/d0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lm6/d0;

    .line 9
    .line 10
    iget v2, v1, Lm6/d0;->j:I

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
    iput v2, v1, Lm6/d0;->j:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lm6/d0;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lm6/d0;-><init>(Lm6/e0;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lm6/d0;->h:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lm6/d0;->j:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v3, :cond_3

    .line 37
    .line 38
    if-eq v3, v5, :cond_2

    .line 39
    .line 40
    if-ne v3, v4, :cond_1

    .line 41
    .line 42
    iget-object p0, v1, Lm6/d0;->g:Lm6/g0;

    .line 43
    .line 44
    iget-object p1, v1, Lm6/d0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Ljava/io/File;

    .line 47
    .line 48
    iget-object v2, v1, Lm6/d0;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v2, Lez0/a;

    .line 51
    .line 52
    iget-object v1, v1, Lm6/d0;->d:Lm6/e0;

    .line 53
    .line 54
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :catchall_0
    move-exception p2

    .line 60
    goto/16 :goto_9

    .line 61
    .line 62
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_2
    iget-object p0, v1, Lm6/d0;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lez0/a;

    .line 73
    .line 74
    iget-object p1, v1, Lm6/d0;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p1, Lay0/n;

    .line 77
    .line 78
    iget-object v3, v1, Lm6/d0;->d:Lm6/e0;

    .line 79
    .line 80
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    move-object p2, p0

    .line 84
    move-object p0, v3

    .line 85
    goto :goto_2

    .line 86
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object p2, p0, Lm6/e0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 90
    .line 91
    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 92
    .line 93
    .line 94
    move-result p2

    .line 95
    if-nez p2, :cond_c

    .line 96
    .line 97
    iget-object p2, p0, Lm6/e0;->a:Ljava/io/File;

    .line 98
    .line 99
    invoke-virtual {p2}, Ljava/io/File;->getCanonicalFile()Ljava/io/File;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    invoke-virtual {v3}, Ljava/io/File;->getParentFile()Ljava/io/File;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    if-eqz v3, :cond_5

    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/io/File;->mkdirs()Z

    .line 110
    .line 111
    .line 112
    invoke-virtual {v3}, Ljava/io/File;->isDirectory()Z

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    if-eqz v3, :cond_4

    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_4
    new-instance p0, Ljava/io/IOException;

    .line 120
    .line 121
    new-instance p1, Ljava/lang/StringBuilder;

    .line 122
    .line 123
    const-string v0, "Unable to create parent directories of "

    .line 124
    .line 125
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw p0

    .line 139
    :cond_5
    :goto_1
    iput-object p0, v1, Lm6/d0;->d:Lm6/e0;

    .line 140
    .line 141
    iput-object p1, v1, Lm6/d0;->e:Ljava/lang/Object;

    .line 142
    .line 143
    iget-object p2, p0, Lm6/e0;->f:Lez0/c;

    .line 144
    .line 145
    iput-object p2, v1, Lm6/d0;->f:Ljava/lang/Object;

    .line 146
    .line 147
    iput v5, v1, Lm6/d0;->j:I

    .line 148
    .line 149
    invoke-virtual {p2, v1}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    if-ne v3, v2, :cond_6

    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_6
    :goto_2
    :try_start_1
    new-instance v3, Ljava/io/File;

    .line 157
    .line 158
    new-instance v7, Ljava/lang/StringBuilder;

    .line 159
    .line 160
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 161
    .line 162
    .line 163
    iget-object v8, p0, Lm6/e0;->a:Ljava/io/File;

    .line 164
    .line 165
    invoke-virtual {v8}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v8

    .line 169
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    const-string v8, ".tmp"

    .line 173
    .line 174
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v7

    .line 181
    invoke-direct {v3, v7}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_5

    .line 182
    .line 183
    .line 184
    :try_start_2
    new-instance v7, Lm6/g0;

    .line 185
    .line 186
    iget-object v8, p0, Lm6/e0;->b:Lm6/u0;

    .line 187
    .line 188
    const-string v9, "serializer"

    .line 189
    .line 190
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-direct {v7, v3, v8}, Lm6/z;-><init>(Ljava/io/File;Lm6/u0;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 194
    .line 195
    .line 196
    :try_start_3
    iput-object p0, v1, Lm6/d0;->d:Lm6/e0;

    .line 197
    .line 198
    iput-object p2, v1, Lm6/d0;->e:Ljava/lang/Object;

    .line 199
    .line 200
    iput-object v3, v1, Lm6/d0;->f:Ljava/lang/Object;

    .line 201
    .line 202
    iput-object v7, v1, Lm6/d0;->g:Lm6/g0;

    .line 203
    .line 204
    iput v4, v1, Lm6/d0;->j:I

    .line 205
    .line 206
    invoke-interface {p1, v7, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 210
    if-ne p1, v2, :cond_7

    .line 211
    .line 212
    :goto_3
    return-object v2

    .line 213
    :cond_7
    move-object v1, p0

    .line 214
    move-object v2, p2

    .line 215
    move-object p1, v3

    .line 216
    move-object p0, v7

    .line 217
    :goto_4
    :try_start_4
    invoke-interface {p0}, Lm6/a;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 218
    .line 219
    .line 220
    move-object p0, v6

    .line 221
    goto :goto_5

    .line 222
    :catchall_1
    move-exception p0

    .line 223
    :goto_5
    if-nez p0, :cond_a

    .line 224
    .line 225
    :try_start_5
    invoke-virtual {p1}, Ljava/io/File;->exists()Z

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    if-eqz p0, :cond_9

    .line 230
    .line 231
    iget-object p0, v1, Lm6/e0;->a:Ljava/io/File;
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 232
    .line 233
    const/4 p2, 0x0

    .line 234
    :try_start_6
    invoke-virtual {p1}, Ljava/io/File;->toPath()Ljava/nio/file/Path;

    .line 235
    .line 236
    .line 237
    move-result-object v3

    .line 238
    invoke-virtual {p0}, Ljava/io/File;->toPath()Ljava/nio/file/Path;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    new-array v4, v5, [Ljava/nio/file/CopyOption;

    .line 243
    .line 244
    sget-object v7, Ljava/nio/file/StandardCopyOption;->REPLACE_EXISTING:Ljava/nio/file/StandardCopyOption;

    .line 245
    .line 246
    aput-object v7, v4, p2

    .line 247
    .line 248
    invoke-static {v3, p0, v4}, Ljava/nio/file/Files;->move(Ljava/nio/file/Path;Ljava/nio/file/Path;[Ljava/nio/file/CopyOption;)Ljava/nio/file/Path;
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 249
    .line 250
    .line 251
    goto :goto_7

    .line 252
    :goto_6
    move-object p2, v2

    .line 253
    goto :goto_c

    .line 254
    :catch_0
    move v5, p2

    .line 255
    :goto_7
    if-eqz v5, :cond_8

    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_8
    :try_start_7
    new-instance p0, Ljava/io/IOException;

    .line 259
    .line 260
    new-instance p2, Ljava/lang/StringBuilder;

    .line 261
    .line 262
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    const-string v0, " to "

    .line 269
    .line 270
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    iget-object v0, v1, Lm6/e0;->a:Ljava/io/File;

    .line 274
    .line 275
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    const-string v0, ". This likely means that there are multiple instances of DataStore for this file. Ensure that you are only creating a single instance of datastore for this file."

    .line 279
    .line 280
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object p2

    .line 287
    invoke-direct {p0, p2}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    throw p0
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_1
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 291
    :catchall_2
    move-exception p0

    .line 292
    goto :goto_6

    .line 293
    :catch_1
    move-exception p0

    .line 294
    move-object v3, p1

    .line 295
    move-object p2, v2

    .line 296
    goto :goto_b

    .line 297
    :cond_9
    :goto_8
    invoke-interface {v2, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 298
    .line 299
    .line 300
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    return-object p0

    .line 303
    :cond_a
    :try_start_8
    throw p0
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_1
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 304
    :catchall_3
    move-exception p0

    .line 305
    move-object v2, p2

    .line 306
    move-object p1, v3

    .line 307
    move-object p2, p0

    .line 308
    move-object p0, v7

    .line 309
    :goto_9
    :try_start_9
    invoke-interface {p0}, Lm6/a;->close()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 310
    .line 311
    .line 312
    goto :goto_a

    .line 313
    :catchall_4
    move-exception p0

    .line 314
    :try_start_a
    invoke-static {p2, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 315
    .line 316
    .line 317
    :goto_a
    throw p2
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_1
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 318
    :catchall_5
    move-exception p0

    .line 319
    goto :goto_c

    .line 320
    :catch_2
    move-exception p0

    .line 321
    :goto_b
    :try_start_b
    invoke-virtual {v3}, Ljava/io/File;->exists()Z

    .line 322
    .line 323
    .line 324
    move-result p1

    .line 325
    if-eqz p1, :cond_b

    .line 326
    .line 327
    invoke-virtual {v3}, Ljava/io/File;->delete()Z

    .line 328
    .line 329
    .line 330
    :cond_b
    throw p0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_5

    .line 331
    :goto_c
    invoke-interface {p2, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    throw p0

    .line 335
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 336
    .line 337
    const-string p1, "StorageConnection has already been disposed."

    .line 338
    .line 339
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    throw p0
.end method

.method public final close()V
    .locals 2

    .line 1
    iget-object v0, p0, Lm6/e0;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lm6/e0;->d:La7/j;

    .line 8
    .line 9
    invoke-virtual {p0}, La7/j;->invoke()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    return-void
.end method
