.class public final Lm6/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/i0;


# instance fields
.field public final a:Lpx0/g;

.field public final b:Ljava/io/File;

.field public final c:Lyy0/e;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Lez0/c;

.field public final h:Llx0/q;

.field public final i:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Lpx0/g;Ljava/io/File;)V
    .locals 3

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "file"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lm6/p0;->a:Lpx0/g;

    .line 15
    .line 16
    iput-object p2, p0, Lm6/p0;->b:Ljava/io/File;

    .line 17
    .line 18
    sget-object p1, Lm6/r0;->b:Ljava/lang/Object;

    .line 19
    .line 20
    new-instance p1, Lk31/l;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    const/16 v1, 0x13

    .line 24
    .line 25
    invoke-direct {p1, p2, v0, v1}, Lk31/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    new-instance p2, Lyy0/e;

    .line 29
    .line 30
    const/4 v0, -0x2

    .line 31
    sget-object v1, Lxy0/a;->d:Lxy0/a;

    .line 32
    .line 33
    sget-object v2, Lpx0/h;->d:Lpx0/h;

    .line 34
    .line 35
    invoke-direct {p2, p1, v2, v0, v1}, Lyy0/e;-><init>(Lay0/n;Lpx0/g;ILxy0/a;)V

    .line 36
    .line 37
    .line 38
    iput-object p2, p0, Lm6/p0;->c:Lyy0/e;

    .line 39
    .line 40
    const-string p1, ".lock"

    .line 41
    .line 42
    iput-object p1, p0, Lm6/p0;->d:Ljava/lang/String;

    .line 43
    .line 44
    const-string p1, ".version"

    .line 45
    .line 46
    iput-object p1, p0, Lm6/p0;->e:Ljava/lang/String;

    .line 47
    .line 48
    const-string p1, "fcntl failed: EAGAIN"

    .line 49
    .line 50
    iput-object p1, p0, Lm6/p0;->f:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    iput-object p1, p0, Lm6/p0;->g:Lez0/c;

    .line 57
    .line 58
    new-instance p1, Lm6/m0;

    .line 59
    .line 60
    const/4 p2, 0x2

    .line 61
    invoke-direct {p1, p0, p2}, Lm6/m0;-><init>(Lm6/p0;I)V

    .line 62
    .line 63
    .line 64
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    iput-object p1, p0, Lm6/p0;->h:Llx0/q;

    .line 69
    .line 70
    new-instance p1, Lm6/m0;

    .line 71
    .line 72
    const/4 p2, 0x1

    .line 73
    invoke-direct {p1, p0, p2}, Lm6/m0;-><init>(Lm6/p0;I)V

    .line 74
    .line 75
    .line 76
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Lm6/p0;->i:Llx0/q;

    .line 81
    .line 82
    return-void
.end method

.method public static final f(Lm6/p0;Ljava/io/File;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/io/File;->getCanonicalFile()Ljava/io/File;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/io/File;->getParentFile()Ljava/io/File;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/io/File;->mkdirs()Z

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/io/File;->isDirectory()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 22
    .line 23
    new-instance v0, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v1, "Unable to create parent directories of "

    .line 26
    .line 27
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    :goto_0
    invoke-virtual {p1}, Ljava/io/File;->exists()Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-nez p0, :cond_2

    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/io/File;->createNewFile()Z

    .line 48
    .line 49
    .line 50
    :cond_2
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lm6/n0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm6/n0;

    .line 7
    .line 8
    iget v1, v0, Lm6/n0;->i:I

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
    iput v1, v0, Lm6/n0;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/n0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lm6/n0;-><init>(Lm6/p0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm6/n0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/n0;->i:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eqz v2, :cond_4

    .line 36
    .line 37
    if-eq v2, v5, :cond_3

    .line 38
    .line 39
    if-eq v2, v4, :cond_2

    .line 40
    .line 41
    if-ne v2, v3, :cond_1

    .line 42
    .line 43
    iget-object p0, v0, Lm6/n0;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Ljava/nio/channels/FileLock;

    .line 46
    .line 47
    iget-object p1, v0, Lm6/n0;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p1, Ljava/io/Closeable;

    .line 50
    .line 51
    iget-object v0, v0, Lm6/n0;->d:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Lez0/a;

    .line 54
    .line 55
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 56
    .line 57
    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :catchall_0
    move-exception p2

    .line 61
    goto/16 :goto_7

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
    iget-object p0, v0, Lm6/n0;->f:Ljava/lang/Object;

    .line 72
    .line 73
    move-object p1, p0

    .line 74
    check-cast p1, Ljava/io/Closeable;

    .line 75
    .line 76
    iget-object p0, v0, Lm6/n0;->e:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Lez0/a;

    .line 79
    .line 80
    iget-object v2, v0, Lm6/n0;->d:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v2, Lay0/k;

    .line 83
    .line 84
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 85
    .line 86
    .line 87
    goto :goto_3

    .line 88
    :catchall_1
    move-exception p2

    .line 89
    move-object v0, p0

    .line 90
    :goto_1
    move-object p0, v6

    .line 91
    goto/16 :goto_7

    .line 92
    .line 93
    :cond_3
    iget-object p0, v0, Lm6/n0;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Lez0/a;

    .line 96
    .line 97
    iget-object p1, v0, Lm6/n0;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p1, Lay0/k;

    .line 100
    .line 101
    iget-object v2, v0, Lm6/n0;->d:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v2, Lm6/p0;

    .line 104
    .line 105
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    move-object p2, p0

    .line 109
    move-object p0, v2

    .line 110
    goto :goto_2

    .line 111
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    iput-object p0, v0, Lm6/n0;->d:Ljava/lang/Object;

    .line 115
    .line 116
    iput-object p1, v0, Lm6/n0;->e:Ljava/lang/Object;

    .line 117
    .line 118
    iget-object p2, p0, Lm6/p0;->g:Lez0/c;

    .line 119
    .line 120
    iput-object p2, v0, Lm6/n0;->f:Ljava/lang/Object;

    .line 121
    .line 122
    iput v5, v0, Lm6/n0;->i:I

    .line 123
    .line 124
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    if-ne v2, v1, :cond_5

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_5
    :goto_2
    :try_start_2
    new-instance v2, Ljava/io/FileOutputStream;

    .line 132
    .line 133
    iget-object p0, p0, Lm6/p0;->h:Llx0/q;

    .line 134
    .line 135
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p0, Ljava/io/File;

    .line 140
    .line 141
    invoke-direct {v2, p0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_7

    .line 142
    .line 143
    .line 144
    :try_start_3
    iput-object p1, v0, Lm6/n0;->d:Ljava/lang/Object;

    .line 145
    .line 146
    iput-object p2, v0, Lm6/n0;->e:Ljava/lang/Object;

    .line 147
    .line 148
    iput-object v2, v0, Lm6/n0;->f:Ljava/lang/Object;

    .line 149
    .line 150
    iput v4, v0, Lm6/n0;->i:I

    .line 151
    .line 152
    invoke-static {v2, v0}, Lm6/c1;->a(Ljava/io/FileOutputStream;Lrx0/c;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_5

    .line 156
    if-ne p0, v1, :cond_6

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_6
    move-object v7, p2

    .line 160
    move-object p2, p0

    .line 161
    move-object p0, v7

    .line 162
    move-object v7, v2

    .line 163
    move-object v2, p1

    .line 164
    move-object p1, v7

    .line 165
    :goto_3
    :try_start_4
    check-cast p2, Ljava/nio/channels/FileLock;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 166
    .line 167
    :try_start_5
    iput-object p0, v0, Lm6/n0;->d:Ljava/lang/Object;

    .line 168
    .line 169
    iput-object p1, v0, Lm6/n0;->e:Ljava/lang/Object;

    .line 170
    .line 171
    iput-object p2, v0, Lm6/n0;->f:Ljava/lang/Object;

    .line 172
    .line 173
    iput v3, v0, Lm6/n0;->i:I

    .line 174
    .line 175
    invoke-interface {v2, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 179
    if-ne v0, v1, :cond_7

    .line 180
    .line 181
    :goto_4
    return-object v1

    .line 182
    :cond_7
    move-object v7, v0

    .line 183
    move-object v0, p0

    .line 184
    move-object p0, p2

    .line 185
    move-object p2, v7

    .line 186
    :goto_5
    if-eqz p0, :cond_8

    .line 187
    .line 188
    :try_start_6
    invoke-virtual {p0}, Ljava/nio/channels/FileLock;->release()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 189
    .line 190
    .line 191
    goto :goto_6

    .line 192
    :catchall_2
    move-exception p0

    .line 193
    move-object p2, v0

    .line 194
    goto :goto_8

    .line 195
    :cond_8
    :goto_6
    :try_start_7
    invoke-static {p1, v6}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 196
    .line 197
    .line 198
    invoke-interface {v0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    return-object p2

    .line 202
    :catchall_3
    move-exception p0

    .line 203
    move-object p2, v0

    .line 204
    goto :goto_9

    .line 205
    :catchall_4
    move-exception v0

    .line 206
    move-object v7, v0

    .line 207
    move-object v0, p0

    .line 208
    move-object p0, p2

    .line 209
    move-object p2, v7

    .line 210
    goto :goto_7

    .line 211
    :catchall_5
    move-exception p0

    .line 212
    move-object v0, p2

    .line 213
    move-object p1, v2

    .line 214
    move-object p2, p0

    .line 215
    goto :goto_1

    .line 216
    :goto_7
    if-eqz p0, :cond_9

    .line 217
    .line 218
    :try_start_8
    invoke-virtual {p0}, Ljava/nio/channels/FileLock;->release()V

    .line 219
    .line 220
    .line 221
    :cond_9
    throw p2
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 222
    :goto_8
    :try_start_9
    throw p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_6

    .line 223
    :catchall_6
    move-exception v0

    .line 224
    :try_start_a
    invoke-static {p1, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 225
    .line 226
    .line 227
    throw v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_7

    .line 228
    :catchall_7
    move-exception p0

    .line 229
    :goto_9
    invoke-interface {p2, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    throw p0
.end method

.method public final b()Lyy0/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lm6/p0;->c:Lyy0/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lm6/p0;->i:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->isInitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lm6/v0;

    .line 14
    .line 15
    sget-object p1, Lm6/v0;->b:Landroidx/datastore/core/NativeSharedCounter;

    .line 16
    .line 17
    iget-wide v0, p0, Lm6/v0;->a:J

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1}, Landroidx/datastore/core/NativeSharedCounter;->nativeGetCounterValue(J)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    new-instance p1, Ljava/lang/Integer;

    .line 24
    .line 25
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 26
    .line 27
    .line 28
    return-object p1

    .line 29
    :cond_0
    new-instance v0, Lm6/l0;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x0

    .line 33
    invoke-direct {v0, p0, v1, v2}, Lm6/l0;-><init>(Lm6/p0;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lm6/p0;->a:Lpx0/g;

    .line 37
    .line 38
    invoke-static {p0, v0, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public final d(Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    instance-of v3, v0, Lm6/o0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v0

    .line 12
    check-cast v3, Lm6/o0;

    .line 13
    .line 14
    iget v4, v3, Lm6/o0;->j:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lm6/o0;->j:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lm6/o0;

    .line 27
    .line 28
    invoke-direct {v3, v1, v0}, Lm6/o0;-><init>(Lm6/p0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v0, v3, Lm6/o0;->h:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lm6/o0;->j:I

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x1

    .line 39
    const/4 v8, 0x0

    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    if-eq v5, v7, :cond_2

    .line 43
    .line 44
    if-ne v5, v6, :cond_1

    .line 45
    .line 46
    iget-boolean v1, v3, Lm6/o0;->g:Z

    .line 47
    .line 48
    iget-object v2, v3, Lm6/o0;->f:Ljava/nio/channels/FileLock;

    .line 49
    .line 50
    iget-object v4, v3, Lm6/o0;->e:Ljava/io/FileInputStream;

    .line 51
    .line 52
    iget-object v3, v3, Lm6/o0;->d:Lez0/c;

    .line 53
    .line 54
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    .line 57
    goto/16 :goto_7

    .line 58
    .line 59
    :catchall_0
    move-exception v0

    .line 60
    goto/16 :goto_a

    .line 61
    .line 62
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw v0

    .line 70
    :cond_2
    iget-boolean v1, v3, Lm6/o0;->g:Z

    .line 71
    .line 72
    iget-object v2, v3, Lm6/o0;->d:Lez0/c;

    .line 73
    .line 74
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :catchall_1
    move-exception v0

    .line 79
    goto/16 :goto_c

    .line 80
    .line 81
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object v5, v1, Lm6/p0;->g:Lez0/c;

    .line 85
    .line 86
    invoke-virtual {v5}, Lez0/c;->tryLock()Z

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    if-nez v9, :cond_6

    .line 91
    .line 92
    :try_start_2
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 93
    .line 94
    iput-object v5, v3, Lm6/o0;->d:Lez0/c;

    .line 95
    .line 96
    iput-boolean v9, v3, Lm6/o0;->g:Z

    .line 97
    .line 98
    iput v7, v3, Lm6/o0;->j:I

    .line 99
    .line 100
    invoke-interface {v2, v0, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 104
    if-ne v0, v4, :cond_4

    .line 105
    .line 106
    goto/16 :goto_6

    .line 107
    .line 108
    :cond_4
    move-object v2, v5

    .line 109
    move v1, v9

    .line 110
    :goto_1
    if-eqz v1, :cond_5

    .line 111
    .line 112
    invoke-interface {v2, v8}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    :cond_5
    return-object v0

    .line 116
    :catchall_2
    move-exception v0

    .line 117
    move-object v2, v5

    .line 118
    move v1, v9

    .line 119
    goto/16 :goto_c

    .line 120
    .line 121
    :cond_6
    :try_start_3
    new-instance v10, Ljava/io/FileInputStream;

    .line 122
    .line 123
    iget-object v0, v1, Lm6/p0;->h:Llx0/q;

    .line 124
    .line 125
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    check-cast v0, Ljava/io/File;

    .line 130
    .line 131
    invoke-direct {v10, v0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 132
    .line 133
    .line 134
    const/4 v11, 0x0

    .line 135
    :try_start_4
    invoke-virtual {v10}, Ljava/io/FileInputStream;->getChannel()Ljava/nio/channels/FileChannel;

    .line 136
    .line 137
    .line 138
    move-result-object v12

    .line 139
    const-wide v15, 0x7fffffffffffffffL

    .line 140
    .line 141
    .line 142
    .line 143
    .line 144
    const/16 v17, 0x1

    .line 145
    .line 146
    const-wide/16 v13, 0x0

    .line 147
    .line 148
    invoke-virtual/range {v12 .. v17}, Ljava/nio/channels/FileChannel;->tryLock(JJZ)Ljava/nio/channels/FileLock;

    .line 149
    .line 150
    .line 151
    move-result-object v0
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 152
    move-object v1, v0

    .line 153
    goto :goto_4

    .line 154
    :catchall_3
    move-exception v0

    .line 155
    move-object v3, v5

    .line 156
    move-object v2, v8

    .line 157
    :goto_2
    move v1, v9

    .line 158
    move-object v4, v10

    .line 159
    goto/16 :goto_a

    .line 160
    .line 161
    :catch_0
    move-exception v0

    .line 162
    :try_start_5
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v12

    .line 166
    if-eqz v12, :cond_7

    .line 167
    .line 168
    iget-object v1, v1, Lm6/p0;->f:Ljava/lang/String;

    .line 169
    .line 170
    invoke-static {v12, v1, v11}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-ne v1, v7, :cond_7

    .line 175
    .line 176
    goto :goto_3

    .line 177
    :cond_7
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    if-eqz v1, :cond_c

    .line 182
    .line 183
    const-string v12, "Resource deadlock would occur"

    .line 184
    .line 185
    invoke-static {v1, v12, v11}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 186
    .line 187
    .line 188
    move-result v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 189
    if-ne v1, v7, :cond_c

    .line 190
    .line 191
    :goto_3
    move-object v1, v8

    .line 192
    :goto_4
    if-eqz v1, :cond_8

    .line 193
    .line 194
    goto :goto_5

    .line 195
    :cond_8
    move v7, v11

    .line 196
    :goto_5
    :try_start_6
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    iput-object v5, v3, Lm6/o0;->d:Lez0/c;

    .line 201
    .line 202
    iput-object v10, v3, Lm6/o0;->e:Ljava/io/FileInputStream;

    .line 203
    .line 204
    iput-object v1, v3, Lm6/o0;->f:Ljava/nio/channels/FileLock;

    .line 205
    .line 206
    iput-boolean v9, v3, Lm6/o0;->g:Z

    .line 207
    .line 208
    iput v6, v3, Lm6/o0;->j:I

    .line 209
    .line 210
    invoke-interface {v2, v0, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 214
    if-ne v0, v4, :cond_9

    .line 215
    .line 216
    :goto_6
    return-object v4

    .line 217
    :cond_9
    move-object v2, v1

    .line 218
    move-object v3, v5

    .line 219
    move v1, v9

    .line 220
    move-object v4, v10

    .line 221
    :goto_7
    if-eqz v2, :cond_a

    .line 222
    .line 223
    :try_start_7
    invoke-virtual {v2}, Ljava/nio/channels/FileLock;->release()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 224
    .line 225
    .line 226
    goto :goto_8

    .line 227
    :catchall_4
    move-exception v0

    .line 228
    move v2, v1

    .line 229
    move-object v1, v0

    .line 230
    goto :goto_b

    .line 231
    :cond_a
    :goto_8
    :try_start_8
    invoke-static {v4, v8}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 232
    .line 233
    .line 234
    if-eqz v1, :cond_b

    .line 235
    .line 236
    invoke-interface {v3, v8}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    :cond_b
    return-object v0

    .line 240
    :catchall_5
    move-exception v0

    .line 241
    :goto_9
    move-object v2, v3

    .line 242
    goto :goto_c

    .line 243
    :catchall_6
    move-exception v0

    .line 244
    move-object v2, v1

    .line 245
    move-object v3, v5

    .line 246
    goto :goto_2

    .line 247
    :cond_c
    :try_start_9
    throw v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 248
    :goto_a
    if-eqz v2, :cond_d

    .line 249
    .line 250
    :try_start_a
    invoke-virtual {v2}, Ljava/nio/channels/FileLock;->release()V

    .line 251
    .line 252
    .line 253
    :cond_d
    throw v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    .line 254
    :goto_b
    :try_start_b
    throw v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    .line 255
    :catchall_7
    move-exception v0

    .line 256
    :try_start_c
    invoke-static {v4, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 257
    .line 258
    .line 259
    throw v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_8

    .line 260
    :catchall_8
    move-exception v0

    .line 261
    move v1, v2

    .line 262
    goto :goto_9

    .line 263
    :goto_c
    if-eqz v1, :cond_e

    .line 264
    .line 265
    invoke-interface {v2, v8}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    :cond_e
    throw v0
.end method

.method public final e(Lm6/v;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lm6/p0;->i:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->isInitialized()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lm6/v0;

    .line 14
    .line 15
    sget-object p1, Lm6/v0;->b:Landroidx/datastore/core/NativeSharedCounter;

    .line 16
    .line 17
    iget-wide v0, p0, Lm6/v0;->a:J

    .line 18
    .line 19
    invoke-virtual {p1, v0, v1}, Landroidx/datastore/core/NativeSharedCounter;->nativeIncrementAndGetCounterValue(J)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    new-instance p1, Ljava/lang/Integer;

    .line 24
    .line 25
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 26
    .line 27
    .line 28
    return-object p1

    .line 29
    :cond_0
    new-instance v0, Lm6/l0;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x1

    .line 33
    invoke-direct {v0, p0, v1, v2}, Lm6/l0;-><init>(Lm6/p0;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lm6/p0;->a:Lpx0/g;

    .line 37
    .line 38
    invoke-static {p0, v0, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
