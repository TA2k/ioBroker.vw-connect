.class public final Lcf0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lhq0/d;

.field public final b:Loj0/k;


# direct methods
.method public constructor <init>(Lhq0/d;Loj0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcf0/d;->a:Lhq0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lcf0/d;->b:Loj0/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lcf0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lcf0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcf0/c;

    .line 7
    .line 8
    iget v1, v0, Lcf0/c;->f:I

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
    iput v1, v0, Lcf0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcf0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcf0/c;-><init>(Lcf0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcf0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcf0/c;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto/16 :goto_5

    .line 42
    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lcf0/d;->b:Loj0/k;

    .line 55
    .line 56
    check-cast p1, Lqj0/a;

    .line 57
    .line 58
    new-instance v2, Ljava/io/File;

    .line 59
    .line 60
    iget-object p1, p1, Lqj0/a;->a:Landroid/content/Context;

    .line 61
    .line 62
    invoke-virtual {p1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    const-string v6, "rpa_logs"

    .line 67
    .line 68
    invoke-direct {v2, v5, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    new-instance v5, Ljava/io/File;

    .line 72
    .line 73
    invoke-virtual {p1}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    const-string v6, "/export/"

    .line 78
    .line 79
    invoke-direct {v5, p1, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v5}, Ljava/io/File;->mkdir()Z

    .line 83
    .line 84
    .line 85
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    const-string v6, "dd.MM.yyyy"

    .line 90
    .line 91
    invoke-static {v6}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    invoke-virtual {p1, v6}, Ljava/time/LocalDate;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    const-string v6, "RpaLogs_"

    .line 100
    .line 101
    const-string v7, ".zip"

    .line 102
    .line 103
    invoke-static {v6, p1, v7}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    new-instance v6, Ljava/io/File;

    .line 108
    .line 109
    invoke-direct {v6, v5, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    new-instance p1, Ljava/util/zip/ZipOutputStream;

    .line 113
    .line 114
    new-instance v5, Ljava/io/BufferedOutputStream;

    .line 115
    .line 116
    new-instance v7, Ljava/io/FileOutputStream;

    .line 117
    .line 118
    invoke-direct {v7, v6}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 119
    .line 120
    .line 121
    invoke-direct {v5, v7}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 122
    .line 123
    .line 124
    sget-object v7, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 125
    .line 126
    invoke-direct {p1, v5, v7}, Ljava/util/zip/ZipOutputStream;-><init>(Ljava/io/OutputStream;Ljava/nio/charset/Charset;)V

    .line 127
    .line 128
    .line 129
    :try_start_0
    invoke-virtual {v2}, Ljava/io/File;->listFiles()[Ljava/io/File;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    if-eqz v2, :cond_4

    .line 134
    .line 135
    array-length v5, v2

    .line 136
    const/4 v7, 0x0

    .line 137
    :goto_1
    if-ge v7, v5, :cond_4

    .line 138
    .line 139
    aget-object v8, v2, v7

    .line 140
    .line 141
    invoke-virtual {v8}, Ljava/io/File;->isDirectory()Z

    .line 142
    .line 143
    .line 144
    move-result v9

    .line 145
    if-nez v9, :cond_3

    .line 146
    .line 147
    new-instance v9, Ljava/io/FileInputStream;

    .line 148
    .line 149
    invoke-direct {v9, v8}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 150
    .line 151
    .line 152
    :try_start_1
    new-instance v10, Ljava/io/BufferedInputStream;

    .line 153
    .line 154
    invoke-direct {v10, v9}, Ljava/io/BufferedInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 155
    .line 156
    .line 157
    :try_start_2
    new-instance v11, Ljava/util/zip/ZipEntry;

    .line 158
    .line 159
    invoke-virtual {v8}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v8

    .line 163
    invoke-direct {v11, v8}, Ljava/util/zip/ZipEntry;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p1, v11}, Ljava/util/zip/ZipOutputStream;->putNextEntry(Ljava/util/zip/ZipEntry;)V

    .line 167
    .line 168
    .line 169
    invoke-static {v10, p1}, Llp/ud;->b(Ljava/io/InputStream;Ljava/io/OutputStream;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 170
    .line 171
    .line 172
    :try_start_3
    invoke-virtual {v10}, Ljava/io/BufferedInputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 173
    .line 174
    .line 175
    :try_start_4
    invoke-virtual {v9}, Ljava/io/FileInputStream;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 176
    .line 177
    .line 178
    goto :goto_3

    .line 179
    :catchall_0
    move-exception p0

    .line 180
    goto :goto_6

    .line 181
    :catchall_1
    move-exception p0

    .line 182
    goto :goto_2

    .line 183
    :catchall_2
    move-exception p0

    .line 184
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 185
    :catchall_3
    move-exception v0

    .line 186
    :try_start_6
    invoke-static {v10, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 187
    .line 188
    .line 189
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 190
    :goto_2
    :try_start_7
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 191
    :catchall_4
    move-exception v0

    .line 192
    :try_start_8
    invoke-static {v9, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 193
    .line 194
    .line 195
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 196
    :cond_3
    :goto_3
    add-int/lit8 v7, v7, 0x1

    .line 197
    .line 198
    goto :goto_1

    .line 199
    :cond_4
    invoke-virtual {p1}, Ljava/util/zip/ZipOutputStream;->close()V

    .line 200
    .line 201
    .line 202
    iput v4, v0, Lcf0/c;->f:I

    .line 203
    .line 204
    iget-object p0, p0, Lcf0/d;->a:Lhq0/d;

    .line 205
    .line 206
    check-cast p0, Lfq0/a;

    .line 207
    .line 208
    iget-object p0, p0, Lfq0/a;->a:Lyy0/q1;

    .line 209
    .line 210
    invoke-virtual {p0, v6, v0}, Lyy0/q1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 215
    .line 216
    if-ne p0, p1, :cond_5

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_5
    move-object p0, v3

    .line 220
    :goto_4
    if-ne p0, v1, :cond_6

    .line 221
    .line 222
    return-object v1

    .line 223
    :cond_6
    :goto_5
    return-object v3

    .line 224
    :goto_6
    :try_start_9
    throw p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_5

    .line 225
    :catchall_5
    move-exception v0

    .line 226
    invoke-static {p1, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 227
    .line 228
    .line 229
    throw v0
.end method
