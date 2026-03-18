.class public final Loj0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Loj0/k;

.field public final b:Loj0/j;


# direct methods
.method public constructor <init>(Loj0/k;Loj0/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Loj0/d;->a:Loj0/k;

    .line 5
    .line 6
    iput-object p2, p0, Loj0/d;->b:Loj0/j;

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
    invoke-virtual {p0, p2}, Loj0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Loj0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Loj0/c;

    .line 7
    .line 8
    iget v1, v0, Loj0/c;->h:I

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
    iput v1, v0, Loj0/c;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Loj0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Loj0/c;-><init>(Loj0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Loj0/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Loj0/c;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Loj0/c;->e:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v0, v0, Loj0/c;->d:Ljava/util/Collection;

    .line 43
    .line 44
    check-cast v0, Ljava/util/Collection;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iput v4, v0, Loj0/c;->h:I

    .line 66
    .line 67
    iget-object p1, p0, Loj0/d;->b:Loj0/j;

    .line 68
    .line 69
    check-cast p1, Lqj0/b;

    .line 70
    .line 71
    sget-object v2, Lge0/b;->c:Lcz0/d;

    .line 72
    .line 73
    new-instance v4, Ln00/f;

    .line 74
    .line 75
    const/16 v6, 0x15

    .line 76
    .line 77
    invoke-direct {v4, p1, v5, v6}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 78
    .line 79
    .line 80
    invoke-static {v2, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    if-ne p1, v1, :cond_4

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    :goto_1
    check-cast p1, Ljava/util/Collection;

    .line 88
    .line 89
    move-object v2, p1

    .line 90
    check-cast v2, Ljava/util/Collection;

    .line 91
    .line 92
    iput-object v2, v0, Loj0/c;->d:Ljava/util/Collection;

    .line 93
    .line 94
    const-string v2, "RecentSystemLog.txt"

    .line 95
    .line 96
    iput-object v2, v0, Loj0/c;->e:Ljava/lang/String;

    .line 97
    .line 98
    iput v3, v0, Loj0/c;->h:I

    .line 99
    .line 100
    iget-object p0, p0, Loj0/d;->a:Loj0/k;

    .line 101
    .line 102
    check-cast p0, Lqj0/a;

    .line 103
    .line 104
    sget-object v3, Lge0/b;->c:Lcz0/d;

    .line 105
    .line 106
    new-instance v4, Lm70/f1;

    .line 107
    .line 108
    const/16 v6, 0xb

    .line 109
    .line 110
    invoke-direct {v4, p0, v5, v6}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {v3, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    if-ne p0, v1, :cond_5

    .line 118
    .line 119
    :goto_2
    return-object v1

    .line 120
    :cond_5
    move-object v0, p1

    .line 121
    move-object p1, p0

    .line 122
    move-object p0, v2

    .line 123
    :goto_3
    check-cast p1, Ljava/lang/String;

    .line 124
    .line 125
    new-instance v1, Lpj0/a;

    .line 126
    .line 127
    invoke-direct {v1, p0, p1}, Lpj0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-static {v0, v1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    new-instance p1, Ljava/io/ByteArrayOutputStream;

    .line 135
    .line 136
    invoke-direct {p1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 137
    .line 138
    .line 139
    new-instance v0, Ljava/util/zip/ZipOutputStream;

    .line 140
    .line 141
    invoke-direct {v0, p1}, Ljava/util/zip/ZipOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 142
    .line 143
    .line 144
    :try_start_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-eqz v1, :cond_6

    .line 153
    .line 154
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    check-cast v1, Lpj0/a;

    .line 159
    .line 160
    new-instance v2, Ljava/util/zip/ZipEntry;

    .line 161
    .line 162
    iget-object v3, v1, Lpj0/a;->a:Ljava/lang/String;

    .line 163
    .line 164
    invoke-direct {v2, v3}, Ljava/util/zip/ZipEntry;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v0, v2}, Ljava/util/zip/ZipOutputStream;->putNextEntry(Ljava/util/zip/ZipEntry;)V

    .line 168
    .line 169
    .line 170
    iget-object v1, v1, Lpj0/a;->b:Ljava/lang/String;

    .line 171
    .line 172
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 173
    .line 174
    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    const-string v2, "getBytes(...)"

    .line 179
    .line 180
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v0, v1}, Ljava/io/OutputStream;->write([B)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v0}, Ljava/util/zip/ZipOutputStream;->closeEntry()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 187
    .line 188
    .line 189
    goto :goto_4

    .line 190
    :catchall_0
    move-exception p0

    .line 191
    goto :goto_5

    .line 192
    :cond_6
    invoke-virtual {v0}, Ljava/util/zip/ZipOutputStream;->close()V

    .line 193
    .line 194
    .line 195
    invoke-virtual {p1}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    const-string p1, "toByteArray(...)"

    .line 200
    .line 201
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    return-object p0

    .line 205
    :goto_5
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 206
    :catchall_1
    move-exception p1

    .line 207
    invoke-static {v0, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 208
    .line 209
    .line 210
    throw p1
.end method
