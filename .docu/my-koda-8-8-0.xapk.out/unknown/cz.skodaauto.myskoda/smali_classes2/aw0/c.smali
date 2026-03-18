.class public Law0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# static fields
.field public static final synthetic g:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

.field public static final h:Lvw0/a;


# instance fields
.field public final d:Lzv0/c;

.field public e:Lkw0/b;

.field public f:Law0/h;

.field private volatile synthetic received:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    const-class v1, Ljava/lang/Object;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :try_start_0
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 10
    .line 11
    .line 12
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    const/4 v1, 0x0

    .line 15
    :goto_0
    new-instance v2, Lzw0/a;

    .line 16
    .line 17
    invoke-direct {v2, v0, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lvw0/a;

    .line 21
    .line 22
    const-string v1, "CustomResponse"

    .line 23
    .line 24
    invoke-direct {v0, v1, v2}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Law0/c;->h:Lvw0/a;

    .line 28
    .line 29
    const-class v0, Law0/c;

    .line 30
    .line 31
    const-string v1, "received"

    .line 32
    .line 33
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Law0/c;->g:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 38
    .line 39
    return-void
.end method

.method public constructor <init>(Lzv0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Law0/c;->d:Lzv0/c;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Law0/c;->received:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Law0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Law0/b;

    .line 7
    .line 8
    iget v1, v0, Law0/b;->g:I

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
    iput v1, v0, Law0/b;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Law0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Law0/b;-><init>(Law0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Law0/b;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Law0/b;->g:I

    .line 30
    .line 31
    const-string v3, "type"

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    iget-object p1, v0, Law0/b;->d:Lzw0/a;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto/16 :goto_4

    .line 47
    .line 48
    :catchall_0
    move-exception p1

    .line 49
    goto/16 :goto_7

    .line 50
    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    iget-object p1, v0, Law0/b;->d:Lzw0/a;

    .line 60
    .line 61
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    :try_start_2
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    iget-object v2, p1, Lzw0/a;->a:Lhy0/d;

    .line 73
    .line 74
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-static {v2}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-virtual {v2, p2}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    if-eqz p2, :cond_4

    .line 86
    .line 87
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    :cond_4
    invoke-virtual {p0}, Law0/c;->b()Z

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    if-nez p2, :cond_6

    .line 97
    .line 98
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    invoke-static {p2}, Lfw0/k;->b(Law0/h;)Z

    .line 103
    .line 104
    .line 105
    move-result p2

    .line 106
    if-nez p2, :cond_6

    .line 107
    .line 108
    sget-object p2, Law0/c;->g:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 109
    .line 110
    const/4 v2, 0x0

    .line 111
    invoke-virtual {p2, p0, v2, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    if-eqz p2, :cond_5

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_5
    new-instance p1, Law0/a;

    .line 119
    .line 120
    invoke-direct {p1, p0}, Law0/a;-><init>(Law0/c;)V

    .line 121
    .line 122
    .line 123
    throw p1

    .line 124
    :cond_6
    :goto_1
    invoke-virtual {p0}, Law0/c;->getAttributes()Lvw0/d;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    sget-object v2, Law0/c;->h:Lvw0/a;

    .line 129
    .line 130
    invoke-virtual {p2, v2}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p2

    .line 134
    if-nez p2, :cond_7

    .line 135
    .line 136
    iput-object p1, v0, Law0/b;->d:Lzw0/a;

    .line 137
    .line 138
    iput v5, v0, Law0/b;->g:I

    .line 139
    .line 140
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 141
    .line 142
    .line 143
    move-result-object p2

    .line 144
    invoke-virtual {p2}, Law0/h;->b()Lio/ktor/utils/io/t;

    .line 145
    .line 146
    .line 147
    move-result-object p2

    .line 148
    if-ne p2, v1, :cond_7

    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_7
    :goto_2
    new-instance v2, Llw0/b;

    .line 152
    .line 153
    invoke-direct {v2, p1, p2}, Llw0/b;-><init>(Lzw0/a;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    iget-object p2, p0, Law0/c;->d:Lzv0/c;

    .line 157
    .line 158
    iget-object p2, p2, Lzv0/c;->j:Llw0/a;

    .line 159
    .line 160
    iput-object p1, v0, Law0/b;->d:Lzw0/a;

    .line 161
    .line 162
    iput v4, v0, Law0/b;->g:I

    .line 163
    .line 164
    invoke-virtual {p2, p0, v2, v0}, Lyw0/d;->a(Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p2

    .line 168
    if-ne p2, v1, :cond_8

    .line 169
    .line 170
    :goto_3
    return-object v1

    .line 171
    :cond_8
    :goto_4
    check-cast p2, Llw0/b;

    .line 172
    .line 173
    iget-object p2, p2, Llw0/b;->b:Ljava/lang/Object;

    .line 174
    .line 175
    sget-object v0, Lrw0/b;->a:Lrw0/b;

    .line 176
    .line 177
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    if-nez v0, :cond_9

    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_9
    const/4 p2, 0x0

    .line 185
    :goto_5
    if-eqz p2, :cond_b

    .line 186
    .line 187
    iget-object v0, p1, Lzw0/a;->a:Lhy0/d;

    .line 188
    .line 189
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    invoke-static {v0}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    invoke-virtual {v0, p2}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    if-eqz v0, :cond_a

    .line 201
    .line 202
    goto :goto_6

    .line 203
    :cond_a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 204
    .line 205
    .line 206
    move-result-object p2

    .line 207
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 208
    .line 209
    invoke-virtual {v0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 210
    .line 211
    .line 212
    move-result-object p2

    .line 213
    iget-object p1, p1, Lzw0/a;->a:Lhy0/d;

    .line 214
    .line 215
    new-instance v0, Law0/d;

    .line 216
    .line 217
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    invoke-direct {v0, v1, p2, p1}, Law0/d;-><init>(Law0/h;Lhy0/d;Lhy0/d;)V

    .line 222
    .line 223
    .line 224
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 225
    :cond_b
    :goto_6
    return-object p2

    .line 226
    :goto_7
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    const-string p2, "Receive failed"

    .line 231
    .line 232
    invoke-static {p2, p1}, Lvy0/e0;->a(Ljava/lang/String;Ljava/lang/Throwable;)Ljava/util/concurrent/CancellationException;

    .line 233
    .line 234
    .line 235
    move-result-object p2

    .line 236
    invoke-static {p0, p2}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 237
    .line 238
    .line 239
    throw p1
.end method

.method public b()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final c()Lkw0/b;
    .locals 0

    .line 1
    iget-object p0, p0, Law0/c;->e:Lkw0/b;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "request"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final d()Law0/h;
    .locals 0

    .line 1
    iget-object p0, p0, Law0/c;->f:Law0/h;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "response"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final getAttributes()Lvw0/d;
    .locals 0

    .line 1
    invoke-virtual {p0}, Law0/c;->c()Lkw0/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lkw0/b;->getAttributes()Lvw0/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "HttpClientCall["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Law0/c;->c()Lkw0/b;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Lkw0/b;->getUrl()Low0/f0;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v1, ", "

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Law0/c;->d()Law0/h;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0}, Law0/h;->c()Low0/v;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const/16 p0, 0x5d

    .line 36
    .line 37
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
