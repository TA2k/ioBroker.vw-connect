.class public final Lio/ktor/utils/io/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/ktor/utils/io/t;
.implements Lio/ktor/utils/io/d0;


# static fields
.field public static final synthetic f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field volatile synthetic _closedCause:Ljava/lang/Object;

.field public final b:Lnz0/a;

.field public final c:Ljava/lang/Object;

.field public final d:Lnz0/a;

.field public final e:Lnz0/a;

.field private volatile flushBufferSize:I

.field volatile synthetic suspensionSlot:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "suspensionSlot"

    .line 2
    .line 3
    const-class v1, Lio/ktor/utils/io/m;

    .line 4
    .line 5
    const-class v2, Ljava/lang/Object;

    .line 6
    .line 7
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    const-string v0, "_closedCause"

    .line 14
    .line 15
    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lio/ktor/utils/io/m;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lnz0/a;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/ktor/utils/io/m;->b:Lnz0/a;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lio/ktor/utils/io/m;->c:Ljava/lang/Object;

    .line 17
    .line 18
    sget-object v0, Lio/ktor/utils/io/c;->b:Lio/ktor/utils/io/c;

    .line 19
    .line 20
    iput-object v0, p0, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 21
    .line 22
    new-instance v0, Lnz0/a;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 28
    .line 29
    new-instance v0, Lnz0/a;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lio/ktor/utils/io/m;->e:Lnz0/a;

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    iput-object v0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    new-instance v0, Lio/ktor/utils/io/a;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lio/ktor/utils/io/a;-><init>(Ljava/lang/Throwable;)V

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    sget-object v0, Lio/ktor/utils/io/g;->a:Lio/ktor/utils/io/b;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    sget-object v0, Lio/ktor/utils/io/b;->b:Lio/ktor/utils/io/a;

    .line 15
    .line 16
    :goto_0
    sget-object v1, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 17
    .line 18
    invoke-virtual {v1, p0, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->getAndSet(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lio/ktor/utils/io/g;

    .line 23
    .line 24
    instance-of v0, p0, Lio/ktor/utils/io/e;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    check-cast p0, Lio/ktor/utils/io/e;

    .line 29
    .line 30
    invoke-interface {p0, p1}, Lio/ktor/utils/io/e;->a(Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    return-void
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object v0, Lio/ktor/utils/io/c;->b:Lio/ktor/utils/io/c;

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    instance-of v2, p1, Lio/ktor/utils/io/i;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, p1

    .line 10
    check-cast v2, Lio/ktor/utils/io/i;

    .line 11
    .line 12
    iget v3, v2, Lio/ktor/utils/io/i;->h:I

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
    iput v3, v2, Lio/ktor/utils/io/i;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lio/ktor/utils/io/i;

    .line 25
    .line 26
    invoke-direct {v2, p0, p1}, Lio/ktor/utils/io/i;-><init>(Lio/ktor/utils/io/m;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v2, Lio/ktor/utils/io/i;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lio/ktor/utils/io/i;->h:I

    .line 34
    .line 35
    const/high16 v5, 0x100000

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    if-ne v4, v6, :cond_1

    .line 41
    .line 42
    iget v4, v2, Lio/ktor/utils/io/i;->e:I

    .line 43
    .line 44
    iget-object v7, v2, Lio/ktor/utils/io/i;->d:Lio/ktor/utils/io/m;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

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
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->d()Ljava/lang/Throwable;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-nez p1, :cond_11

    .line 66
    .line 67
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->i()V

    .line 68
    .line 69
    .line 70
    iget p1, p0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 71
    .line 72
    if-ge p1, v5, :cond_3

    .line 73
    .line 74
    goto/16 :goto_5

    .line 75
    .line 76
    :cond_3
    const/4 p1, 0x0

    .line 77
    move-object v7, p0

    .line 78
    move v4, p1

    .line 79
    :cond_4
    :goto_1
    iget p1, p0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 80
    .line 81
    if-lt p1, v5, :cond_10

    .line 82
    .line 83
    iget-object p1, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 84
    .line 85
    if-nez p1, :cond_10

    .line 86
    .line 87
    iput-object v7, v2, Lio/ktor/utils/io/i;->d:Lio/ktor/utils/io/m;

    .line 88
    .line 89
    iput v4, v2, Lio/ktor/utils/io/i;->e:I

    .line 90
    .line 91
    iput v6, v2, Lio/ktor/utils/io/i;->h:I

    .line 92
    .line 93
    new-instance p1, Lvy0/l;

    .line 94
    .line 95
    invoke-static {v2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    invoke-direct {p1, v6, v8}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 103
    .line 104
    .line 105
    new-instance v8, Lio/ktor/utils/io/f;

    .line 106
    .line 107
    invoke-direct {v8, p1}, Lio/ktor/utils/io/f;-><init>(Lvy0/l;)V

    .line 108
    .line 109
    .line 110
    iget-object v9, v7, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v9, Lio/ktor/utils/io/g;

    .line 113
    .line 114
    instance-of v10, v9, Lio/ktor/utils/io/a;

    .line 115
    .line 116
    if-nez v10, :cond_7

    .line 117
    .line 118
    sget-object v11, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 119
    .line 120
    :cond_5
    invoke-virtual {v11, v7, v9, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v12

    .line 124
    if-eqz v12, :cond_6

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_6
    invoke-virtual {v11, v7}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v12

    .line 131
    if-eq v12, v9, :cond_5

    .line 132
    .line 133
    invoke-interface {v8}, Lio/ktor/utils/io/e;->b()V

    .line 134
    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_7
    :goto_2
    instance-of v11, v9, Lio/ktor/utils/io/f;

    .line 138
    .line 139
    if-eqz v11, :cond_8

    .line 140
    .line 141
    check-cast v9, Lio/ktor/utils/io/e;

    .line 142
    .line 143
    new-instance v8, Laq/c;

    .line 144
    .line 145
    const-string v10, "write"

    .line 146
    .line 147
    invoke-interface {v9}, Lio/ktor/utils/io/e;->c()Ljava/lang/Throwable;

    .line 148
    .line 149
    .line 150
    move-result-object v11

    .line 151
    invoke-direct {v8, v10, v11}, Laq/c;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 152
    .line 153
    .line 154
    invoke-interface {v9, v8}, Lio/ktor/utils/io/e;->a(Ljava/lang/Throwable;)V

    .line 155
    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_8
    instance-of v11, v9, Lio/ktor/utils/io/e;

    .line 159
    .line 160
    if-eqz v11, :cond_9

    .line 161
    .line 162
    check-cast v9, Lio/ktor/utils/io/e;

    .line 163
    .line 164
    invoke-interface {v9}, Lio/ktor/utils/io/e;->b()V

    .line 165
    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_9
    if-eqz v10, :cond_a

    .line 169
    .line 170
    check-cast v9, Lio/ktor/utils/io/a;

    .line 171
    .line 172
    iget-object v9, v9, Lio/ktor/utils/io/a;->b:Ljava/lang/Throwable;

    .line 173
    .line 174
    invoke-interface {v8, v9}, Lio/ktor/utils/io/e;->a(Ljava/lang/Throwable;)V

    .line 175
    .line 176
    .line 177
    goto :goto_4

    .line 178
    :cond_a
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v8

    .line 182
    if-eqz v8, :cond_f

    .line 183
    .line 184
    :goto_3
    iget v8, p0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 185
    .line 186
    if-lt v8, v5, :cond_b

    .line 187
    .line 188
    iget-object v8, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 189
    .line 190
    if-nez v8, :cond_b

    .line 191
    .line 192
    goto :goto_4

    .line 193
    :cond_b
    iget-object v8, v7, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v8, Lio/ktor/utils/io/g;

    .line 196
    .line 197
    instance-of v9, v8, Lio/ktor/utils/io/f;

    .line 198
    .line 199
    if-eqz v9, :cond_e

    .line 200
    .line 201
    sget-object v9, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 202
    .line 203
    :cond_c
    invoke-virtual {v9, v7, v8, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v10

    .line 207
    if-eqz v10, :cond_d

    .line 208
    .line 209
    check-cast v8, Lio/ktor/utils/io/e;

    .line 210
    .line 211
    invoke-interface {v8}, Lio/ktor/utils/io/e;->b()V

    .line 212
    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_d
    invoke-virtual {v9, v7}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v10

    .line 219
    if-eq v10, v8, :cond_c

    .line 220
    .line 221
    :cond_e
    :goto_4
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object p1

    .line 225
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 226
    .line 227
    if-ne p1, v3, :cond_4

    .line 228
    .line 229
    return-object v3

    .line 230
    :cond_f
    new-instance p0, La8/r0;

    .line 231
    .line 232
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 233
    .line 234
    .line 235
    throw p0

    .line 236
    :cond_10
    :goto_5
    return-object v1

    .line 237
    :cond_11
    throw p1
.end method

.method public final c(Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance v0, Lio/ktor/utils/io/j0;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lio/ktor/utils/io/j0;-><init>(Ljava/lang/Throwable;)V

    .line 9
    .line 10
    .line 11
    sget-object p1, Lio/ktor/utils/io/m;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    :cond_1
    const/4 v1, 0x0

    .line 14
    invoke-virtual {p1, p0, v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_2
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    :goto_0
    sget-object p1, Lio/ktor/utils/io/i0;->d:Lio/ktor/utils/io/i0;

    .line 28
    .line 29
    invoke-virtual {v0, p1}, Lio/ktor/utils/io/j0;->a(Lay0/k;)Ljava/lang/Throwable;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Lio/ktor/utils/io/m;->a(Ljava/lang/Throwable;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public final d()Ljava/lang/Throwable;
    .locals 1

    .line 1
    iget-object p0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lio/ktor/utils/io/j0;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    sget-object v0, Lio/ktor/utils/io/i0;->d:Lio/ktor/utils/io/i0;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/j0;->a(Lay0/k;)Ljava/lang/Throwable;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return-object p0
.end method

.method public final e()Lnz0/a;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lio/ktor/utils/io/j0;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    sget-object v1, Lio/ktor/utils/io/k;->d:Lio/ktor/utils/io/k;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Lio/ktor/utils/io/j0;->a(Lay0/k;)Ljava/lang/Throwable;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    throw v0

    .line 17
    :cond_1
    :goto_0
    iget-object v0, p0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 18
    .line 19
    invoke-virtual {v0}, Lnz0/a;->Z()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->k()V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object p0, p0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 29
    .line 30
    return-object p0
.end method

.method public final f(ILrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    sget-object v2, Lio/ktor/utils/io/c;->b:Lio/ktor/utils/io/c;

    .line 6
    .line 7
    instance-of v3, v1, Lio/ktor/utils/io/h;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lio/ktor/utils/io/h;

    .line 13
    .line 14
    iget v4, v3, Lio/ktor/utils/io/h;->i:I

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
    iput v4, v3, Lio/ktor/utils/io/h;->i:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lio/ktor/utils/io/h;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lio/ktor/utils/io/h;-><init>(Lio/ktor/utils/io/m;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lio/ktor/utils/io/h;->g:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lio/ktor/utils/io/h;->i:I

    .line 36
    .line 37
    const/4 v7, 0x1

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    if-ne v5, v7, :cond_1

    .line 41
    .line 42
    iget v5, v3, Lio/ktor/utils/io/h;->e:I

    .line 43
    .line 44
    iget v8, v3, Lio/ktor/utils/io/h;->d:I

    .line 45
    .line 46
    iget-object v9, v3, Lio/ktor/utils/io/h;->f:Lio/ktor/utils/io/m;

    .line 47
    .line 48
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move v1, v8

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Lio/ktor/utils/io/m;->d()Ljava/lang/Throwable;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    if-nez v1, :cond_13

    .line 69
    .line 70
    iget-object v1, v0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 71
    .line 72
    iget-wide v8, v1, Lnz0/a;->f:J

    .line 73
    .line 74
    move/from16 v1, p1

    .line 75
    .line 76
    int-to-long v10, v1

    .line 77
    cmp-long v5, v8, v10

    .line 78
    .line 79
    if-ltz v5, :cond_3

    .line 80
    .line 81
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 82
    .line 83
    return-object v0

    .line 84
    :cond_3
    move-object v9, v0

    .line 85
    const/4 v5, 0x0

    .line 86
    :cond_4
    :goto_1
    iget v8, v0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 87
    .line 88
    int-to-long v10, v8

    .line 89
    iget-object v8, v0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 90
    .line 91
    iget-wide v12, v8, Lnz0/a;->f:J

    .line 92
    .line 93
    add-long/2addr v10, v12

    .line 94
    int-to-long v12, v1

    .line 95
    cmp-long v8, v10, v12

    .line 96
    .line 97
    if-gez v8, :cond_10

    .line 98
    .line 99
    iget-object v8, v0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 100
    .line 101
    if-nez v8, :cond_10

    .line 102
    .line 103
    iput-object v9, v3, Lio/ktor/utils/io/h;->f:Lio/ktor/utils/io/m;

    .line 104
    .line 105
    iput v1, v3, Lio/ktor/utils/io/h;->d:I

    .line 106
    .line 107
    iput v5, v3, Lio/ktor/utils/io/h;->e:I

    .line 108
    .line 109
    iput v7, v3, Lio/ktor/utils/io/h;->i:I

    .line 110
    .line 111
    new-instance v8, Lvy0/l;

    .line 112
    .line 113
    invoke-static {v3}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 114
    .line 115
    .line 116
    move-result-object v10

    .line 117
    invoke-direct {v8, v7, v10}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v8}, Lvy0/l;->q()V

    .line 121
    .line 122
    .line 123
    new-instance v10, Lio/ktor/utils/io/d;

    .line 124
    .line 125
    invoke-direct {v10, v8}, Lio/ktor/utils/io/d;-><init>(Lvy0/l;)V

    .line 126
    .line 127
    .line 128
    iget-object v11, v9, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v11, Lio/ktor/utils/io/g;

    .line 131
    .line 132
    instance-of v14, v11, Lio/ktor/utils/io/a;

    .line 133
    .line 134
    if-nez v14, :cond_7

    .line 135
    .line 136
    sget-object v15, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 137
    .line 138
    :cond_5
    invoke-virtual {v15, v9, v11, v10}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v16

    .line 142
    if-eqz v16, :cond_6

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_6
    invoke-virtual {v15, v9}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    if-eq v6, v11, :cond_5

    .line 150
    .line 151
    invoke-interface {v10}, Lio/ktor/utils/io/e;->b()V

    .line 152
    .line 153
    .line 154
    goto :goto_4

    .line 155
    :cond_7
    :goto_2
    instance-of v6, v11, Lio/ktor/utils/io/d;

    .line 156
    .line 157
    if-eqz v6, :cond_8

    .line 158
    .line 159
    check-cast v11, Lio/ktor/utils/io/e;

    .line 160
    .line 161
    new-instance v6, Laq/c;

    .line 162
    .line 163
    const-string v10, "read"

    .line 164
    .line 165
    invoke-interface {v11}, Lio/ktor/utils/io/e;->c()Ljava/lang/Throwable;

    .line 166
    .line 167
    .line 168
    move-result-object v14

    .line 169
    invoke-direct {v6, v10, v14}, Laq/c;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 170
    .line 171
    .line 172
    invoke-interface {v11, v6}, Lio/ktor/utils/io/e;->a(Ljava/lang/Throwable;)V

    .line 173
    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_8
    instance-of v6, v11, Lio/ktor/utils/io/e;

    .line 177
    .line 178
    if-eqz v6, :cond_9

    .line 179
    .line 180
    check-cast v11, Lio/ktor/utils/io/e;

    .line 181
    .line 182
    invoke-interface {v11}, Lio/ktor/utils/io/e;->b()V

    .line 183
    .line 184
    .line 185
    goto :goto_3

    .line 186
    :cond_9
    if-eqz v14, :cond_a

    .line 187
    .line 188
    check-cast v11, Lio/ktor/utils/io/a;

    .line 189
    .line 190
    iget-object v6, v11, Lio/ktor/utils/io/a;->b:Ljava/lang/Throwable;

    .line 191
    .line 192
    invoke-interface {v10, v6}, Lio/ktor/utils/io/e;->a(Ljava/lang/Throwable;)V

    .line 193
    .line 194
    .line 195
    goto :goto_4

    .line 196
    :cond_a
    invoke-static {v11, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v6

    .line 200
    if-eqz v6, :cond_f

    .line 201
    .line 202
    :goto_3
    iget v6, v0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 203
    .line 204
    int-to-long v10, v6

    .line 205
    iget-object v6, v0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 206
    .line 207
    iget-wide v14, v6, Lnz0/a;->f:J

    .line 208
    .line 209
    add-long/2addr v10, v14

    .line 210
    cmp-long v6, v10, v12

    .line 211
    .line 212
    if-gez v6, :cond_b

    .line 213
    .line 214
    iget-object v6, v0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 215
    .line 216
    if-nez v6, :cond_b

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_b
    iget-object v6, v9, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v6, Lio/ktor/utils/io/g;

    .line 222
    .line 223
    instance-of v10, v6, Lio/ktor/utils/io/d;

    .line 224
    .line 225
    if-eqz v10, :cond_e

    .line 226
    .line 227
    sget-object v10, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 228
    .line 229
    :cond_c
    invoke-virtual {v10, v9, v6, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v11

    .line 233
    if-eqz v11, :cond_d

    .line 234
    .line 235
    check-cast v6, Lio/ktor/utils/io/e;

    .line 236
    .line 237
    invoke-interface {v6}, Lio/ktor/utils/io/e;->b()V

    .line 238
    .line 239
    .line 240
    goto :goto_4

    .line 241
    :cond_d
    invoke-virtual {v10, v9}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v11

    .line 245
    if-eq v11, v6, :cond_c

    .line 246
    .line 247
    :cond_e
    :goto_4
    invoke-virtual {v8}, Lvy0/l;->p()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v6

    .line 251
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 252
    .line 253
    if-ne v6, v4, :cond_4

    .line 254
    .line 255
    return-object v4

    .line 256
    :cond_f
    new-instance v0, La8/r0;

    .line 257
    .line 258
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 259
    .line 260
    .line 261
    throw v0

    .line 262
    :cond_10
    iget-object v1, v0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 263
    .line 264
    iget-wide v1, v1, Lnz0/a;->f:J

    .line 265
    .line 266
    const-wide/32 v3, 0x100000

    .line 267
    .line 268
    .line 269
    cmp-long v1, v1, v3

    .line 270
    .line 271
    if-gez v1, :cond_11

    .line 272
    .line 273
    invoke-virtual {v0}, Lio/ktor/utils/io/m;->k()V

    .line 274
    .line 275
    .line 276
    :cond_11
    iget-object v0, v0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 277
    .line 278
    iget-wide v0, v0, Lnz0/a;->f:J

    .line 279
    .line 280
    cmp-long v0, v0, v12

    .line 281
    .line 282
    if-ltz v0, :cond_12

    .line 283
    .line 284
    move v6, v7

    .line 285
    goto :goto_5

    .line 286
    :cond_12
    const/4 v6, 0x0

    .line 287
    :goto_5
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    return-object v0

    .line 292
    :cond_13
    throw v1
.end method

.method public final g()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lio/ktor/utils/io/m;->d()Ljava/lang/Throwable;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget v0, p0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 16
    .line 17
    invoke-virtual {p0}, Lnz0/a;->Z()Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0

    .line 26
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 27
    return p0
.end method

.method public final h(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lio/ktor/utils/io/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lio/ktor/utils/io/j;

    .line 7
    .line 8
    iget v1, v0, Lio/ktor/utils/io/j;->f:I

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
    iput v1, v0, Lio/ktor/utils/io/j;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lio/ktor/utils/io/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lio/ktor/utils/io/j;-><init>(Lio/ktor/utils/io/m;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lio/ktor/utils/io/j;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lio/ktor/utils/io/j;->f:I

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
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    .line 38
    .line 39
    goto :goto_2

    .line 40
    :catchall_0
    move-exception p1

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :try_start_1
    iput v3, v0, Lio/ktor/utils/io/j;->f:I

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :goto_1
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 63
    .line 64
    .line 65
    :cond_3
    :goto_2
    sget-object p1, Lio/ktor/utils/io/h0;->b:Lio/ktor/utils/io/j0;

    .line 66
    .line 67
    :cond_4
    sget-object v0, Lio/ktor/utils/io/m;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 68
    .line 69
    const/4 v1, 0x0

    .line 70
    invoke-virtual {v0, p0, v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    if-eqz v2, :cond_5

    .line 77
    .line 78
    invoke-virtual {p0, v1}, Lio/ktor/utils/io/m;->a(Ljava/lang/Throwable;)V

    .line 79
    .line 80
    .line 81
    return-object v3

    .line 82
    :cond_5
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    if-eqz v0, :cond_4

    .line 87
    .line 88
    return-object v3
.end method

.method public final i()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/m;->e:Lnz0/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnz0/a;->Z()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v0, p0, Lio/ktor/utils/io/m;->c:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v0

    .line 13
    :try_start_0
    iget-object v1, p0, Lio/ktor/utils/io/m;->e:Lnz0/a;

    .line 14
    .line 15
    iget-wide v2, v1, Lnz0/a;->f:J

    .line 16
    .line 17
    long-to-int v2, v2

    .line 18
    iget-object v3, p0, Lio/ktor/utils/io/m;->b:Lnz0/a;

    .line 19
    .line 20
    invoke-virtual {v3, v1}, Lnz0/a;->g(Lnz0/d;)J

    .line 21
    .line 22
    .line 23
    iget v1, p0, Lio/ktor/utils/io/m;->flushBufferSize:I

    .line 24
    .line 25
    add-int/2addr v1, v2

    .line 26
    iput v1, p0, Lio/ktor/utils/io/m;->flushBufferSize:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    .line 28
    monitor-exit v0

    .line 29
    iget-object v0, p0, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Lio/ktor/utils/io/g;

    .line 32
    .line 33
    instance-of v1, v0, Lio/ktor/utils/io/d;

    .line 34
    .line 35
    if-eqz v1, :cond_3

    .line 36
    .line 37
    sget-object v1, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 38
    .line 39
    sget-object v2, Lio/ktor/utils/io/c;->b:Lio/ktor/utils/io/c;

    .line 40
    .line 41
    :cond_1
    invoke-virtual {v1, p0, v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_2

    .line 46
    .line 47
    check-cast v0, Lio/ktor/utils/io/e;

    .line 48
    .line 49
    invoke-interface {v0}, Lio/ktor/utils/io/e;->b()V

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :cond_2
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    if-eq v3, v0, :cond_1

    .line 58
    .line 59
    :cond_3
    :goto_0
    return-void

    .line 60
    :catchall_0
    move-exception p0

    .line 61
    monitor-exit v0

    .line 62
    throw p0
.end method

.method public final j()Lnz0/a;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object p0, p0, Lio/ktor/utils/io/m;->_closedCause:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lio/ktor/utils/io/j0;

    .line 8
    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    sget-object v0, Lio/ktor/utils/io/l;->d:Lio/ktor/utils/io/l;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lio/ktor/utils/io/j0;->a(Lay0/k;)Ljava/lang/Throwable;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    throw p0

    .line 21
    :cond_1
    :goto_0
    new-instance p0, Lio/ktor/utils/io/m0;

    .line 22
    .line 23
    const/4 v0, 0x0

    .line 24
    invoke-direct {p0, v0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_2
    iget-object p0, p0, Lio/ktor/utils/io/m;->e:Lnz0/a;

    .line 29
    .line 30
    return-object p0
.end method

.method public final k()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/ktor/utils/io/m;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lio/ktor/utils/io/m;->b:Lnz0/a;

    .line 5
    .line 6
    iget-object v2, p0, Lio/ktor/utils/io/m;->d:Lnz0/a;

    .line 7
    .line 8
    invoke-virtual {v1, v2}, Lnz0/a;->h(Lnz0/a;)J

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    iput v1, p0, Lio/ktor/utils/io/m;->flushBufferSize:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    .line 14
    monitor-exit v0

    .line 15
    iget-object v0, p0, Lio/ktor/utils/io/m;->suspensionSlot:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lio/ktor/utils/io/g;

    .line 18
    .line 19
    instance-of v1, v0, Lio/ktor/utils/io/f;

    .line 20
    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    sget-object v1, Lio/ktor/utils/io/m;->f:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 24
    .line 25
    sget-object v2, Lio/ktor/utils/io/c;->b:Lio/ktor/utils/io/c;

    .line 26
    .line 27
    :cond_0
    invoke-virtual {v1, p0, v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    check-cast v0, Lio/ktor/utils/io/e;

    .line 34
    .line 35
    invoke-interface {v0}, Lio/ktor/utils/io/e;->b()V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    if-eq v3, v0, :cond_0

    .line 44
    .line 45
    :cond_2
    return-void

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    monitor-exit v0

    .line 48
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ByteChannel["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const/16 p0, 0x5d

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method
