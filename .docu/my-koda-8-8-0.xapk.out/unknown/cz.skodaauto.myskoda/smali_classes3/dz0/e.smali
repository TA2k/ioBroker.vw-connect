.class public final Ldz0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/j;
.implements Ldz0/f;
.implements Lvy0/k2;


# static fields
.field public static final synthetic i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field public final d:Lpx0/g;

.field public e:Ljava/util/ArrayList;

.field public f:Ljava/lang/Object;

.field public g:I

.field public h:Ljava/lang/Object;

.field private volatile synthetic state$volatile:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-class v0, Ljava/lang/Object;

    .line 2
    .line 3
    const-string v1, "state$volatile"

    .line 4
    .line 5
    const-class v2, Ldz0/e;

    .line 6
    .line 7
    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lpx0/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldz0/e;->d:Lpx0/g;

    .line 5
    .line 6
    sget-object p1, Ldz0/h;->a:Lj51/i;

    .line 7
    .line 8
    iput-object p1, p0, Ldz0/e;->state$volatile:Ljava/lang/Object;

    .line 9
    .line 10
    new-instance p1, Ljava/util/ArrayList;

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 17
    .line 18
    const/4 p1, -0x1

    .line 19
    iput p1, p0, Ldz0/e;->g:I

    .line 20
    .line 21
    sget-object p1, Ldz0/h;->d:Lj51/i;

    .line 22
    .line 23
    iput-object p1, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    :goto_0
    sget-object p1, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Ldz0/h;->b:Lj51/i;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    sget-object v1, Ldz0/h;->c:Lj51/i;

    .line 13
    .line 14
    invoke-virtual {p1, p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_3

    .line 19
    .line 20
    iget-object p1, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 21
    .line 22
    if-nez p1, :cond_1

    .line 23
    .line 24
    :goto_1
    return-void

    .line 25
    :cond_1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Ldz0/c;

    .line 40
    .line 41
    invoke-virtual {v0}, Ldz0/c;->a()V

    .line 42
    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    sget-object p1, Ldz0/h;->d:Lj51/i;

    .line 46
    .line 47
    iput-object p1, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 48
    .line 49
    const/4 p1, 0x0

    .line 50
    iput-object p1, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 51
    .line 52
    return-void

    .line 53
    :cond_3
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    if-eq v1, v0, :cond_0

    .line 58
    .line 59
    goto :goto_0
.end method

.method public final b(Laz0/q;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Ldz0/e;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iput p2, p0, Ldz0/e;->g:I

    .line 4
    .line 5
    return-void
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "null cannot be cast to non-null type kotlinx.coroutines.selects.SelectImplementation.ClauseData<R of kotlinx.coroutines.selects.SelectImplementation>"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast v1, Ldz0/c;

    .line 13
    .line 14
    iget-object v2, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 15
    .line 16
    iget-object v3, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 17
    .line 18
    if-nez v3, :cond_0

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    :cond_1
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    if-eqz v4, :cond_2

    .line 30
    .line 31
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    check-cast v4, Ldz0/c;

    .line 36
    .line 37
    if-eq v4, v1, :cond_1

    .line 38
    .line 39
    invoke-virtual {v4}, Ldz0/c;->a()V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    sget-object v3, Ldz0/h;->b:Lj51/i;

    .line 44
    .line 45
    invoke-virtual {v0, p0, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    sget-object v0, Ldz0/h;->d:Lj51/i;

    .line 49
    .line 50
    iput-object v0, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 51
    .line 52
    const/4 v0, 0x0

    .line 53
    iput-object v0, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 54
    .line 55
    :goto_1
    iget-object p0, v1, Ldz0/c;->c:Lay0/o;

    .line 56
    .line 57
    iget-object v0, v1, Ldz0/c;->a:Ljava/lang/Object;

    .line 58
    .line 59
    iget-object v3, v1, Ldz0/c;->d:Ljava/lang/Object;

    .line 60
    .line 61
    invoke-interface {p0, v0, v3, v2}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    iget-object v0, v1, Ldz0/c;->e:Lrx0/i;

    .line 66
    .line 67
    iget-object v1, v1, Ldz0/c;->d:Ljava/lang/Object;

    .line 68
    .line 69
    sget-object v2, Ldz0/h;->e:Lj51/i;

    .line 70
    .line 71
    if-ne v1, v2, :cond_3

    .line 72
    .line 73
    check-cast v0, Lay0/k;

    .line 74
    .line 75
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    goto :goto_2

    .line 80
    :cond_3
    check-cast v0, Lay0/n;

    .line 81
    .line 82
    invoke-interface {v0, p0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    :goto_2
    return-object p0
.end method

.method public final d(Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Ldz0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ldz0/d;

    .line 7
    .line 8
    iget v1, v0, Ldz0/d;->g:I

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
    iput v1, v0, Ldz0/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ldz0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ldz0/d;-><init>(Ldz0/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ldz0/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ldz0/d;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-object p1

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
    iget-object p0, v0, Ldz0/d;->d:Ldz0/e;

    .line 53
    .line 54
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_5

    .line 58
    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object p0, v0, Ldz0/d;->d:Ldz0/e;

    .line 63
    .line 64
    iput v5, v0, Ldz0/d;->g:I

    .line 65
    .line 66
    new-instance p1, Lvy0/l;

    .line 67
    .line 68
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-direct {p1, v5, v2}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 76
    .line 77
    .line 78
    :cond_4
    :goto_1
    sget-object v2, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 79
    .line 80
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    sget-object v8, Ldz0/h;->a:Lj51/i;

    .line 87
    .line 88
    if-ne v6, v8, :cond_7

    .line 89
    .line 90
    :cond_5
    invoke-virtual {v2, p0, v6, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v8

    .line 94
    if-eqz v8, :cond_6

    .line 95
    .line 96
    invoke-virtual {p1, p0}, Lvy0/l;->u(Lvy0/v1;)V

    .line 97
    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_6
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v8

    .line 104
    if-eq v8, v6, :cond_5

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_7
    instance-of v9, v6, Ljava/util/List;

    .line 108
    .line 109
    if-eqz v9, :cond_a

    .line 110
    .line 111
    :cond_8
    invoke-virtual {v2, p0, v6, v8}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    if-eqz v7, :cond_9

    .line 116
    .line 117
    check-cast v6, Ljava/lang/Iterable;

    .line 118
    .line 119
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 124
    .line 125
    .line 126
    move-result v6

    .line 127
    if-eqz v6, :cond_4

    .line 128
    .line 129
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    invoke-virtual {p0, v6}, Ldz0/e;->e(Ljava/lang/Object;)Ldz0/c;

    .line 134
    .line 135
    .line 136
    move-result-object v6

    .line 137
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    iput-object v3, v6, Ldz0/c;->g:Ljava/lang/Object;

    .line 141
    .line 142
    const/4 v7, -0x1

    .line 143
    iput v7, v6, Ldz0/c;->h:I

    .line 144
    .line 145
    invoke-virtual {p0, v6, v5}, Ldz0/e;->g(Ldz0/c;Z)V

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_9
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    if-eq v7, v6, :cond_8

    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_a
    instance-of v2, v6, Ldz0/c;

    .line 157
    .line 158
    if-eqz v2, :cond_f

    .line 159
    .line 160
    check-cast v6, Ldz0/c;

    .line 161
    .line 162
    iget-object v2, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 163
    .line 164
    iget-object v5, v6, Ldz0/c;->f:Lay0/o;

    .line 165
    .line 166
    if-eqz v5, :cond_b

    .line 167
    .line 168
    iget-object v6, v6, Ldz0/c;->d:Ljava/lang/Object;

    .line 169
    .line 170
    invoke-interface {v5, p0, v6, v2}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v2

    .line 174
    check-cast v2, Lay0/o;

    .line 175
    .line 176
    goto :goto_3

    .line 177
    :cond_b
    move-object v2, v3

    .line 178
    :goto_3
    invoke-virtual {p1, v7, v2}, Lvy0/l;->t(Ljava/lang/Object;Lay0/o;)V

    .line 179
    .line 180
    .line 181
    :goto_4
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 186
    .line 187
    if-ne p1, v2, :cond_c

    .line 188
    .line 189
    move-object v7, p1

    .line 190
    :cond_c
    if-ne v7, v1, :cond_d

    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_d
    :goto_5
    iput-object v3, v0, Ldz0/d;->d:Ldz0/e;

    .line 194
    .line 195
    iput v4, v0, Ldz0/d;->g:I

    .line 196
    .line 197
    invoke-virtual {p0, v0}, Ldz0/e;->c(Lrx0/c;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    if-ne p0, v1, :cond_e

    .line 202
    .line 203
    :goto_6
    return-object v1

    .line 204
    :cond_e
    return-object p0

    .line 205
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 206
    .line 207
    new-instance p1, Ljava/lang/StringBuilder;

    .line 208
    .line 209
    const-string v0, "unexpected state: "

    .line 210
    .line 211
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p1

    .line 221
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object p1

    .line 225
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    throw p0
.end method

.method public final e(Ljava/lang/Object;)Ldz0/c;
    .locals 3

    .line 1
    iget-object p0, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-nez p0, :cond_0

    .line 5
    .line 6
    return-object v0

    .line 7
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    move-object v2, v1

    .line 22
    check-cast v2, Ldz0/c;

    .line 23
    .line 24
    iget-object v2, v2, Ldz0/c;->a:Ljava/lang/Object;

    .line 25
    .line 26
    if-ne v2, p1, :cond_1

    .line 27
    .line 28
    move-object v0, v1

    .line 29
    :cond_2
    check-cast v0, Ldz0/c;

    .line 30
    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    return-object v0

    .line 34
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    new-instance v0, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    const-string v1, "Clause with object "

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string p1, " is not found"

    .line 47
    .line 48
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public final f(Lcom/google/firebase/messaging/w;Lay0/n;)V
    .locals 8

    .line 1
    new-instance v0, Ldz0/c;

    .line 2
    .line 3
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v2, v1

    .line 6
    check-cast v2, Lxy0/j;

    .line 7
    .line 8
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v3, v1

    .line 11
    check-cast v3, Lay0/o;

    .line 12
    .line 13
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v1

    .line 16
    check-cast v4, Lay0/o;

    .line 17
    .line 18
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v7, p1

    .line 21
    check-cast v7, Lay0/o;

    .line 22
    .line 23
    move-object v6, p2

    .line 24
    check-cast v6, Lrx0/i;

    .line 25
    .line 26
    const/4 v5, 0x0

    .line 27
    move-object v1, p0

    .line 28
    invoke-direct/range {v0 .. v7}, Ldz0/c;-><init>(Ldz0/e;Ljava/lang/Object;Lay0/o;Lay0/o;Lj51/i;Lrx0/i;Lay0/o;)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    invoke-virtual {v1, v0, p0}, Ldz0/e;->g(Ldz0/c;Z)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final g(Ldz0/c;Z)V
    .locals 4

    .line 1
    iget-object v0, p1, Ldz0/c;->a:Ljava/lang/Object;

    .line 2
    .line 3
    sget-object v1, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 4
    .line 5
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    instance-of v2, v2, Ldz0/c;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    if-nez p2, :cond_3

    .line 15
    .line 16
    iget-object v2, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_3

    .line 37
    .line 38
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    check-cast v3, Ldz0/c;

    .line 43
    .line 44
    iget-object v3, v3, Ldz0/c;->a:Ljava/lang/Object;

    .line 45
    .line 46
    if-eq v3, v0, :cond_2

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    const-string p0, "Cannot use select clauses on the same object: "

    .line 50
    .line 51
    invoke-static {v0, p0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1

    .line 65
    :cond_3
    :goto_1
    iget-object v2, p1, Ldz0/c;->b:Lay0/o;

    .line 66
    .line 67
    iget-object v3, p1, Ldz0/c;->d:Ljava/lang/Object;

    .line 68
    .line 69
    invoke-interface {v2, v0, p0, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 73
    .line 74
    sget-object v2, Ldz0/h;->d:Lj51/i;

    .line 75
    .line 76
    if-ne v0, v2, :cond_5

    .line 77
    .line 78
    if-nez p2, :cond_4

    .line 79
    .line 80
    iget-object p2, p0, Ldz0/e;->e:Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    invoke-interface {p2, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    :cond_4
    iget-object p2, p0, Ldz0/e;->f:Ljava/lang/Object;

    .line 89
    .line 90
    iput-object p2, p1, Ldz0/c;->g:Ljava/lang/Object;

    .line 91
    .line 92
    iget p2, p0, Ldz0/e;->g:I

    .line 93
    .line 94
    iput p2, p1, Ldz0/c;->h:I

    .line 95
    .line 96
    const/4 p1, 0x0

    .line 97
    iput-object p1, p0, Ldz0/e;->f:Ljava/lang/Object;

    .line 98
    .line 99
    const/4 p1, -0x1

    .line 100
    iput p1, p0, Ldz0/e;->g:I

    .line 101
    .line 102
    return-void

    .line 103
    :cond_5
    invoke-virtual {v1, p0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    return-void
.end method

.method public final h(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 6

    .line 1
    :goto_0
    sget-object v0, Ldz0/e;->i:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    instance-of v2, v1, Lvy0/k;

    .line 8
    .line 9
    const/4 v3, 0x2

    .line 10
    if-eqz v2, :cond_5

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ldz0/e;->e(Ljava/lang/Object;)Ldz0/c;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    if-nez v2, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v4, v2, Ldz0/c;->f:Lay0/o;

    .line 20
    .line 21
    if-eqz v4, :cond_1

    .line 22
    .line 23
    iget-object v5, v2, Ldz0/c;->d:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-interface {v4, p0, v5, p2}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    check-cast v4, Lay0/o;

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/4 v4, 0x0

    .line 33
    :cond_2
    :goto_1
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_4

    .line 38
    .line 39
    check-cast v1, Lvy0/k;

    .line 40
    .line 41
    iput-object p2, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 42
    .line 43
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    invoke-interface {v1, p1, v4}, Lvy0/k;->h(Ljava/lang/Object;Lay0/o;)Lj51/i;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    if-nez p1, :cond_3

    .line 50
    .line 51
    sget-object p1, Ldz0/h;->d:Lj51/i;

    .line 52
    .line 53
    iput-object p1, p0, Ldz0/e;->h:Ljava/lang/Object;

    .line 54
    .line 55
    return v3

    .line 56
    :cond_3
    invoke-interface {v1, p1}, Lvy0/k;->w(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    return p0

    .line 61
    :cond_4
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    if-eq v5, v1, :cond_2

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_5
    sget-object v2, Ldz0/h;->b:Lj51/i;

    .line 69
    .line 70
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    if-nez v2, :cond_e

    .line 75
    .line 76
    instance-of v2, v1, Ldz0/c;

    .line 77
    .line 78
    if-eqz v2, :cond_6

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_6
    sget-object v2, Ldz0/h;->c:Lj51/i;

    .line 82
    .line 83
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_7

    .line 88
    .line 89
    return v3

    .line 90
    :cond_7
    sget-object v2, Ldz0/h;->a:Lj51/i;

    .line 91
    .line 92
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    if-eqz v2, :cond_a

    .line 97
    .line 98
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    :cond_8
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    if-eqz v3, :cond_9

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_9
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    if-eq v3, v1, :cond_8

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_a
    instance-of v2, v1, Ljava/util/List;

    .line 117
    .line 118
    if-eqz v2, :cond_d

    .line 119
    .line 120
    move-object v2, v1

    .line 121
    check-cast v2, Ljava/util/Collection;

    .line 122
    .line 123
    invoke-static {v2, p1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    :cond_b
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    if-eqz v3, :cond_c

    .line 132
    .line 133
    :goto_2
    const/4 p0, 0x1

    .line 134
    return p0

    .line 135
    :cond_c
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    if-eq v3, v1, :cond_b

    .line 140
    .line 141
    goto/16 :goto_0

    .line 142
    .line 143
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 144
    .line 145
    new-instance p1, Ljava/lang/StringBuilder;

    .line 146
    .line 147
    const-string p2, "Unexpected state: "

    .line 148
    .line 149
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw p0

    .line 167
    :cond_e
    :goto_3
    const/4 p0, 0x3

    .line 168
    return p0
.end method
