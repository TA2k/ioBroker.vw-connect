.class public final Lac0/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcc0/a;
.implements Lvy0/b0;


# static fields
.field public static final u:Lcm0/b;


# instance fields
.field public final d:Lac0/y;

.field public final e:Lac0/x;

.field public final f:Lac0/z;

.field public final g:Lzr0/a;

.field public final h:Lrh0/f;

.field public i:Lcm0/b;

.field public final j:Lpx0/g;

.field public final k:Ljava/util/concurrent/atomic/AtomicReference;

.field public final l:Ljava/util/concurrent/ConcurrentHashMap;

.field public m:Lorg/eclipse/paho/mqttv5/client/MqttClient;

.field public final n:Llx0/q;

.field public final o:Ljava/lang/Object;

.field public p:Z

.field public final q:Lyy0/q1;

.field public final r:Lac0/q;

.field public final s:Ljava/util/concurrent/ConcurrentHashMap;

.field public final t:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcm0/b;->d:Lcm0/b;

    .line 2
    .line 3
    sput-object v0, Lac0/w;->u:Lcm0/b;

    .line 4
    .line 5
    return-void
.end method

.method public constructor <init>(Lac0/y;Lac0/x;Lac0/z;Lzr0/a;Lrh0/f;)V
    .locals 6

    .line 1
    const/4 v0, 0x3

    .line 2
    const-string v1, "MQTT Coroutine dispatcher"

    .line 3
    .line 4
    invoke-static {v0, v1}, Lvy0/e0;->G(ILjava/lang/String;)Lvy0/b1;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v0, v1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance v3, Ljava/util/concurrent/ConcurrentHashMap;

    .line 23
    .line 24
    invoke-direct {v3}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 25
    .line 26
    .line 27
    const-string v4, "environment"

    .line 28
    .line 29
    sget-object v5, Lac0/w;->u:Lcm0/b;

    .line 30
    .line 31
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string v4, "coroutineContext"

    .line 35
    .line 36
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 40
    .line 41
    .line 42
    iput-object p1, p0, Lac0/w;->d:Lac0/y;

    .line 43
    .line 44
    iput-object p2, p0, Lac0/w;->e:Lac0/x;

    .line 45
    .line 46
    iput-object p3, p0, Lac0/w;->f:Lac0/z;

    .line 47
    .line 48
    iput-object p4, p0, Lac0/w;->g:Lzr0/a;

    .line 49
    .line 50
    iput-object p5, p0, Lac0/w;->h:Lrh0/f;

    .line 51
    .line 52
    iput-object v5, p0, Lac0/w;->i:Lcm0/b;

    .line 53
    .line 54
    iput-object v0, p0, Lac0/w;->j:Lpx0/g;

    .line 55
    .line 56
    iput-object v1, p0, Lac0/w;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 57
    .line 58
    iput-object v3, p0, Lac0/w;->l:Ljava/util/concurrent/ConcurrentHashMap;

    .line 59
    .line 60
    new-instance p1, La71/u;

    .line 61
    .line 62
    const/4 p2, 0x1

    .line 63
    invoke-direct {p1, p0, p2}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 64
    .line 65
    .line 66
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Lac0/w;->n:Llx0/q;

    .line 71
    .line 72
    new-instance p1, Ljava/lang/Object;

    .line 73
    .line 74
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object p1, p0, Lac0/w;->o:Ljava/lang/Object;

    .line 78
    .line 79
    const/4 p1, 0x1

    .line 80
    iput-boolean p1, p0, Lac0/w;->p:Z

    .line 81
    .line 82
    const/4 p1, 0x0

    .line 83
    const/4 p2, 0x6

    .line 84
    invoke-static {p1, p2, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    iput-object p1, p0, Lac0/w;->q:Lyy0/q1;

    .line 89
    .line 90
    new-instance p1, Lac0/q;

    .line 91
    .line 92
    invoke-direct {p1}, Lac0/q;-><init>()V

    .line 93
    .line 94
    .line 95
    iput-object p1, p0, Lac0/w;->r:Lac0/q;

    .line 96
    .line 97
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 98
    .line 99
    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object p1, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 103
    .line 104
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 105
    .line 106
    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 107
    .line 108
    .line 109
    iput-object p1, p0, Lac0/w;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 110
    .line 111
    new-instance p1, Lac0/f;

    .line 112
    .line 113
    const/4 p2, 0x0

    .line 114
    invoke-direct {p1, p0, v2, p2}, Lac0/f;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 115
    .line 116
    .line 117
    const/4 p2, 0x2

    .line 118
    invoke-static {p0, v0, v2, p1, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 119
    .line 120
    .line 121
    return-void
.end method

.method public static final a(Lac0/w;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    instance-of v1, p2, Lac0/t;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lac0/t;

    .line 9
    .line 10
    iget v2, v1, Lac0/t;->g:I

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
    iput v2, v1, Lac0/t;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lac0/t;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lac0/t;-><init>(Lac0/w;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lac0/t;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lac0/t;->g:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v3, :cond_3

    .line 36
    .line 37
    if-eq v3, v5, :cond_2

    .line 38
    .line 39
    if-ne v3, v4, :cond_1

    .line 40
    .line 41
    iget-object p1, v1, Lac0/t;->d:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto/16 :goto_3

    .line 47
    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-object p1, v1, Lac0/t;->d:Ljava/lang/String;

    .line 57
    .line 58
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p2, p0, Lac0/w;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 66
    .line 67
    const/4 v3, 0x0

    .line 68
    invoke-virtual {p2, v3}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    check-cast p2, Lvy0/i1;

    .line 73
    .line 74
    if-eqz p2, :cond_4

    .line 75
    .line 76
    invoke-interface {p2, v3}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 77
    .line 78
    .line 79
    :cond_4
    iget-object p2, p0, Lac0/w;->l:Ljava/util/concurrent/ConcurrentHashMap;

    .line 80
    .line 81
    new-instance v6, Ldc0/b;

    .line 82
    .line 83
    invoke-direct {v6, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2, v6}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    check-cast p2, Lvy0/i1;

    .line 91
    .line 92
    if-eqz p2, :cond_5

    .line 93
    .line 94
    invoke-interface {p2, v3}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 95
    .line 96
    .line 97
    :cond_5
    new-instance p2, Ldc0/b;

    .line 98
    .line 99
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    new-instance v6, Ldc0/b;

    .line 103
    .line 104
    invoke-direct {v6, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-static {v0, v6}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v6

    .line 111
    check-cast v6, Lac0/l;

    .line 112
    .line 113
    new-instance v7, Ldc0/b;

    .line 114
    .line 115
    invoke-direct {v7, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-static {v0, v7}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v7

    .line 122
    check-cast v7, Lac0/l;

    .line 123
    .line 124
    iget v7, v7, Lac0/l;->a:I

    .line 125
    .line 126
    add-int/2addr v7, v5

    .line 127
    const/4 v8, 0x0

    .line 128
    const/4 v9, 0x6

    .line 129
    invoke-static {v6, v7, v8, v9}, Lac0/l;->a(Lac0/l;IZI)Lac0/l;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    invoke-virtual {v0, p2, v6}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    iput-object p1, v1, Lac0/t;->d:Ljava/lang/String;

    .line 137
    .line 138
    iput v5, v1, Lac0/t;->g:I

    .line 139
    .line 140
    iget-object p2, p0, Lac0/w;->j:Lpx0/g;

    .line 141
    .line 142
    new-instance v6, Lac0/n;

    .line 143
    .line 144
    const/4 v7, 0x1

    .line 145
    invoke-direct {v6, p0, v3, v7}, Lac0/n;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 146
    .line 147
    .line 148
    invoke-static {p2, v6, v1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p2

    .line 152
    if-ne p2, v2, :cond_6

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_6
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 156
    .line 157
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 158
    .line 159
    .line 160
    move-result p2

    .line 161
    if-nez p2, :cond_7

    .line 162
    .line 163
    iput-object p1, v1, Lac0/t;->d:Ljava/lang/String;

    .line 164
    .line 165
    iput v4, v1, Lac0/t;->g:I

    .line 166
    .line 167
    invoke-virtual {p0, v5, v1}, Lac0/w;->d(ZLrx0/c;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p2

    .line 171
    if-ne p2, v2, :cond_7

    .line 172
    .line 173
    :goto_2
    return-object v2

    .line 174
    :cond_7
    :goto_3
    new-instance p2, Ldc0/b;

    .line 175
    .line 176
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    invoke-static {v0, p2}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p2

    .line 183
    check-cast p2, Lac0/l;

    .line 184
    .line 185
    iget-boolean p2, p2, Lac0/l;->c:Z

    .line 186
    .line 187
    if-nez p2, :cond_8

    .line 188
    .line 189
    invoke-virtual {p0, p1}, Lac0/w;->e(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    return-object p0
.end method

.method public static final b(Lac0/w;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    instance-of v1, p2, Lac0/u;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lac0/u;

    .line 9
    .line 10
    iget v2, v1, Lac0/u;->f:I

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
    iput v2, v1, Lac0/u;->f:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lac0/u;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lac0/u;-><init>(Lac0/w;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lac0/u;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lac0/u;->f:I

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v3, :cond_2

    .line 37
    .line 38
    if-ne v3, v6, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_2

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    new-instance p2, Ldc0/b;

    .line 56
    .line 57
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v0, p2}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    check-cast p2, Lac0/l;

    .line 65
    .line 66
    iget v3, p2, Lac0/l;->a:I

    .line 67
    .line 68
    const/4 v7, 0x6

    .line 69
    if-ne v3, v6, :cond_3

    .line 70
    .line 71
    iget-boolean v3, p2, Lac0/l;->c:Z

    .line 72
    .line 73
    if-eqz v3, :cond_3

    .line 74
    .line 75
    new-instance p2, Ldc0/b;

    .line 76
    .line 77
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    new-instance v3, Ldc0/b;

    .line 81
    .line 82
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-static {v0, v3}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    check-cast v3, Lac0/l;

    .line 90
    .line 91
    invoke-static {v3, v5, v5, v7}, Lac0/l;->a(Lac0/l;IZI)Lac0/l;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-virtual {v0, p2, v3}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p0, p1, v6}, Lac0/w;->f(Ljava/lang/String;Z)V

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_3
    new-instance v3, Ldc0/b;

    .line 103
    .line 104
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    new-instance v8, Ldc0/b;

    .line 108
    .line 109
    invoke-direct {v8, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v0, v8}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    check-cast p1, Lac0/l;

    .line 117
    .line 118
    iget p2, p2, Lac0/l;->a:I

    .line 119
    .line 120
    sub-int/2addr p2, v6

    .line 121
    invoke-static {p1, p2, v5, v7}, Lac0/l;->a(Lac0/l;IZI)Lac0/l;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {v0, v3, p1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    :goto_1
    iput v6, v1, Lac0/u;->f:I

    .line 129
    .line 130
    iget-object p1, p0, Lac0/w;->j:Lpx0/g;

    .line 131
    .line 132
    new-instance p2, Lac0/n;

    .line 133
    .line 134
    const/4 v3, 0x1

    .line 135
    invoke-direct {p2, p0, v4, v3}, Lac0/n;-><init>(Lac0/w;Lkotlin/coroutines/Continuation;I)V

    .line 136
    .line 137
    .line 138
    invoke-static {p1, p2, v1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p2

    .line 142
    if-ne p2, v2, :cond_4

    .line 143
    .line 144
    return-object v2

    .line 145
    :cond_4
    :goto_2
    check-cast p2, Ljava/lang/Boolean;

    .line 146
    .line 147
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    if-eqz p1, :cond_9

    .line 152
    .line 153
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    const-string p2, "<get-values>(...)"

    .line 158
    .line 159
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    check-cast p1, Ljava/lang/Iterable;

    .line 163
    .line 164
    move-object p2, p1

    .line 165
    check-cast p2, Ljava/util/Collection;

    .line 166
    .line 167
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 168
    .line 169
    .line 170
    move-result p2

    .line 171
    if-eqz p2, :cond_5

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_5
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    :cond_6
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 179
    .line 180
    .line 181
    move-result p2

    .line 182
    if-eqz p2, :cond_8

    .line 183
    .line 184
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p2

    .line 188
    check-cast p2, Lac0/l;

    .line 189
    .line 190
    iget p2, p2, Lac0/l;->a:I

    .line 191
    .line 192
    if-lez p2, :cond_6

    .line 193
    .line 194
    add-int/lit8 v5, v5, 0x1

    .line 195
    .line 196
    if-ltz v5, :cond_7

    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_7
    invoke-static {}, Ljp/k1;->q()V

    .line 200
    .line 201
    .line 202
    throw v4

    .line 203
    :cond_8
    :goto_4
    if-nez v5, :cond_9

    .line 204
    .line 205
    invoke-virtual {p0, v6}, Lac0/w;->c(Z)V

    .line 206
    .line 207
    .line 208
    :cond_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 209
    .line 210
    return-object p0
.end method

.method public static final g(Lac0/w;Ljava/lang/String;)V
    .locals 6

    .line 1
    new-instance v0, Lac0/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p1, v1}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {v1, p0, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 9
    .line 10
    .line 11
    :try_start_0
    iget-object v0, p0, Lac0/w;->o:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    :try_start_1
    iget-object v2, p0, Lac0/w;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 15
    .line 16
    new-instance v3, Ldc0/b;

    .line 17
    .line 18
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2, v3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Lvy0/i1;

    .line 26
    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    invoke-interface {v2, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p1

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    iget-object v2, p0, Lac0/w;->m:Lorg/eclipse/paho/mqttv5/client/MqttClient;

    .line 36
    .line 37
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v2, p1}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->unsubscribe(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object v2, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 44
    .line 45
    new-instance v3, Ldc0/b;

    .line 46
    .line 47
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    new-instance v4, Ldc0/b;

    .line 51
    .line 52
    invoke-direct {v4, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-static {v2, v4}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, Lac0/l;

    .line 60
    .line 61
    const/4 v4, 0x3

    .line 62
    const/4 v5, 0x0

    .line 63
    invoke-static {p1, v5, v5, v4}, Lac0/l;->a(Lac0/l;IZI)Lac0/l;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {v2, v3, p1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    .line 69
    .line 70
    :try_start_2
    monitor-exit v0

    .line 71
    return-void

    .line 72
    :catch_0
    move-exception p1

    .line 73
    goto :goto_2

    .line 74
    :goto_1
    monitor-exit v0

    .line 75
    throw p1
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 76
    :goto_2
    new-instance v0, Lac0/b;

    .line 77
    .line 78
    const/4 v2, 0x0

    .line 79
    invoke-direct {v0, v2, p1}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 83
    .line 84
    .line 85
    new-instance p0, Ljava/io/IOException;

    .line 86
    .line 87
    const-string v0, "Could not unsubscribe from the MQTT topics"

    .line 88
    .line 89
    invoke-direct {p0, v0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 90
    .line 91
    .line 92
    throw p0
.end method


# virtual methods
.method public final c(Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lac0/w;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    new-instance p1, La2/m;

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    invoke-direct {p1, v0}, La2/m;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v2, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    new-instance v1, La2/m;

    .line 21
    .line 22
    const/4 v3, 0x2

    .line 23
    invoke-direct {v1, v3}, La2/m;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v2, p0, v1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 27
    .line 28
    .line 29
    new-instance v1, Lac0/m;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    invoke-direct {v1, p1, p0, v2, v3}, Lac0/m;-><init>(ZLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    const/4 p1, 0x2

    .line 36
    iget-object v3, p0, Lac0/w;->j:Lpx0/g;

    .line 37
    .line 38
    invoke-static {p0, v3, v2, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance v1, La2/e;

    .line 43
    .line 44
    const/4 v2, 0x2

    .line 45
    invoke-direct {v1, p0, v2}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, v1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final d(ZLrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    instance-of v2, v0, Lac0/o;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v0

    .line 10
    check-cast v2, Lac0/o;

    .line 11
    .line 12
    iget v3, v2, Lac0/o;->q:I

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
    iput v3, v2, Lac0/o;->q:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lac0/o;

    .line 25
    .line 26
    invoke-direct {v2, v1, v0}, Lac0/o;-><init>(Lac0/w;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v0, v2, Lac0/o;->o:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lac0/o;->q:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x0

    .line 39
    packed-switch v4, :pswitch_data_0

    .line 40
    .line 41
    .line 42
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0

    .line 50
    :pswitch_0
    iget-object v3, v2, Lac0/o;->k:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v3, Lne0/t;

    .line 53
    .line 54
    iget-object v4, v2, Lac0/o;->j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 55
    .line 56
    check-cast v4, [I

    .line 57
    .line 58
    iget-object v4, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v4, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 61
    .line 62
    iget-object v2, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 63
    .line 64
    check-cast v2, Lorg/eclipse/paho/mqttv5/client/MqttClient;

    .line 65
    .line 66
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_12

    .line 70
    .line 71
    :pswitch_1
    iget v4, v2, Lac0/o;->m:I

    .line 72
    .line 73
    iget-boolean v5, v2, Lac0/o;->e:Z

    .line 74
    .line 75
    iget-boolean v6, v2, Lac0/o;->d:Z

    .line 76
    .line 77
    iget-object v9, v2, Lac0/o;->j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 78
    .line 79
    check-cast v9, [I

    .line 80
    .line 81
    iget-object v9, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v9, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 84
    .line 85
    iget-object v10, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 86
    .line 87
    check-cast v10, Lorg/eclipse/paho/mqttv5/client/MqttClient;

    .line 88
    .line 89
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    move v7, v6

    .line 93
    move v6, v5

    .line 94
    move v5, v4

    .line 95
    move-object v4, v9

    .line 96
    goto/16 :goto_10

    .line 97
    .line 98
    :pswitch_2
    iget v6, v2, Lac0/o;->n:I

    .line 99
    .line 100
    iget-boolean v4, v2, Lac0/o;->e:Z

    .line 101
    .line 102
    iget-boolean v5, v2, Lac0/o;->d:Z

    .line 103
    .line 104
    iget-object v9, v2, Lac0/o;->l:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v10, v2, Lac0/o;->k:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v10, [Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 109
    .line 110
    iget-object v11, v2, Lac0/o;->j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 111
    .line 112
    iget-object v12, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v12, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 115
    .line 116
    iget-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 117
    .line 118
    iget-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 119
    .line 120
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    move/from16 p2, v7

    .line 124
    .line 125
    goto/16 :goto_9

    .line 126
    .line 127
    :pswitch_3
    iget v4, v2, Lac0/o;->m:I

    .line 128
    .line 129
    iget-boolean v9, v2, Lac0/o;->e:Z

    .line 130
    .line 131
    iget-boolean v10, v2, Lac0/o;->d:Z

    .line 132
    .line 133
    iget-object v11, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v11, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 136
    .line 137
    iget-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 138
    .line 139
    iget-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 140
    .line 141
    iget-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 142
    .line 143
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    move/from16 p2, v7

    .line 147
    .line 148
    :goto_1
    move v6, v4

    .line 149
    move v4, v9

    .line 150
    goto/16 :goto_7

    .line 151
    .line 152
    :pswitch_4
    iget v4, v2, Lac0/o;->m:I

    .line 153
    .line 154
    iget-boolean v9, v2, Lac0/o;->e:Z

    .line 155
    .line 156
    iget-boolean v10, v2, Lac0/o;->d:Z

    .line 157
    .line 158
    iget-object v11, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v11, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 161
    .line 162
    iget-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 163
    .line 164
    iget-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 165
    .line 166
    iget-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 167
    .line 168
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move/from16 p2, v7

    .line 172
    .line 173
    goto/16 :goto_6

    .line 174
    .line 175
    :pswitch_5
    iget v4, v2, Lac0/o;->m:I

    .line 176
    .line 177
    iget-boolean v9, v2, Lac0/o;->e:Z

    .line 178
    .line 179
    iget-boolean v10, v2, Lac0/o;->d:Z

    .line 180
    .line 181
    iget-object v11, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v11, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 184
    .line 185
    iget-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 186
    .line 187
    iget-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 188
    .line 189
    iget-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 190
    .line 191
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    move/from16 p2, v7

    .line 195
    .line 196
    goto/16 :goto_5

    .line 197
    .line 198
    :pswitch_6
    iget v4, v2, Lac0/o;->m:I

    .line 199
    .line 200
    iget-boolean v9, v2, Lac0/o;->e:Z

    .line 201
    .line 202
    iget-boolean v10, v2, Lac0/o;->d:Z

    .line 203
    .line 204
    iget-object v11, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v11, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 207
    .line 208
    iget-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 209
    .line 210
    iget-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 211
    .line 212
    iget-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 213
    .line 214
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_4

    .line 218
    .line 219
    :pswitch_7
    iget-boolean v4, v2, Lac0/o;->e:Z

    .line 220
    .line 221
    iget-boolean v9, v2, Lac0/o;->d:Z

    .line 222
    .line 223
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    move v10, v9

    .line 227
    move v9, v4

    .line 228
    goto :goto_3

    .line 229
    :pswitch_8
    iget-boolean v4, v2, Lac0/o;->d:Z

    .line 230
    .line 231
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    goto :goto_2

    .line 235
    :pswitch_9
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    iget-object v0, v1, Lac0/w;->h:Lrh0/f;

    .line 239
    .line 240
    sget-object v4, Lqh0/a;->k:Lqh0/a;

    .line 241
    .line 242
    move/from16 v9, p1

    .line 243
    .line 244
    iput-boolean v9, v2, Lac0/o;->d:Z

    .line 245
    .line 246
    iput v6, v2, Lac0/o;->q:I

    .line 247
    .line 248
    invoke-virtual {v0, v4, v2}, Lrh0/f;->a(Lqh0/a;Lrx0/c;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    if-ne v0, v3, :cond_1

    .line 253
    .line 254
    goto/16 :goto_11

    .line 255
    .line 256
    :cond_1
    move v4, v9

    .line 257
    :goto_2
    check-cast v0, Ljava/lang/Boolean;

    .line 258
    .line 259
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 260
    .line 261
    .line 262
    move-result v0

    .line 263
    iget-object v9, v1, Lac0/w;->d:Lac0/y;

    .line 264
    .line 265
    iget-object v10, v1, Lac0/w;->i:Lcm0/b;

    .line 266
    .line 267
    iput-boolean v4, v2, Lac0/o;->d:Z

    .line 268
    .line 269
    iput-boolean v0, v2, Lac0/o;->e:Z

    .line 270
    .line 271
    iput v5, v2, Lac0/o;->q:I

    .line 272
    .line 273
    check-cast v9, Lec0/b;

    .line 274
    .line 275
    invoke-virtual {v9, v10, v0, v2}, Lec0/b;->a(Lcm0/b;ZLrx0/c;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v9

    .line 279
    if-ne v9, v3, :cond_2

    .line 280
    .line 281
    goto/16 :goto_11

    .line 282
    .line 283
    :cond_2
    move-object v10, v9

    .line 284
    move v9, v0

    .line 285
    move-object v0, v10

    .line 286
    move v10, v4

    .line 287
    :goto_3
    move-object v14, v0

    .line 288
    check-cast v14, Ldc0/e;

    .line 289
    .line 290
    new-instance v11, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 291
    .line 292
    invoke-direct {v11}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;-><init>()V

    .line 293
    .line 294
    .line 295
    iget-object v0, v1, Lac0/w;->h:Lrh0/f;

    .line 296
    .line 297
    sget-object v4, Lqh0/a;->i:Lqh0/a;

    .line 298
    .line 299
    iput-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 300
    .line 301
    iput-object v11, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 302
    .line 303
    iput-object v11, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 304
    .line 305
    iput-object v11, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 306
    .line 307
    iput-boolean v10, v2, Lac0/o;->d:Z

    .line 308
    .line 309
    iput-boolean v9, v2, Lac0/o;->e:Z

    .line 310
    .line 311
    iput v7, v2, Lac0/o;->m:I

    .line 312
    .line 313
    const/4 v12, 0x3

    .line 314
    iput v12, v2, Lac0/o;->q:I

    .line 315
    .line 316
    invoke-virtual {v0, v4, v2}, Lrh0/f;->c(Lqh0/a;Lrx0/c;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    if-ne v0, v3, :cond_3

    .line 321
    .line 322
    goto/16 :goto_11

    .line 323
    .line 324
    :cond_3
    move v4, v7

    .line 325
    move-object v12, v11

    .line 326
    move-object v13, v12

    .line 327
    :goto_4
    check-cast v0, Ljava/lang/Number;

    .line 328
    .line 329
    move/from16 p2, v7

    .line 330
    .line 331
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 332
    .line 333
    .line 334
    move-result-wide v6

    .line 335
    long-to-int v0, v6

    .line 336
    invoke-virtual {v11, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setKeepAliveInterval(I)V

    .line 337
    .line 338
    .line 339
    iget-object v0, v1, Lac0/w;->h:Lrh0/f;

    .line 340
    .line 341
    sget-object v6, Lqh0/a;->j:Lqh0/a;

    .line 342
    .line 343
    iput-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 344
    .line 345
    iput-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 346
    .line 347
    iput-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 348
    .line 349
    iput-object v12, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 350
    .line 351
    iput-boolean v10, v2, Lac0/o;->d:Z

    .line 352
    .line 353
    iput-boolean v9, v2, Lac0/o;->e:Z

    .line 354
    .line 355
    iput v4, v2, Lac0/o;->m:I

    .line 356
    .line 357
    const/4 v7, 0x4

    .line 358
    iput v7, v2, Lac0/o;->q:I

    .line 359
    .line 360
    invoke-virtual {v0, v6, v2}, Lrh0/f;->c(Lqh0/a;Lrx0/c;)Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    move-result-object v0

    .line 364
    if-ne v0, v3, :cond_4

    .line 365
    .line 366
    goto/16 :goto_11

    .line 367
    .line 368
    :cond_4
    move-object v11, v12

    .line 369
    :goto_5
    check-cast v0, Ljava/lang/Long;

    .line 370
    .line 371
    invoke-virtual {v11, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setSessionExpiryInterval(Ljava/lang/Long;)V

    .line 372
    .line 373
    .line 374
    iget-object v0, v1, Lac0/w;->h:Lrh0/f;

    .line 375
    .line 376
    sget-object v6, Lqh0/a;->l:Lqh0/a;

    .line 377
    .line 378
    iput-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 379
    .line 380
    iput-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 381
    .line 382
    iput-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 383
    .line 384
    iput-object v12, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 385
    .line 386
    iput-boolean v10, v2, Lac0/o;->d:Z

    .line 387
    .line 388
    iput-boolean v9, v2, Lac0/o;->e:Z

    .line 389
    .line 390
    iput v4, v2, Lac0/o;->m:I

    .line 391
    .line 392
    const/4 v7, 0x5

    .line 393
    iput v7, v2, Lac0/o;->q:I

    .line 394
    .line 395
    invoke-virtual {v0, v6, v2}, Lrh0/f;->a(Lqh0/a;Lrx0/c;)Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    if-ne v0, v3, :cond_5

    .line 400
    .line 401
    goto/16 :goto_11

    .line 402
    .line 403
    :cond_5
    move-object v11, v12

    .line 404
    :goto_6
    check-cast v0, Ljava/lang/Boolean;

    .line 405
    .line 406
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    invoke-virtual {v11, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setCleanStart(Z)V

    .line 411
    .line 412
    .line 413
    instance-of v0, v14, Ldc0/c;

    .line 414
    .line 415
    if-eqz v0, :cond_6

    .line 416
    .line 417
    iget-object v0, v14, Ldc0/e;->c:Ljava/lang/String;

    .line 418
    .line 419
    invoke-virtual {v12, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setUserName(Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    const-string v0, ""

    .line 423
    .line 424
    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 425
    .line 426
    const-string v5, "UTF_8"

    .line 427
    .line 428
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v0, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    const-string v4, "getBytes(...)"

    .line 436
    .line 437
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    invoke-virtual {v12, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setPassword([B)V

    .line 441
    .line 442
    .line 443
    move v5, v9

    .line 444
    move v6, v10

    .line 445
    goto/16 :goto_a

    .line 446
    .line 447
    :cond_6
    instance-of v0, v14, Ldc0/d;

    .line 448
    .line 449
    if-eqz v0, :cond_14

    .line 450
    .line 451
    iget-object v0, v1, Lac0/w;->g:Lzr0/a;

    .line 452
    .line 453
    iput-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 454
    .line 455
    iput-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 456
    .line 457
    iput-object v12, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 458
    .line 459
    iput-object v12, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 460
    .line 461
    iput-boolean v10, v2, Lac0/o;->d:Z

    .line 462
    .line 463
    iput-boolean v9, v2, Lac0/o;->e:Z

    .line 464
    .line 465
    iput v4, v2, Lac0/o;->m:I

    .line 466
    .line 467
    const/4 v6, 0x6

    .line 468
    iput v6, v2, Lac0/o;->q:I

    .line 469
    .line 470
    iget-object v0, v0, Lzr0/a;->a:Lur0/g;

    .line 471
    .line 472
    sget-object v6, Lge0/b;->a:Lcz0/e;

    .line 473
    .line 474
    new-instance v7, Lur0/c;

    .line 475
    .line 476
    const/4 v11, 0x1

    .line 477
    invoke-direct {v7, v0, v8, v11}, Lur0/c;-><init>(Lur0/g;Lkotlin/coroutines/Continuation;I)V

    .line 478
    .line 479
    .line 480
    invoke-static {v6, v7, v2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    if-ne v0, v3, :cond_7

    .line 485
    .line 486
    goto/16 :goto_11

    .line 487
    .line 488
    :cond_7
    move-object v11, v12

    .line 489
    goto/16 :goto_1

    .line 490
    .line 491
    :goto_7
    check-cast v0, Ljava/lang/String;

    .line 492
    .line 493
    invoke-virtual {v11, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setUserName(Ljava/lang/String;)V

    .line 494
    .line 495
    .line 496
    iget-object v0, v1, Lac0/w;->e:Lac0/x;

    .line 497
    .line 498
    check-cast v0, Lnc0/j;

    .line 499
    .line 500
    iget-object v0, v0, Lnc0/j;->a:Lkc0/g;

    .line 501
    .line 502
    check-cast v0, Lic0/p;

    .line 503
    .line 504
    invoke-virtual {v0}, Lic0/p;->b()Ljava/lang/String;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    if-nez v0, :cond_8

    .line 509
    .line 510
    move-object v0, v8

    .line 511
    :cond_8
    if-eqz v0, :cond_9

    .line 512
    .line 513
    sget-object v7, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 514
    .line 515
    const-string v9, "UTF_8"

    .line 516
    .line 517
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    invoke-virtual {v0, v7}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 521
    .line 522
    .line 523
    move-result-object v0

    .line 524
    const-string v7, "getBytes(...)"

    .line 525
    .line 526
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    goto :goto_8

    .line 530
    :cond_9
    move-object v0, v8

    .line 531
    :goto_8
    invoke-virtual {v12, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setPassword([B)V

    .line 532
    .line 533
    .line 534
    new-array v0, v5, [Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 535
    .line 536
    new-instance v5, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 537
    .line 538
    const-string v7, "auth_method"

    .line 539
    .line 540
    const-string v9, "totp_v1"

    .line 541
    .line 542
    invoke-direct {v5, v7, v9}, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 543
    .line 544
    .line 545
    aput-object v5, v0, p2

    .line 546
    .line 547
    const-string v9, "auth_credentials"

    .line 548
    .line 549
    iget-object v5, v1, Lac0/w;->f:Lac0/z;

    .line 550
    .line 551
    iput-object v14, v2, Lac0/o;->f:Ldc0/e;

    .line 552
    .line 553
    iput-object v13, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 554
    .line 555
    iput-object v8, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 556
    .line 557
    iput-object v12, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 558
    .line 559
    iput-object v0, v2, Lac0/o;->j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 560
    .line 561
    iput-object v0, v2, Lac0/o;->k:Ljava/lang/Object;

    .line 562
    .line 563
    iput-object v9, v2, Lac0/o;->l:Ljava/lang/String;

    .line 564
    .line 565
    iput-boolean v10, v2, Lac0/o;->d:Z

    .line 566
    .line 567
    iput-boolean v4, v2, Lac0/o;->e:Z

    .line 568
    .line 569
    iput v6, v2, Lac0/o;->m:I

    .line 570
    .line 571
    const/4 v15, 0x1

    .line 572
    iput v15, v2, Lac0/o;->n:I

    .line 573
    .line 574
    const/4 v6, 0x7

    .line 575
    iput v6, v2, Lac0/o;->q:I

    .line 576
    .line 577
    check-cast v5, Lec0/d;

    .line 578
    .line 579
    invoke-virtual {v5, v2}, Lec0/d;->a(Lrx0/c;)Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object v5

    .line 583
    if-ne v5, v3, :cond_a

    .line 584
    .line 585
    goto/16 :goto_11

    .line 586
    .line 587
    :cond_a
    move-object v11, v0

    .line 588
    move v6, v15

    .line 589
    move-object v0, v5

    .line 590
    move v5, v10

    .line 591
    move-object v10, v11

    .line 592
    :goto_9
    check-cast v0, Ljava/lang/String;

    .line 593
    .line 594
    new-instance v7, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 595
    .line 596
    invoke-direct {v7, v9, v0}, Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    aput-object v7, v11, v6

    .line 600
    .line 601
    invoke-static {v10}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 602
    .line 603
    .line 604
    move-result-object v0

    .line 605
    invoke-virtual {v12, v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->setUserProperties(Ljava/util/List;)V

    .line 606
    .line 607
    .line 608
    move v6, v5

    .line 609
    move v5, v4

    .line 610
    :goto_a
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttClient;

    .line 611
    .line 612
    iget-object v4, v14, Ldc0/e;->a:Ljava/lang/String;

    .line 613
    .line 614
    iget-object v7, v14, Ldc0/e;->b:Ljava/lang/String;

    .line 615
    .line 616
    new-instance v9, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;

    .line 617
    .line 618
    invoke-direct {v9}, Lorg/eclipse/paho/mqttv5/client/persist/MemoryPersistence;-><init>()V

    .line 619
    .line 620
    .line 621
    invoke-direct {v0, v4, v7, v9}, Lorg/eclipse/paho/mqttv5/client/MqttClient;-><init>(Ljava/lang/String;Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;)V

    .line 622
    .line 623
    .line 624
    iput-object v0, v1, Lac0/w;->m:Lorg/eclipse/paho/mqttv5/client/MqttClient;

    .line 625
    .line 626
    const-wide/16 v9, 0x2710

    .line 627
    .line 628
    invoke-virtual {v0, v9, v10}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->setTimeToWait(J)V

    .line 629
    .line 630
    .line 631
    iget-object v4, v1, Lac0/w;->n:Llx0/q;

    .line 632
    .line 633
    invoke-virtual {v4}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    move-result-object v4

    .line 637
    check-cast v4, Lorg/eclipse/paho/mqttv5/client/MqttCallback;

    .line 638
    .line 639
    invoke-virtual {v0, v4}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V

    .line 640
    .line 641
    .line 642
    new-instance v4, La2/m;

    .line 643
    .line 644
    const/4 v7, 0x4

    .line 645
    invoke-direct {v4, v7}, La2/m;-><init>(I)V

    .line 646
    .line 647
    .line 648
    invoke-static {v8, v1, v4}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 649
    .line 650
    .line 651
    const/16 v4, 0x87

    .line 652
    .line 653
    :try_start_0
    iget-object v7, v1, Lac0/w;->o:Ljava/lang/Object;

    .line 654
    .line 655
    monitor-enter v7
    :try_end_0
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 656
    :try_start_1
    instance-of v9, v14, Ldc0/d;

    .line 657
    .line 658
    if-eqz v9, :cond_c

    .line 659
    .line 660
    invoke-virtual {v13}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getPassword()[B

    .line 661
    .line 662
    .line 663
    move-result-object v9

    .line 664
    if-eqz v9, :cond_b

    .line 665
    .line 666
    goto :goto_b

    .line 667
    :cond_b
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 668
    .line 669
    invoke-direct {v0, v4}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(I)V

    .line 670
    .line 671
    .line 672
    throw v0

    .line 673
    :catchall_0
    move-exception v0

    .line 674
    goto :goto_c

    .line 675
    :cond_c
    :goto_b
    invoke-virtual {v0, v13}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 676
    .line 677
    .line 678
    :try_start_2
    monitor-exit v7

    .line 679
    goto/16 :goto_13

    .line 680
    .line 681
    :catch_0
    move-exception v0

    .line 682
    goto :goto_d

    .line 683
    :catch_1
    move-exception v0

    .line 684
    goto :goto_e

    .line 685
    :goto_c
    monitor-exit v7

    .line 686
    throw v0
    :try_end_2
    .catch Lorg/eclipse/paho/mqttv5/common/MqttException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 687
    :goto_d
    iget-object v2, v1, Lac0/w;->q:Lyy0/q1;

    .line 688
    .line 689
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 690
    .line 691
    invoke-virtual {v2, v3}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 692
    .line 693
    .line 694
    new-instance v2, Lac0/b;

    .line 695
    .line 696
    const/4 v3, 0x1

    .line 697
    invoke-direct {v2, v3, v0}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 698
    .line 699
    .line 700
    invoke-static {v8, v1, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 701
    .line 702
    .line 703
    new-instance v1, Ljava/io/IOException;

    .line 704
    .line 705
    const-string v2, "Could not connect to the MQTT server with provided configuration"

    .line 706
    .line 707
    invoke-direct {v1, v2, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 708
    .line 709
    .line 710
    throw v1

    .line 711
    :goto_e
    invoke-virtual {v13}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getPassword()[B

    .line 712
    .line 713
    .line 714
    move-result-object v7

    .line 715
    if-eqz v7, :cond_d

    .line 716
    .line 717
    new-instance v7, Lac0/c;

    .line 718
    .line 719
    const/4 v9, 0x0

    .line 720
    invoke-direct {v7, v0, v9}, Lac0/c;-><init>(Lorg/eclipse/paho/mqttv5/common/MqttException;I)V

    .line 721
    .line 722
    .line 723
    invoke-static {v8, v1, v7}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 724
    .line 725
    .line 726
    :cond_d
    const/16 v7, 0x86

    .line 727
    .line 728
    filled-new-array {v4, v7}, [I

    .line 729
    .line 730
    .line 731
    move-result-object v4

    .line 732
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/common/MqttException;->getReasonCode()I

    .line 733
    .line 734
    .line 735
    move-result v7

    .line 736
    invoke-static {v7, v4}, Lmx0/n;->d(I[I)Z

    .line 737
    .line 738
    .line 739
    move-result v4

    .line 740
    if-eqz v4, :cond_13

    .line 741
    .line 742
    iget-boolean v4, v1, Lac0/w;->p:Z

    .line 743
    .line 744
    if-eqz v4, :cond_13

    .line 745
    .line 746
    if-eqz v6, :cond_13

    .line 747
    .line 748
    instance-of v4, v14, Ldc0/d;

    .line 749
    .line 750
    if-eqz v4, :cond_13

    .line 751
    .line 752
    new-instance v4, La2/m;

    .line 753
    .line 754
    const/4 v7, 0x5

    .line 755
    invoke-direct {v4, v7}, La2/m;-><init>(I)V

    .line 756
    .line 757
    .line 758
    invoke-static {v8, v1, v4}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 759
    .line 760
    .line 761
    iget-object v4, v1, Lac0/w;->e:Lac0/x;

    .line 762
    .line 763
    invoke-virtual {v13}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getPassword()[B

    .line 764
    .line 765
    .line 766
    move-result-object v7

    .line 767
    if-eqz v7, :cond_e

    .line 768
    .line 769
    new-instance v9, Ljava/lang/String;

    .line 770
    .line 771
    sget-object v10, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 772
    .line 773
    invoke-direct {v9, v7, v10}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 774
    .line 775
    .line 776
    goto :goto_f

    .line 777
    :cond_e
    move-object v9, v8

    .line 778
    :goto_f
    iput-object v8, v2, Lac0/o;->f:Ldc0/e;

    .line 779
    .line 780
    iput-object v8, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 781
    .line 782
    iput-object v8, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 783
    .line 784
    iput-object v0, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 785
    .line 786
    iput-object v8, v2, Lac0/o;->j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 787
    .line 788
    iput-object v8, v2, Lac0/o;->k:Ljava/lang/Object;

    .line 789
    .line 790
    iput-object v8, v2, Lac0/o;->l:Ljava/lang/String;

    .line 791
    .line 792
    iput-boolean v6, v2, Lac0/o;->d:Z

    .line 793
    .line 794
    iput-boolean v5, v2, Lac0/o;->e:Z

    .line 795
    .line 796
    move/from16 v7, p2

    .line 797
    .line 798
    iput v7, v2, Lac0/o;->m:I

    .line 799
    .line 800
    const/16 v7, 0x8

    .line 801
    .line 802
    iput v7, v2, Lac0/o;->q:I

    .line 803
    .line 804
    check-cast v4, Lnc0/j;

    .line 805
    .line 806
    invoke-virtual {v4, v9, v2}, Lnc0/j;->a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 807
    .line 808
    .line 809
    move-result-object v4

    .line 810
    if-ne v4, v3, :cond_f

    .line 811
    .line 812
    goto :goto_11

    .line 813
    :cond_f
    move-object v7, v4

    .line 814
    move-object v4, v0

    .line 815
    move-object v0, v7

    .line 816
    move v7, v6

    .line 817
    move v6, v5

    .line 818
    const/4 v5, 0x0

    .line 819
    :goto_10
    check-cast v0, Lne0/t;

    .line 820
    .line 821
    instance-of v9, v0, Lne0/e;

    .line 822
    .line 823
    if-eqz v9, :cond_11

    .line 824
    .line 825
    move-object v9, v0

    .line 826
    check-cast v9, Lne0/e;

    .line 827
    .line 828
    iget-object v9, v9, Lne0/e;->a:Ljava/lang/Object;

    .line 829
    .line 830
    check-cast v9, Ljava/lang/String;

    .line 831
    .line 832
    iput-object v8, v2, Lac0/o;->f:Ldc0/e;

    .line 833
    .line 834
    iput-object v8, v2, Lac0/o;->g:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 835
    .line 836
    iput-object v8, v2, Lac0/o;->h:Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 837
    .line 838
    iput-object v4, v2, Lac0/o;->i:Ljava/lang/Object;

    .line 839
    .line 840
    iput-object v8, v2, Lac0/o;->j:[Lorg/eclipse/paho/mqttv5/common/packet/UserProperty;

    .line 841
    .line 842
    iput-object v0, v2, Lac0/o;->k:Ljava/lang/Object;

    .line 843
    .line 844
    iput-object v8, v2, Lac0/o;->l:Ljava/lang/String;

    .line 845
    .line 846
    iput-boolean v7, v2, Lac0/o;->d:Z

    .line 847
    .line 848
    iput-boolean v6, v2, Lac0/o;->e:Z

    .line 849
    .line 850
    iput v5, v2, Lac0/o;->m:I

    .line 851
    .line 852
    const/4 v7, 0x0

    .line 853
    iput v7, v2, Lac0/o;->n:I

    .line 854
    .line 855
    const/16 v5, 0x9

    .line 856
    .line 857
    iput v5, v2, Lac0/o;->q:I

    .line 858
    .line 859
    invoke-virtual {v1, v7, v2}, Lac0/w;->d(ZLrx0/c;)Ljava/lang/Object;

    .line 860
    .line 861
    .line 862
    move-result-object v2

    .line 863
    if-ne v2, v3, :cond_10

    .line 864
    .line 865
    :goto_11
    return-object v3

    .line 866
    :cond_10
    move-object v3, v0

    .line 867
    :goto_12
    move-object v0, v3

    .line 868
    :cond_11
    instance-of v0, v0, Lne0/c;

    .line 869
    .line 870
    if-nez v0, :cond_12

    .line 871
    .line 872
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 873
    .line 874
    return-object v0

    .line 875
    :cond_12
    const/4 v7, 0x0

    .line 876
    iput-boolean v7, v1, Lac0/w;->p:Z

    .line 877
    .line 878
    new-instance v0, Ljava/io/IOException;

    .line 879
    .line 880
    const-string v1, "Could not connect to the MQTT server. Unable to refresh access token."

    .line 881
    .line 882
    invoke-direct {v0, v1, v4}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 883
    .line 884
    .line 885
    throw v0

    .line 886
    :cond_13
    iget-object v1, v1, Lac0/w;->q:Lyy0/q1;

    .line 887
    .line 888
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 889
    .line 890
    invoke-virtual {v1, v2}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 891
    .line 892
    .line 893
    new-instance v1, Ljava/io/IOException;

    .line 894
    .line 895
    const-string v2, "Could not connect to the MQTT server. Unable to refresh access token. Max retry tries exceeded."

    .line 896
    .line 897
    invoke-direct {v1, v2, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 898
    .line 899
    .line 900
    throw v1

    .line 901
    :cond_14
    new-instance v0, La8/r0;

    .line 902
    .line 903
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 904
    .line 905
    .line 906
    throw v0

    .line 907
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Ljava/lang/String;)V
    .locals 8

    .line 1
    new-instance v0, Lac0/a;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, p1, v1}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-static {v1, p0, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 9
    .line 10
    .line 11
    :try_start_0
    iget-object v0, p0, Lac0/w;->o:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    :try_start_1
    iget-object v2, p0, Lac0/w;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 15
    .line 16
    new-instance v3, Ldc0/b;

    .line 17
    .line 18
    invoke-direct {v3, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v4, p0, Lac0/w;->j:Lpx0/g;

    .line 22
    .line 23
    new-instance v5, Lac0/v;

    .line 24
    .line 25
    const/4 v6, 0x0

    .line 26
    invoke-direct {v5, p0, p1, v1, v6}, Lac0/v;-><init>(Lac0/w;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    const/4 v6, 0x2

    .line 30
    invoke-static {p0, v4, v1, v5, v6}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    iget-object v2, p0, Lac0/w;->m:Lorg/eclipse/paho/mqttv5/client/MqttClient;

    .line 38
    .line 39
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    const/4 v3, 0x1

    .line 43
    invoke-virtual {v2, p1, v3}, Lorg/eclipse/paho/mqttv5/client/MqttClient;->subscribe(Ljava/lang/String;I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;

    .line 44
    .line 45
    .line 46
    iget-object v2, p0, Lac0/w;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 47
    .line 48
    new-instance v4, Ldc0/b;

    .line 49
    .line 50
    invoke-direct {v4, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    new-instance v5, Ldc0/b;

    .line 54
    .line 55
    invoke-direct {v5, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-static {v2, v5}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    check-cast v5, Lac0/l;

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    const/4 v7, 0x3

    .line 66
    invoke-static {v5, v6, v3, v7}, Lac0/l;->a(Lac0/l;IZI)Lac0/l;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {v2, v4, v3}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    .line 72
    .line 73
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 74
    new-instance v0, Lac0/a;

    .line 75
    .line 76
    const/4 v2, 0x0

    .line 77
    invoke-direct {v0, p1, v2}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 78
    .line 79
    .line 80
    invoke-static {v1, p0, v0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :catch_0
    move-exception v0

    .line 85
    goto :goto_0

    .line 86
    :catchall_0
    move-exception v2

    .line 87
    :try_start_3
    monitor-exit v0

    .line 88
    throw v2
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 89
    :goto_0
    new-instance v2, Lac0/b;

    .line 90
    .line 91
    const/4 v3, 0x2

    .line 92
    invoke-direct {v2, v3, v0}, Lac0/b;-><init>(ILjava/lang/Exception;)V

    .line 93
    .line 94
    .line 95
    invoke-static {v1, p0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 96
    .line 97
    .line 98
    iget-object p0, p0, Lac0/w;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 99
    .line 100
    new-instance v2, Ldc0/b;

    .line 101
    .line 102
    invoke-direct {v2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    check-cast p0, Lvy0/i1;

    .line 110
    .line 111
    if-eqz p0, :cond_0

    .line 112
    .line 113
    invoke-interface {p0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 114
    .line 115
    .line 116
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 117
    .line 118
    const-string p1, "Could not subscribe to the MQTT topics"

    .line 119
    .line 120
    invoke-direct {p0, p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method

.method public final f(Ljava/lang/String;Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lac0/w;->l:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez p2, :cond_1

    .line 5
    .line 6
    new-instance p2, Ldc0/b;

    .line 7
    .line 8
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, p2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    check-cast p2, Lvy0/i1;

    .line 16
    .line 17
    if-eqz p2, :cond_0

    .line 18
    .line 19
    invoke-interface {p2, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    new-instance p2, Ldc0/b;

    .line 23
    .line 24
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p2}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    invoke-static {p0, p1}, Lac0/w;->g(Lac0/w;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    new-instance p2, Ldc0/b;

    .line 35
    .line 36
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, p2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    if-eqz p2, :cond_2

    .line 44
    .line 45
    new-instance p2, Ldc0/b;

    .line 46
    .line 47
    invoke-direct {p2, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, p2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    check-cast p2, Lvy0/i1;

    .line 55
    .line 56
    if-eqz p2, :cond_2

    .line 57
    .line 58
    invoke-interface {p2}, Lvy0/i1;->a()Z

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    const/4 v2, 0x1

    .line 63
    if-ne p2, v2, :cond_2

    .line 64
    .line 65
    new-instance p2, Lac0/a;

    .line 66
    .line 67
    const/4 v0, 0x3

    .line 68
    invoke-direct {p2, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 69
    .line 70
    .line 71
    invoke-static {v1, p0, p2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :cond_2
    new-instance p2, Lac0/a;

    .line 76
    .line 77
    const/4 v2, 0x4

    .line 78
    invoke-direct {p2, p1, v2}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 79
    .line 80
    .line 81
    invoke-static {v1, p0, p2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 82
    .line 83
    .line 84
    new-instance p2, Lac0/v;

    .line 85
    .line 86
    const/4 v2, 0x1

    .line 87
    invoke-direct {p2, p0, p1, v1, v2}, Lac0/v;-><init>(Lac0/w;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 88
    .line 89
    .line 90
    const/4 v2, 0x2

    .line 91
    iget-object v3, p0, Lac0/w;->j:Lpx0/g;

    .line 92
    .line 93
    invoke-static {p0, v3, v1, p2, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    new-instance v1, Laa/z;

    .line 98
    .line 99
    invoke-direct {v1, v2, p0, p1}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p2, v1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 103
    .line 104
    .line 105
    new-instance p0, Ldc0/b;

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-interface {v0, p0, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    return-void
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lac0/w;->j:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method
