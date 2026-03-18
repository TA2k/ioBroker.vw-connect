.class public final Lla/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final l:[Ljava/lang/String;


# instance fields
.field public final a:Lla/u;

.field public final b:Ljava/util/LinkedHashMap;

.field public final c:Ljava/util/LinkedHashMap;

.field public final d:Z

.field public final e:Ll20/g;

.field public final f:Ljava/util/LinkedHashMap;

.field public final g:[Ljava/lang/String;

.field public final h:Lla/l;

.field public final i:Lhu/q;

.field public final j:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public k:Lay0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "UPDATE"

    .line 2
    .line 3
    const-string v1, "DELETE"

    .line 4
    .line 5
    const-string v2, "INSERT"

    .line 6
    .line 7
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lla/l0;->l:[Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lla/u;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;[Ljava/lang/String;ZLl20/g;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lla/l0;->a:Lla/u;

    .line 5
    .line 6
    iput-object p2, p0, Lla/l0;->b:Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    iput-object p3, p0, Lla/l0;->c:Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    iput-boolean p5, p0, Lla/l0;->d:Z

    .line 11
    .line 12
    iput-object p6, p0, Lla/l0;->e:Ll20/g;

    .line 13
    .line 14
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lla/l0;->j:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 21
    .line 22
    new-instance p1, Ll31/b;

    .line 23
    .line 24
    const/16 p3, 0x8

    .line 25
    .line 26
    invoke-direct {p1, p3}, Ll31/b;-><init>(I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lla/l0;->k:Lay0/a;

    .line 30
    .line 31
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 32
    .line 33
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lla/l0;->f:Ljava/util/LinkedHashMap;

    .line 37
    .line 38
    array-length p1, p4

    .line 39
    new-array p3, p1, [Ljava/lang/String;

    .line 40
    .line 41
    :goto_0
    const-string p5, "toLowerCase(...)"

    .line 42
    .line 43
    if-ge p2, p1, :cond_2

    .line 44
    .line 45
    aget-object p6, p4, p2

    .line 46
    .line 47
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 48
    .line 49
    invoke-virtual {p6, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p6

    .line 53
    invoke-static {p6, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lla/l0;->f:Ljava/util/LinkedHashMap;

    .line 57
    .line 58
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-interface {v1, p6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lla/l0;->b:Ljava/util/LinkedHashMap;

    .line 66
    .line 67
    aget-object v2, p4, p2

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    check-cast v1, Ljava/lang/String;

    .line 74
    .line 75
    if-eqz v1, :cond_0

    .line 76
    .line 77
    invoke-virtual {v1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-static {v0, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_0
    const/4 v0, 0x0

    .line 86
    :goto_1
    if-nez v0, :cond_1

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_1
    move-object p6, v0

    .line 90
    :goto_2
    aput-object p6, p3, p2

    .line 91
    .line 92
    add-int/lit8 p2, p2, 0x1

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_2
    iput-object p3, p0, Lla/l0;->g:[Ljava/lang/String;

    .line 96
    .line 97
    iget-object p1, p0, Lla/l0;->b:Ljava/util/LinkedHashMap;

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    :cond_3
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 108
    .line 109
    .line 110
    move-result p2

    .line 111
    if-eqz p2, :cond_4

    .line 112
    .line 113
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    check-cast p2, Ljava/util/Map$Entry;

    .line 118
    .line 119
    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p3

    .line 123
    check-cast p3, Ljava/lang/String;

    .line 124
    .line 125
    sget-object p4, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 126
    .line 127
    invoke-virtual {p3, p4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p3

    .line 131
    invoke-static {p3, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    iget-object p6, p0, Lla/l0;->f:Ljava/util/LinkedHashMap;

    .line 135
    .line 136
    invoke-interface {p6, p3}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result p6

    .line 140
    if-eqz p6, :cond_3

    .line 141
    .line 142
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    check-cast p2, Ljava/lang/String;

    .line 147
    .line 148
    invoke-virtual {p2, p4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p2

    .line 152
    invoke-static {p2, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    iget-object p4, p0, Lla/l0;->f:Ljava/util/LinkedHashMap;

    .line 156
    .line 157
    invoke-static {p4, p3}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p3

    .line 161
    invoke-interface {p4, p2, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    goto :goto_3

    .line 165
    :cond_4
    new-instance p1, Lla/l;

    .line 166
    .line 167
    iget-object p2, p0, Lla/l0;->g:[Ljava/lang/String;

    .line 168
    .line 169
    array-length p2, p2

    .line 170
    invoke-direct {p1, p2}, Lla/l;-><init>(I)V

    .line 171
    .line 172
    .line 173
    iput-object p1, p0, Lla/l0;->h:Lla/l;

    .line 174
    .line 175
    new-instance p1, Lhu/q;

    .line 176
    .line 177
    iget-object p2, p0, Lla/l0;->g:[Ljava/lang/String;

    .line 178
    .line 179
    array-length p2, p2

    .line 180
    invoke-direct {p1, p2}, Lhu/q;-><init>(I)V

    .line 181
    .line 182
    .line 183
    iput-object p1, p0, Lla/l0;->i:Lhu/q;

    .line 184
    .line 185
    return-void
.end method

.method public static final a(Lla/l0;Lla/o;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lla/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lla/d0;

    .line 7
    .line 8
    iget v1, v0, Lla/d0;->g:I

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
    iput v1, v0, Lla/d0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lla/d0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lla/d0;-><init>(Lla/l0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lla/d0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lla/d0;->g:I

    .line 30
    .line 31
    const/4 v2, 0x2

    .line 32
    const/4 v3, 0x1

    .line 33
    if-eqz v1, :cond_3

    .line 34
    .line 35
    if-eq v1, v3, :cond_2

    .line 36
    .line 37
    if-ne v1, v2, :cond_1

    .line 38
    .line 39
    iget-object p1, v0, Lla/d0;->d:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Ljava/util/Set;

    .line 42
    .line 43
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-object p1

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object p1, v0, Lla/d0;->d:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Lla/o;

    .line 58
    .line 59
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    new-instance p0, Lkq0/a;

    .line 67
    .line 68
    const/16 v1, 0xa

    .line 69
    .line 70
    invoke-direct {p0, v1}, Lkq0/a;-><init>(I)V

    .line 71
    .line 72
    .line 73
    iput-object p1, v0, Lla/d0;->d:Ljava/lang/Object;

    .line 74
    .line 75
    iput v3, v0, Lla/d0;->g:I

    .line 76
    .line 77
    const-string v1, "SELECT * FROM room_table_modification_log WHERE invalidated = 1"

    .line 78
    .line 79
    invoke-interface {p1, v1, p0, v0}, Lla/o;->a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-ne p0, p2, :cond_4

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    :goto_1
    check-cast p0, Ljava/util/Set;

    .line 87
    .line 88
    move-object v1, p0

    .line 89
    check-cast v1, Ljava/util/Collection;

    .line 90
    .line 91
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-nez v1, :cond_5

    .line 96
    .line 97
    iput-object p0, v0, Lla/d0;->d:Ljava/lang/Object;

    .line 98
    .line 99
    iput v2, v0, Lla/d0;->g:I

    .line 100
    .line 101
    const-string v1, "UPDATE room_table_modification_log SET invalidated = 0 WHERE invalidated = 1"

    .line 102
    .line 103
    invoke-static {p1, v1, v0}, Llp/hf;->a(Lla/o;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    if-ne p1, p2, :cond_5

    .line 108
    .line 109
    :goto_2
    return-object p2

    .line 110
    :cond_5
    return-object p0
.end method

.method public static final b(Lla/l0;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lla/l0;->a:Lla/u;

    .line 2
    .line 3
    instance-of v1, p1, Lla/f0;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lla/f0;

    .line 9
    .line 10
    iget v2, v1, Lla/f0;->g:I

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
    iput v2, v1, Lla/f0;->g:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lla/f0;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lla/f0;-><init>(Lla/l0;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lla/f0;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lla/f0;->g:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    iget-object v0, v1, Lla/f0;->d:Lb81/c;

    .line 39
    .line 40
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p1, v0, Lla/u;->g:Lb81/c;

    .line 58
    .line 59
    invoke-virtual {p1}, Lb81/c;->h()Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    sget-object v5, Lmx0/u;->d:Lmx0/u;

    .line 64
    .line 65
    if-eqz v3, :cond_7

    .line 66
    .line 67
    :try_start_1
    iget-object v3, p0, Lla/l0;->j:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 68
    .line 69
    const/4 v6, 0x0

    .line 70
    invoke-virtual {v3, v4, v6}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 71
    .line 72
    .line 73
    move-result v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 74
    if-nez v3, :cond_3

    .line 75
    .line 76
    invoke-virtual {p1}, Lb81/c;->w()V

    .line 77
    .line 78
    .line 79
    return-object v5

    .line 80
    :cond_3
    :try_start_2
    iget-object v3, p0, Lla/l0;->k:Lay0/a;

    .line 81
    .line 82
    invoke-interface {v3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Ljava/lang/Boolean;

    .line 87
    .line 88
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 89
    .line 90
    .line 91
    move-result v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 92
    if-nez v3, :cond_4

    .line 93
    .line 94
    invoke-virtual {p1}, Lb81/c;->w()V

    .line 95
    .line 96
    .line 97
    return-object v5

    .line 98
    :cond_4
    :try_start_3
    new-instance v3, Lla/g0;

    .line 99
    .line 100
    const/4 v5, 0x0

    .line 101
    const/4 v7, 0x1

    .line 102
    invoke-direct {v3, p0, v5, v7}, Lla/g0;-><init>(Lla/l0;Lkotlin/coroutines/Continuation;I)V

    .line 103
    .line 104
    .line 105
    iput-object p1, v1, Lla/f0;->d:Lb81/c;

    .line 106
    .line 107
    iput v4, v1, Lla/f0;->g:I

    .line 108
    .line 109
    invoke-virtual {v0, v6, v3, v1}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 113
    if-ne v0, v2, :cond_5

    .line 114
    .line 115
    return-object v2

    .line 116
    :cond_5
    move-object v8, v0

    .line 117
    move-object v0, p1

    .line 118
    move-object p1, v8

    .line 119
    :goto_1
    :try_start_4
    check-cast p1, Ljava/util/Set;

    .line 120
    .line 121
    move-object v1, p1

    .line 122
    check-cast v1, Ljava/util/Collection;

    .line 123
    .line 124
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-nez v1, :cond_6

    .line 129
    .line 130
    iget-object v1, p0, Lla/l0;->i:Lhu/q;

    .line 131
    .line 132
    invoke-virtual {v1, p1}, Lhu/q;->E(Ljava/util/Set;)V

    .line 133
    .line 134
    .line 135
    iget-object p0, p0, Lla/l0;->e:Ll20/g;

    .line 136
    .line 137
    invoke-virtual {p0, p1}, Ll20/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 138
    .line 139
    .line 140
    :cond_6
    invoke-virtual {v0}, Lb81/c;->w()V

    .line 141
    .line 142
    .line 143
    return-object p1

    .line 144
    :catchall_1
    move-exception p0

    .line 145
    move-object v0, p1

    .line 146
    :goto_2
    invoke-virtual {v0}, Lb81/c;->w()V

    .line 147
    .line 148
    .line 149
    throw p0

    .line 150
    :cond_7
    return-object v5
.end method

.method public static final c(Lla/l0;Lla/c0;ILrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    instance-of v4, v3, Lla/h0;

    .line 13
    .line 14
    if-eqz v4, :cond_0

    .line 15
    .line 16
    move-object v4, v3

    .line 17
    check-cast v4, Lla/h0;

    .line 18
    .line 19
    iget v5, v4, Lla/h0;->l:I

    .line 20
    .line 21
    const/high16 v6, -0x80000000

    .line 22
    .line 23
    and-int v7, v5, v6

    .line 24
    .line 25
    if-eqz v7, :cond_0

    .line 26
    .line 27
    sub-int/2addr v5, v6

    .line 28
    iput v5, v4, Lla/h0;->l:I

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v4, Lla/h0;

    .line 32
    .line 33
    invoke-direct {v4, v0, v3}, Lla/h0;-><init>(Lla/l0;Lrx0/c;)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object v3, v4, Lla/h0;->j:Ljava/lang/Object;

    .line 37
    .line 38
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 39
    .line 40
    iget v6, v4, Lla/h0;->l:I

    .line 41
    .line 42
    const/4 v7, 0x2

    .line 43
    const/4 v8, 0x1

    .line 44
    if-eqz v6, :cond_3

    .line 45
    .line 46
    if-eq v6, v8, :cond_2

    .line 47
    .line 48
    if-ne v6, v7, :cond_1

    .line 49
    .line 50
    iget v1, v4, Lla/h0;->i:I

    .line 51
    .line 52
    iget v2, v4, Lla/h0;->h:I

    .line 53
    .line 54
    iget v6, v4, Lla/h0;->g:I

    .line 55
    .line 56
    iget-object v9, v4, Lla/h0;->f:[Ljava/lang/String;

    .line 57
    .line 58
    iget-object v10, v4, Lla/h0;->e:Ljava/lang/String;

    .line 59
    .line 60
    iget-object v11, v4, Lla/h0;->d:Lla/o;

    .line 61
    .line 62
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move/from16 p3, v8

    .line 66
    .line 67
    goto/16 :goto_5

    .line 68
    .line 69
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    iget v1, v4, Lla/h0;->g:I

    .line 78
    .line 79
    iget-object v2, v4, Lla/h0;->d:Lla/o;

    .line 80
    .line 81
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    move-object/from16 v16, v2

    .line 85
    .line 86
    move v2, v1

    .line 87
    move-object/from16 v1, v16

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_3
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    new-instance v3, Ljava/lang/StringBuilder;

    .line 94
    .line 95
    const-string v6, "INSERT OR IGNORE INTO room_table_modification_log VALUES("

    .line 96
    .line 97
    invoke-direct {v3, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v6, ", 0)"

    .line 104
    .line 105
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    iput-object v1, v4, Lla/h0;->d:Lla/o;

    .line 113
    .line 114
    iput v2, v4, Lla/h0;->g:I

    .line 115
    .line 116
    iput v8, v4, Lla/h0;->l:I

    .line 117
    .line 118
    invoke-static {v1, v3, v4}, Llp/hf;->a(Lla/o;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    if-ne v3, v5, :cond_4

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_4
    :goto_1
    iget-object v3, v0, Lla/l0;->g:[Ljava/lang/String;

    .line 126
    .line 127
    aget-object v3, v3, v2

    .line 128
    .line 129
    sget-object v6, Lla/l0;->l:[Ljava/lang/String;

    .line 130
    .line 131
    const/4 v9, 0x0

    .line 132
    const/4 v10, 0x3

    .line 133
    move-object v11, v6

    .line 134
    move v6, v2

    .line 135
    move v2, v9

    .line 136
    move-object v9, v11

    .line 137
    move-object v11, v1

    .line 138
    move v1, v10

    .line 139
    move-object v10, v3

    .line 140
    :goto_2
    if-ge v2, v1, :cond_7

    .line 141
    .line 142
    aget-object v3, v9, v2

    .line 143
    .line 144
    iget-boolean v12, v0, Lla/l0;->d:Z

    .line 145
    .line 146
    if-eqz v12, :cond_5

    .line 147
    .line 148
    const-string v12, "TEMP"

    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_5
    const-string v12, ""

    .line 152
    .line 153
    :goto_3
    new-instance v13, Ljava/lang/StringBuilder;

    .line 154
    .line 155
    const-string v14, "room_table_modification_trigger_"

    .line 156
    .line 157
    invoke-direct {v13, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    const/16 v14, 0x5f

    .line 164
    .line 165
    invoke-virtual {v13, v14}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v13, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v13

    .line 175
    const-string v14, " TRIGGER IF NOT EXISTS `"

    .line 176
    .line 177
    const-string v15, "` AFTER "

    .line 178
    .line 179
    move/from16 p3, v8

    .line 180
    .line 181
    const-string v8, "CREATE "

    .line 182
    .line 183
    invoke-static {v8, v12, v14, v13, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    const-string v12, " ON `"

    .line 188
    .line 189
    const-string v13, "` BEGIN UPDATE room_table_modification_log SET invalidated = 1 WHERE table_id = "

    .line 190
    .line 191
    invoke-static {v8, v3, v12, v10, v13}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    const-string v3, " AND invalidated = 0; END"

    .line 195
    .line 196
    invoke-static {v6, v3, v8}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v3

    .line 200
    iput-object v11, v4, Lla/h0;->d:Lla/o;

    .line 201
    .line 202
    iput-object v10, v4, Lla/h0;->e:Ljava/lang/String;

    .line 203
    .line 204
    iput-object v9, v4, Lla/h0;->f:[Ljava/lang/String;

    .line 205
    .line 206
    iput v6, v4, Lla/h0;->g:I

    .line 207
    .line 208
    iput v2, v4, Lla/h0;->h:I

    .line 209
    .line 210
    iput v1, v4, Lla/h0;->i:I

    .line 211
    .line 212
    iput v7, v4, Lla/h0;->l:I

    .line 213
    .line 214
    invoke-static {v11, v3, v4}, Llp/hf;->a(Lla/o;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v3

    .line 218
    if-ne v3, v5, :cond_6

    .line 219
    .line 220
    :goto_4
    return-object v5

    .line 221
    :cond_6
    :goto_5
    add-int/lit8 v2, v2, 0x1

    .line 222
    .line 223
    move/from16 v8, p3

    .line 224
    .line 225
    goto :goto_2

    .line 226
    :cond_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 227
    .line 228
    return-object v0
.end method

.method public static final d(Lla/l0;Lla/c0;ILrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p3, Lla/i0;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p3

    .line 9
    check-cast v0, Lla/i0;

    .line 10
    .line 11
    iget v1, v0, Lla/i0;->k:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lla/i0;->k:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lla/i0;

    .line 24
    .line 25
    invoke-direct {v0, p0, p3}, Lla/i0;-><init>(Lla/l0;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p3, v0, Lla/i0;->i:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lla/i0;->k:I

    .line 33
    .line 34
    const/4 v3, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget p0, v0, Lla/i0;->h:I

    .line 40
    .line 41
    iget p1, v0, Lla/i0;->g:I

    .line 42
    .line 43
    iget-object p2, v0, Lla/i0;->f:[Ljava/lang/String;

    .line 44
    .line 45
    iget-object v2, v0, Lla/i0;->e:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v4, v0, Lla/i0;->d:Lla/o;

    .line 48
    .line 49
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    move-object p3, p2

    .line 53
    move-object p2, v4

    .line 54
    goto :goto_2

    .line 55
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Lla/l0;->g:[Ljava/lang/String;

    .line 67
    .line 68
    aget-object p0, p0, p2

    .line 69
    .line 70
    sget-object p2, Lla/l0;->l:[Ljava/lang/String;

    .line 71
    .line 72
    const/4 p3, 0x0

    .line 73
    const/4 v2, 0x3

    .line 74
    move v7, v2

    .line 75
    move-object v2, p0

    .line 76
    move p0, v7

    .line 77
    move-object v7, p2

    .line 78
    move-object p2, p1

    .line 79
    move p1, p3

    .line 80
    move-object p3, v7

    .line 81
    :goto_1
    if-ge p1, p0, :cond_4

    .line 82
    .line 83
    aget-object v4, p3, p1

    .line 84
    .line 85
    new-instance v5, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string v6, "room_table_modification_trigger_"

    .line 88
    .line 89
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const/16 v6, 0x5f

    .line 96
    .line 97
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    const-string v5, "DROP TRIGGER IF EXISTS `"

    .line 108
    .line 109
    const/16 v6, 0x60

    .line 110
    .line 111
    invoke-static {v6, v5, v4}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    iput-object p2, v0, Lla/i0;->d:Lla/o;

    .line 116
    .line 117
    iput-object v2, v0, Lla/i0;->e:Ljava/lang/String;

    .line 118
    .line 119
    iput-object p3, v0, Lla/i0;->f:[Ljava/lang/String;

    .line 120
    .line 121
    iput p1, v0, Lla/i0;->g:I

    .line 122
    .line 123
    iput p0, v0, Lla/i0;->h:I

    .line 124
    .line 125
    iput v3, v0, Lla/i0;->k:I

    .line 126
    .line 127
    invoke-static {p2, v4, v0}, Llp/hf;->a(Lla/o;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    if-ne v4, v1, :cond_3

    .line 132
    .line 133
    return-object v1

    .line 134
    :cond_3
    :goto_2
    add-int/2addr p1, v3

    .line 135
    goto :goto_1

    .line 136
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0
.end method


# virtual methods
.method public final e(Lay0/a;Lay0/a;)V
    .locals 4

    .line 1
    const-string v0, "onRefreshScheduled"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onRefreshCompleted"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    const/4 v1, 0x1

    .line 13
    iget-object v2, p0, Lla/l0;->j:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    iget-object p1, p0, Lla/l0;->a:Lla/u;

    .line 25
    .line 26
    iget-object p1, p1, Lla/u;->a:Lpw0/a;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    new-instance v1, Lvy0/a0;

    .line 32
    .line 33
    const-string v2, "Room Invalidation Tracker Refresh"

    .line 34
    .line 35
    invoke-direct {v1, v2}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance v2, Lk31/t;

    .line 39
    .line 40
    const/16 v3, 0xe

    .line 41
    .line 42
    invoke-direct {v2, v3, p0, p2, v0}, Lk31/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x2

    .line 46
    invoke-static {p1, v1, v0, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_0
    const-string p0, "coroutineScope"

    .line 51
    .line 52
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw v0

    .line 56
    :cond_1
    return-void
.end method

.method public final f(Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lla/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lla/j0;

    .line 7
    .line 8
    iget v1, v0, Lla/j0;->g:I

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
    iput v1, v0, Lla/j0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lla/j0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lla/j0;-><init>(Lla/l0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lla/j0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lla/j0;->g:I

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
    iget-object p0, v0, Lla/j0;->d:Lb81/c;

    .line 37
    .line 38
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catchall_0
    move-exception p1

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object p1, p0, Lla/l0;->a:Lla/u;

    .line 56
    .line 57
    iget-object v2, p1, Lla/u;->g:Lb81/c;

    .line 58
    .line 59
    invoke-virtual {v2}, Lb81/c;->h()Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_4

    .line 64
    .line 65
    :try_start_1
    new-instance v4, Lk31/l;

    .line 66
    .line 67
    const/4 v5, 0x0

    .line 68
    const/16 v6, 0xd

    .line 69
    .line 70
    invoke-direct {v4, p0, v5, v6}, Lk31/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 71
    .line 72
    .line 73
    iput-object v2, v0, Lla/j0;->d:Lb81/c;

    .line 74
    .line 75
    iput v3, v0, Lla/j0;->g:I

    .line 76
    .line 77
    const/4 p0, 0x0

    .line 78
    invoke-virtual {p1, p0, v4, v0}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 82
    if-ne p0, v1, :cond_3

    .line 83
    .line 84
    return-object v1

    .line 85
    :cond_3
    move-object p0, v2

    .line 86
    :goto_1
    invoke-virtual {p0}, Lb81/c;->w()V

    .line 87
    .line 88
    .line 89
    goto :goto_3

    .line 90
    :catchall_1
    move-exception p1

    .line 91
    move-object p0, v2

    .line 92
    :goto_2
    invoke-virtual {p0}, Lb81/c;->w()V

    .line 93
    .line 94
    .line 95
    throw p1

    .line 96
    :cond_4
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0
.end method
