.class public final Liu/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Liu/c;

.field public static final b:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Liu/c;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Liu/c;->a:Liu/c;

    .line 7
    .line 8
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Liu/c;->b:Ljava/util/Map;

    .line 18
    .line 19
    return-void
.end method

.method public static a(Liu/d;)Liu/a;
    .locals 3

    .line 1
    const-string v0, "dependencies"

    .line 2
    .line 3
    sget-object v1, Liu/c;->b:Ljava/util/Map;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {v1, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    check-cast v0, Liu/a;

    .line 15
    .line 16
    return-object v0

    .line 17
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    new-instance v1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v2, "Cannot get dependency "

    .line 22
    .line 23
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p0, ". Dependencies should be added at class load time."

    .line 30
    .line 31
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw v0
.end method


# virtual methods
.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Liu/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Liu/b;

    .line 7
    .line 8
    iget v1, v0, Liu/b;->l:I

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
    iput v1, v0, Liu/b;->l:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Liu/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Liu/b;-><init>(Liu/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Liu/b;->j:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Liu/b;->l:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget-object v1, v0, Liu/b;->i:Ljava/lang/Object;

    .line 37
    .line 38
    iget-object v3, v0, Liu/b;->h:Ljava/util/Map;

    .line 39
    .line 40
    iget-object v4, v0, Liu/b;->g:Lez0/c;

    .line 41
    .line 42
    iget-object v5, v0, Liu/b;->f:Liu/d;

    .line 43
    .line 44
    iget-object v6, v0, Liu/b;->e:Ljava/util/Iterator;

    .line 45
    .line 46
    iget-object v7, v0, Liu/b;->d:Ljava/util/Map;

    .line 47
    .line 48
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    const-string p0, "dependencies"

    .line 64
    .line 65
    sget-object v1, Liu/c;->b:Ljava/util/Map;

    .line 66
    .line 67
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 71
    .line 72
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    invoke-static {v3}, Lmx0/x;->k(I)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    invoke-direct {p0, v3}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    check-cast v1, Ljava/lang/Iterable;

    .line 88
    .line 89
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    move-object v3, p0

    .line 94
    move-object v6, v1

    .line 95
    :goto_1
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-eqz p0, :cond_5

    .line 100
    .line 101
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Ljava/util/Map$Entry;

    .line 106
    .line 107
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    move-object v5, v4

    .line 116
    check-cast v5, Liu/d;

    .line 117
    .line 118
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    check-cast p0, Liu/a;

    .line 123
    .line 124
    iget-object v4, p0, Liu/a;->a:Lez0/c;

    .line 125
    .line 126
    iput-object v3, v0, Liu/b;->d:Ljava/util/Map;

    .line 127
    .line 128
    iput-object v6, v0, Liu/b;->e:Ljava/util/Iterator;

    .line 129
    .line 130
    iput-object v5, v0, Liu/b;->f:Liu/d;

    .line 131
    .line 132
    iput-object v4, v0, Liu/b;->g:Lez0/c;

    .line 133
    .line 134
    iput-object v3, v0, Liu/b;->h:Ljava/util/Map;

    .line 135
    .line 136
    iput-object v1, v0, Liu/b;->i:Ljava/lang/Object;

    .line 137
    .line 138
    iput v2, v0, Liu/b;->l:I

    .line 139
    .line 140
    invoke-virtual {v4, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-ne p0, p1, :cond_3

    .line 145
    .line 146
    return-object p1

    .line 147
    :cond_3
    move-object v7, v3

    .line 148
    :goto_2
    const/4 p0, 0x0

    .line 149
    :try_start_0
    const-string v8, "subscriberName"

    .line 150
    .line 151
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    invoke-static {v5}, Liu/c;->a(Liu/d;)Liu/a;

    .line 155
    .line 156
    .line 157
    move-result-object v8

    .line 158
    iget-object v8, v8, Liu/a;->b:Lms/i;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 159
    .line 160
    if-eqz v8, :cond_4

    .line 161
    .line 162
    invoke-interface {v4, p0}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    invoke-interface {v3, v1, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-object v3, v7

    .line 169
    goto :goto_1

    .line 170
    :cond_4
    :try_start_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    new-instance v0, Ljava/lang/StringBuilder;

    .line 173
    .line 174
    const-string v1, "Subscriber "

    .line 175
    .line 176
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    const-string v1, " has not been registered."

    .line 183
    .line 184
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 195
    :catchall_0
    move-exception p1

    .line 196
    invoke-interface {v4, p0}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    throw p1

    .line 200
    :cond_5
    return-object v3
.end method
