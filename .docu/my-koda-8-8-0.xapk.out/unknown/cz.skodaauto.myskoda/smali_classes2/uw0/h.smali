.class public final Luw0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lvz0/d;

.field public final b:Ljava/util/LinkedHashMap;


# direct methods
.method public constructor <init>(Lvz0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luw0/h;->a:Lvz0/d;

    .line 5
    .line 6
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Luw0/h;->b:Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    return-void
.end method

.method public static final a(Luw0/h;Lyy0/i;Lqz0/a;Ljava/nio/charset/Charset;Lio/ktor/utils/io/d0;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object/from16 v1, p4

    .line 2
    .line 3
    move-object/from16 v2, p5

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    instance-of v4, v2, Luw0/g;

    .line 9
    .line 10
    if-eqz v4, :cond_0

    .line 11
    .line 12
    move-object v4, v2

    .line 13
    check-cast v4, Luw0/g;

    .line 14
    .line 15
    iget v5, v4, Luw0/g;->k:I

    .line 16
    .line 17
    const/high16 v6, -0x80000000

    .line 18
    .line 19
    and-int v7, v5, v6

    .line 20
    .line 21
    if-eqz v7, :cond_0

    .line 22
    .line 23
    sub-int/2addr v5, v6

    .line 24
    iput v5, v4, Luw0/g;->k:I

    .line 25
    .line 26
    :goto_0
    move-object v6, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    new-instance v4, Luw0/g;

    .line 29
    .line 30
    invoke-direct {v4, p0, v2}, Luw0/g;-><init>(Luw0/h;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :goto_1
    iget-object v2, v6, Luw0/g;->i:Ljava/lang/Object;

    .line 35
    .line 36
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    iget v4, v6, Luw0/g;->k:I

    .line 39
    .line 40
    const/4 v8, 0x3

    .line 41
    const/4 v9, 0x2

    .line 42
    const/4 v5, 0x1

    .line 43
    const/4 v10, 0x0

    .line 44
    if-eqz v4, :cond_4

    .line 45
    .line 46
    if-eq v4, v5, :cond_3

    .line 47
    .line 48
    if-eq v4, v9, :cond_2

    .line 49
    .line 50
    if-ne v4, v8, :cond_1

    .line 51
    .line 52
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto/16 :goto_5

    .line 56
    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    iget-object v0, v6, Luw0/g;->h:Luw0/a;

    .line 66
    .line 67
    iget-object v1, v6, Luw0/g;->g:Lio/ktor/utils/io/d0;

    .line 68
    .line 69
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto/16 :goto_3

    .line 73
    .line 74
    :cond_3
    iget-object v0, v6, Luw0/g;->h:Luw0/a;

    .line 75
    .line 76
    iget-object v1, v6, Luw0/g;->g:Lio/ktor/utils/io/d0;

    .line 77
    .line 78
    iget-object v4, v6, Luw0/g;->f:Ljava/nio/charset/Charset;

    .line 79
    .line 80
    iget-object v5, v6, Luw0/g;->e:Lqz0/a;

    .line 81
    .line 82
    check-cast v5, Lqz0/a;

    .line 83
    .line 84
    iget-object v11, v6, Luw0/g;->d:Lyy0/i;

    .line 85
    .line 86
    check-cast v11, Lyy0/i;

    .line 87
    .line 88
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object v2, v5

    .line 92
    move-object v5, v4

    .line 93
    move-object v4, v2

    .line 94
    move-object v2, v0

    .line 95
    goto :goto_2

    .line 96
    :cond_4
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object v2, p0, Luw0/h;->b:Ljava/util/LinkedHashMap;

    .line 100
    .line 101
    invoke-virtual {v2, p3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    if-nez v4, :cond_5

    .line 106
    .line 107
    new-instance v4, Luw0/a;

    .line 108
    .line 109
    invoke-direct {v4, p3}, Luw0/a;-><init>(Ljava/nio/charset/Charset;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v2, p3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    :cond_5
    move-object v2, v4

    .line 116
    check-cast v2, Luw0/a;

    .line 117
    .line 118
    iget-object v4, v2, Luw0/a;->a:[B

    .line 119
    .line 120
    move-object v11, p1

    .line 121
    check-cast v11, Lyy0/i;

    .line 122
    .line 123
    iput-object v11, v6, Luw0/g;->d:Lyy0/i;

    .line 124
    .line 125
    move-object v11, p2

    .line 126
    check-cast v11, Lqz0/a;

    .line 127
    .line 128
    iput-object v11, v6, Luw0/g;->e:Lqz0/a;

    .line 129
    .line 130
    iput-object p3, v6, Luw0/g;->f:Ljava/nio/charset/Charset;

    .line 131
    .line 132
    iput-object v1, v6, Luw0/g;->g:Lio/ktor/utils/io/d0;

    .line 133
    .line 134
    iput-object v2, v6, Luw0/g;->h:Luw0/a;

    .line 135
    .line 136
    iput v5, v6, Luw0/g;->k:I

    .line 137
    .line 138
    invoke-static {v1, v4, v6}, Lio/ktor/utils/io/h0;->o(Lio/ktor/utils/io/d0;[BLrx0/c;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v4

    .line 142
    if-ne v4, v7, :cond_6

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_6
    move-object v11, p1

    .line 146
    move-object v4, p2

    .line 147
    move-object v5, p3

    .line 148
    :goto_2
    new-instance v0, Luw0/f;

    .line 149
    .line 150
    move-object v3, p0

    .line 151
    invoke-direct/range {v0 .. v5}, Luw0/f;-><init>(Lio/ktor/utils/io/d0;Luw0/a;Luw0/h;Lqz0/a;Ljava/nio/charset/Charset;)V

    .line 152
    .line 153
    .line 154
    iput-object v10, v6, Luw0/g;->d:Lyy0/i;

    .line 155
    .line 156
    iput-object v10, v6, Luw0/g;->e:Lqz0/a;

    .line 157
    .line 158
    iput-object v10, v6, Luw0/g;->f:Ljava/nio/charset/Charset;

    .line 159
    .line 160
    iput-object v1, v6, Luw0/g;->g:Lio/ktor/utils/io/d0;

    .line 161
    .line 162
    iput-object v2, v6, Luw0/g;->h:Luw0/a;

    .line 163
    .line 164
    iput v9, v6, Luw0/g;->k:I

    .line 165
    .line 166
    invoke-interface {v11, v0, v6}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    if-ne v0, v7, :cond_7

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_7
    move-object v0, v2

    .line 174
    :goto_3
    iget-object v0, v0, Luw0/a;->b:[B

    .line 175
    .line 176
    iput-object v10, v6, Luw0/g;->d:Lyy0/i;

    .line 177
    .line 178
    iput-object v10, v6, Luw0/g;->e:Lqz0/a;

    .line 179
    .line 180
    iput-object v10, v6, Luw0/g;->f:Ljava/nio/charset/Charset;

    .line 181
    .line 182
    iput-object v10, v6, Luw0/g;->g:Lio/ktor/utils/io/d0;

    .line 183
    .line 184
    iput-object v10, v6, Luw0/g;->h:Luw0/a;

    .line 185
    .line 186
    iput v8, v6, Luw0/g;->k:I

    .line 187
    .line 188
    invoke-static {v1, v0, v6}, Lio/ktor/utils/io/h0;->o(Lio/ktor/utils/io/d0;[BLrx0/c;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    if-ne v0, v7, :cond_8

    .line 193
    .line 194
    :goto_4
    return-object v7

    .line 195
    :cond_8
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 196
    .line 197
    return-object v0
.end method


# virtual methods
.method public final b(Ljava/nio/charset/Charset;Lzw0/a;Lio/ktor/utils/io/t;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p4, Luw0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Luw0/d;

    .line 7
    .line 8
    iget v1, v0, Luw0/d;->f:I

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
    iput v1, v0, Luw0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luw0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Luw0/d;-><init>(Luw0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Luw0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luw0/d;->f:I

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
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    .line 38
    .line 39
    return-object p4

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p4, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 52
    .line 53
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    const/4 v9, 0x0

    .line 58
    if-eqz p1, :cond_5

    .line 59
    .line 60
    iget-object p1, p2, Lzw0/a;->a:Lhy0/d;

    .line 61
    .line 62
    const-class p4, Lky0/j;

    .line 63
    .line 64
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 65
    .line 66
    invoke-virtual {v2, p4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 67
    .line 68
    .line 69
    move-result-object p4

    .line 70
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    if-nez p1, :cond_3

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_3
    :try_start_1
    iget-object v8, p0, Luw0/h;->a:Lvz0/d;

    .line 78
    .line 79
    iput v3, v0, Luw0/d;->f:I

    .line 80
    .line 81
    sget-object p0, Lvy0/p0;->a:Lcz0/e;

    .line 82
    .line 83
    sget-object p0, Lcz0/d;->e:Lcz0/d;

    .line 84
    .line 85
    new-instance v4, Lqh/a;

    .line 86
    .line 87
    const/16 v5, 0x9

    .line 88
    .line 89
    move-object v7, p2

    .line 90
    move-object v6, p3

    .line 91
    invoke-direct/range {v4 .. v9}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 92
    .line 93
    .line 94
    invoke-static {p0, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 98
    if-ne p0, v1, :cond_4

    .line 99
    .line 100
    return-object v1

    .line 101
    :cond_4
    return-object p0

    .line 102
    :catchall_0
    move-exception v0

    .line 103
    move-object p0, v0

    .line 104
    new-instance p1, Lsw0/f;

    .line 105
    .line 106
    new-instance p2, Ljava/lang/StringBuilder;

    .line 107
    .line 108
    const-string p3, "Illegal input: "

    .line 109
    .line 110
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p3

    .line 117
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p2

    .line 124
    invoke-direct {p1, p2, p0}, Lsw0/f;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 125
    .line 126
    .line 127
    throw p1

    .line 128
    :cond_5
    :goto_1
    return-object v9
.end method
