.class public final Ld01/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ljava/util/List;

.field public static final f:Ljava/util/List;

.field public static final g:Ld01/p;

.field public static final h:Ld01/p;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:[Ljava/lang/String;

.field public final d:[Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 18

    .line 1
    sget-object v0, Ld01/n;->r:Ld01/n;

    .line 2
    .line 3
    sget-object v1, Ld01/n;->s:Ld01/n;

    .line 4
    .line 5
    sget-object v2, Ld01/n;->t:Ld01/n;

    .line 6
    .line 7
    sget-object v3, Ld01/n;->l:Ld01/n;

    .line 8
    .line 9
    sget-object v4, Ld01/n;->n:Ld01/n;

    .line 10
    .line 11
    sget-object v5, Ld01/n;->m:Ld01/n;

    .line 12
    .line 13
    sget-object v6, Ld01/n;->o:Ld01/n;

    .line 14
    .line 15
    sget-object v7, Ld01/n;->q:Ld01/n;

    .line 16
    .line 17
    sget-object v8, Ld01/n;->p:Ld01/n;

    .line 18
    .line 19
    filled-new-array/range {v0 .. v8}, [Ld01/n;

    .line 20
    .line 21
    .line 22
    move-result-object v9

    .line 23
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object v17

    .line 27
    sput-object v17, Ld01/p;->e:Ljava/util/List;

    .line 28
    .line 29
    sget-object v10, Ld01/n;->j:Ld01/n;

    .line 30
    .line 31
    sget-object v11, Ld01/n;->k:Ld01/n;

    .line 32
    .line 33
    sget-object v12, Ld01/n;->h:Ld01/n;

    .line 34
    .line 35
    sget-object v13, Ld01/n;->i:Ld01/n;

    .line 36
    .line 37
    sget-object v14, Ld01/n;->f:Ld01/n;

    .line 38
    .line 39
    sget-object v15, Ld01/n;->g:Ld01/n;

    .line 40
    .line 41
    sget-object v16, Ld01/n;->e:Ld01/n;

    .line 42
    .line 43
    move-object v9, v8

    .line 44
    move-object v8, v7

    .line 45
    move-object v7, v6

    .line 46
    move-object v6, v5

    .line 47
    move-object v5, v4

    .line 48
    move-object v4, v3

    .line 49
    move-object v3, v2

    .line 50
    move-object v2, v1

    .line 51
    move-object v1, v0

    .line 52
    filled-new-array/range {v1 .. v16}, [Ld01/n;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    sput-object v0, Ld01/p;->f:Ljava/util/List;

    .line 61
    .line 62
    new-instance v1, Ld01/o;

    .line 63
    .line 64
    invoke-direct {v1}, Ld01/o;-><init>()V

    .line 65
    .line 66
    .line 67
    move-object/from16 v2, v17

    .line 68
    .line 69
    check-cast v2, Ljava/util/Collection;

    .line 70
    .line 71
    const/4 v3, 0x0

    .line 72
    new-array v4, v3, [Ld01/n;

    .line 73
    .line 74
    invoke-interface {v2, v4}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, [Ld01/n;

    .line 79
    .line 80
    array-length v4, v2

    .line 81
    invoke-static {v2, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    check-cast v2, [Ld01/n;

    .line 86
    .line 87
    invoke-virtual {v1, v2}, Ld01/o;->b([Ld01/n;)V

    .line 88
    .line 89
    .line 90
    sget-object v2, Ld01/x0;->f:Ld01/x0;

    .line 91
    .line 92
    sget-object v4, Ld01/x0;->g:Ld01/x0;

    .line 93
    .line 94
    filled-new-array {v2, v4}, [Ld01/x0;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    invoke-virtual {v1, v5}, Ld01/o;->d([Ld01/x0;)V

    .line 99
    .line 100
    .line 101
    const/4 v5, 0x1

    .line 102
    iput-boolean v5, v1, Ld01/o;->b:Z

    .line 103
    .line 104
    invoke-virtual {v1}, Ld01/o;->a()Ld01/p;

    .line 105
    .line 106
    .line 107
    new-instance v1, Ld01/o;

    .line 108
    .line 109
    invoke-direct {v1}, Ld01/o;-><init>()V

    .line 110
    .line 111
    .line 112
    check-cast v0, Ljava/util/Collection;

    .line 113
    .line 114
    new-array v6, v3, [Ld01/n;

    .line 115
    .line 116
    invoke-interface {v0, v6}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    check-cast v6, [Ld01/n;

    .line 121
    .line 122
    array-length v7, v6

    .line 123
    invoke-static {v6, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    check-cast v6, [Ld01/n;

    .line 128
    .line 129
    invoke-virtual {v1, v6}, Ld01/o;->b([Ld01/n;)V

    .line 130
    .line 131
    .line 132
    filled-new-array {v2, v4}, [Ld01/x0;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    invoke-virtual {v1, v6}, Ld01/o;->d([Ld01/x0;)V

    .line 137
    .line 138
    .line 139
    iput-boolean v5, v1, Ld01/o;->b:Z

    .line 140
    .line 141
    invoke-virtual {v1}, Ld01/o;->a()Ld01/p;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    sput-object v1, Ld01/p;->g:Ld01/p;

    .line 146
    .line 147
    new-instance v1, Ld01/o;

    .line 148
    .line 149
    invoke-direct {v1}, Ld01/o;-><init>()V

    .line 150
    .line 151
    .line 152
    new-array v6, v3, [Ld01/n;

    .line 153
    .line 154
    invoke-interface {v0, v6}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    check-cast v0, [Ld01/n;

    .line 159
    .line 160
    array-length v6, v0

    .line 161
    invoke-static {v0, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    check-cast v0, [Ld01/n;

    .line 166
    .line 167
    invoke-virtual {v1, v0}, Ld01/o;->b([Ld01/n;)V

    .line 168
    .line 169
    .line 170
    sget-object v0, Ld01/x0;->h:Ld01/x0;

    .line 171
    .line 172
    sget-object v6, Ld01/x0;->i:Ld01/x0;

    .line 173
    .line 174
    filled-new-array {v2, v4, v0, v6}, [Ld01/x0;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    invoke-virtual {v1, v0}, Ld01/o;->d([Ld01/x0;)V

    .line 179
    .line 180
    .line 181
    iput-boolean v5, v1, Ld01/o;->b:Z

    .line 182
    .line 183
    invoke-virtual {v1}, Ld01/o;->a()Ld01/p;

    .line 184
    .line 185
    .line 186
    new-instance v0, Ld01/p;

    .line 187
    .line 188
    const/4 v1, 0x0

    .line 189
    invoke-direct {v0, v3, v3, v1, v1}, Ld01/p;-><init>(ZZ[Ljava/lang/String;[Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    sput-object v0, Ld01/p;->h:Ld01/p;

    .line 193
    .line 194
    return-void
.end method

.method public constructor <init>(ZZ[Ljava/lang/String;[Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Ld01/p;->a:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Ld01/p;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Ld01/p;->c:[Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Ld01/p;->d:[Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljavax/net/ssl/SSLSocket;Z)V
    .locals 11

    .line 1
    invoke-virtual {p1}, Ljavax/net/ssl/SSLSocket;->getEnabledCipherSuites()[Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ld01/p;->c:[Ljava/lang/String;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    sget-object v2, Ld01/n;->c:Ld01/m;

    .line 13
    .line 14
    invoke-static {v1, v0, v2}, Le01/e;->l([Ljava/lang/String;[Ljava/lang/String;Ljava/util/Comparator;)[Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :cond_0
    iget-object v2, p0, Ld01/p;->d:[Ljava/lang/String;

    .line 19
    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {p1}, Ljavax/net/ssl/SSLSocket;->getEnabledProtocols()[Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    const-string v4, "getEnabledProtocols(...)"

    .line 27
    .line 28
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    sget-object v4, Lox0/a;->e:Lox0/a;

    .line 32
    .line 33
    invoke-static {v3, v2, v4}, Le01/e;->l([Ljava/lang/String;[Ljava/lang/String;Ljava/util/Comparator;)[Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    invoke-virtual {p1}, Ljavax/net/ssl/SSLSocket;->getEnabledProtocols()[Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    :goto_0
    invoke-virtual {p1}, Ljavax/net/ssl/SSLSocket;->getSupportedCipherSuites()[Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    sget-object v5, Ld01/n;->c:Ld01/m;

    .line 50
    .line 51
    sget-object v6, Le01/e;->a:[B

    .line 52
    .line 53
    array-length v6, v4

    .line 54
    const/4 v7, 0x0

    .line 55
    :goto_1
    const/4 v8, -0x1

    .line 56
    if-ge v7, v6, :cond_3

    .line 57
    .line 58
    aget-object v9, v4, v7

    .line 59
    .line 60
    const-string v10, "TLS_FALLBACK_SCSV"

    .line 61
    .line 62
    invoke-virtual {v5, v9, v10}, Ld01/m;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    if-nez v9, :cond_2

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_2
    add-int/lit8 v7, v7, 0x1

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_3
    move v7, v8

    .line 73
    :goto_2
    if-eqz p2, :cond_4

    .line 74
    .line 75
    if-eq v7, v8, :cond_4

    .line 76
    .line 77
    aget-object p2, v4, v7

    .line 78
    .line 79
    const-string v4, "get(...)"

    .line 80
    .line 81
    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    const-string v4, "<this>"

    .line 85
    .line 86
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    array-length v4, v0

    .line 90
    add-int/lit8 v4, v4, 0x1

    .line 91
    .line 92
    invoke-static {v0, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    const-string v4, "copyOf(...)"

    .line 97
    .line 98
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    check-cast v0, [Ljava/lang/String;

    .line 102
    .line 103
    array-length v4, v0

    .line 104
    add-int/lit8 v4, v4, -0x1

    .line 105
    .line 106
    aput-object p2, v0, v4

    .line 107
    .line 108
    :cond_4
    new-instance p2, Ld01/o;

    .line 109
    .line 110
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 111
    .line 112
    .line 113
    iget-boolean v4, p0, Ld01/p;->a:Z

    .line 114
    .line 115
    iput-boolean v4, p2, Ld01/o;->a:Z

    .line 116
    .line 117
    iput-object v1, p2, Ld01/o;->c:Ljava/lang/Object;

    .line 118
    .line 119
    iput-object v2, p2, Ld01/o;->d:Ljava/io/Serializable;

    .line 120
    .line 121
    iget-boolean p0, p0, Ld01/p;->b:Z

    .line 122
    .line 123
    iput-boolean p0, p2, Ld01/o;->b:Z

    .line 124
    .line 125
    array-length p0, v0

    .line 126
    invoke-static {v0, p0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    check-cast p0, [Ljava/lang/String;

    .line 131
    .line 132
    invoke-virtual {p2, p0}, Ld01/o;->c([Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    array-length p0, v3

    .line 136
    invoke-static {v3, p0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    check-cast p0, [Ljava/lang/String;

    .line 141
    .line 142
    invoke-virtual {p2, p0}, Ld01/o;->e([Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p2}, Ld01/o;->a()Ld01/p;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-virtual {p0}, Ld01/p;->c()Ljava/util/ArrayList;

    .line 150
    .line 151
    .line 152
    move-result-object p2

    .line 153
    if-eqz p2, :cond_5

    .line 154
    .line 155
    iget-object p2, p0, Ld01/p;->d:[Ljava/lang/String;

    .line 156
    .line 157
    invoke-virtual {p1, p2}, Ljavax/net/ssl/SSLSocket;->setEnabledProtocols([Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    :cond_5
    invoke-virtual {p0}, Ld01/p;->b()Ljava/util/ArrayList;

    .line 161
    .line 162
    .line 163
    move-result-object p2

    .line 164
    if-eqz p2, :cond_6

    .line 165
    .line 166
    iget-object p0, p0, Ld01/p;->c:[Ljava/lang/String;

    .line 167
    .line 168
    invoke-virtual {p1, p0}, Ljavax/net/ssl/SSLSocket;->setEnabledCipherSuites([Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    :cond_6
    return-void
.end method

.method public final b()Ljava/util/ArrayList;
    .locals 5

    .line 1
    iget-object p0, p0, Ld01/p;->c:[Ljava/lang/String;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    array-length v1, p0

    .line 8
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 9
    .line 10
    .line 11
    array-length v1, p0

    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_0

    .line 14
    .line 15
    aget-object v3, p0, v2

    .line 16
    .line 17
    sget-object v4, Ld01/n;->b:Ld01/r;

    .line 18
    .line 19
    invoke-virtual {v4, v3}, Ld01/r;->c(Ljava/lang/String;)Ld01/n;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    add-int/lit8 v2, v2, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    return-object v0

    .line 30
    :cond_1
    const/4 p0, 0x0

    .line 31
    return-object p0
.end method

.method public final c()Ljava/util/ArrayList;
    .locals 5

    .line 1
    iget-object p0, p0, Ld01/p;->d:[Ljava/lang/String;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    array-length v1, p0

    .line 8
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 9
    .line 10
    .line 11
    array-length v1, p0

    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_0

    .line 14
    .line 15
    aget-object v3, p0, v2

    .line 16
    .line 17
    sget-object v4, Ld01/x0;->e:Ld01/r;

    .line 18
    .line 19
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {v3}, Ld01/r;->d(Ljava/lang/String;)Ld01/x0;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    return-object v0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Ld01/p;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    if-ne p1, p0, :cond_1

    .line 7
    .line 8
    goto :goto_1

    .line 9
    :cond_1
    check-cast p1, Ld01/p;

    .line 10
    .line 11
    iget-boolean v0, p1, Ld01/p;->a:Z

    .line 12
    .line 13
    iget-boolean v1, p0, Ld01/p;->a:Z

    .line 14
    .line 15
    if-eq v1, v0, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    if-eqz v1, :cond_5

    .line 19
    .line 20
    iget-object v0, p0, Ld01/p;->c:[Ljava/lang/String;

    .line 21
    .line 22
    iget-object v1, p1, Ld01/p;->c:[Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_3

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_3
    iget-object v0, p0, Ld01/p;->d:[Ljava/lang/String;

    .line 32
    .line 33
    iget-object v1, p1, Ld01/p;->d:[Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v0, v1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_4

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_4
    iget-boolean p0, p0, Ld01/p;->b:Z

    .line 43
    .line 44
    iget-boolean p1, p1, Ld01/p;->b:Z

    .line 45
    .line 46
    if-eq p0, p1, :cond_5

    .line 47
    .line 48
    :goto_0
    const/4 p0, 0x0

    .line 49
    return p0

    .line 50
    :cond_5
    :goto_1
    const/4 p0, 0x1

    .line 51
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ld01/p;->a:Z

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iget-object v1, p0, Ld01/p;->c:[Ljava/lang/String;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    invoke-static {v1}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v1, v0

    .line 16
    :goto_0
    const/16 v2, 0x20f

    .line 17
    .line 18
    add-int/2addr v2, v1

    .line 19
    mul-int/lit8 v2, v2, 0x1f

    .line 20
    .line 21
    iget-object v1, p0, Ld01/p;->d:[Ljava/lang/String;

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    invoke-static {v1}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    :cond_1
    add-int/2addr v2, v0

    .line 30
    mul-int/lit8 v2, v2, 0x1f

    .line 31
    .line 32
    iget-boolean p0, p0, Ld01/p;->b:Z

    .line 33
    .line 34
    xor-int/lit8 p0, p0, 0x1

    .line 35
    .line 36
    add-int/2addr v2, p0

    .line 37
    return v2

    .line 38
    :cond_2
    const/16 p0, 0x11

    .line 39
    .line 40
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-boolean v0, p0, Ld01/p;->a:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string p0, "ConnectionSpec()"

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "ConnectionSpec(cipherSuites="

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ld01/p;->b()Ljava/util/ArrayList;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "[all enabled]"

    .line 20
    .line 21
    invoke-static {v1, v2}, Ljava/util/Objects;->toString(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", tlsVersions="

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Ld01/p;->c()Ljava/util/ArrayList;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-static {v1, v2}, Ljava/util/Objects;->toString(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", supportsTlsExtensions="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-boolean p0, p0, Ld01/p;->b:Z

    .line 50
    .line 51
    const/16 v1, 0x29

    .line 52
    .line 53
    invoke-static {v0, p0, v1}, Lf2/m0;->l(Ljava/lang/StringBuilder;ZC)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method
