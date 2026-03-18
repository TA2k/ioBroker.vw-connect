.class public final Lca/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf8/l;


# instance fields
.field public d:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lca/d;->d:Landroid/content/Context;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a()Lrn/k;
    .locals 12

    .line 1
    iget-object p0, p0, Lca/d;->d:Landroid/content/Context;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lrn/k;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    sget-object v1, Lrn/n;->a:Lrb0/a;

    .line 11
    .line 12
    invoke-static {v1}, Ltn/a;->a(Ltn/b;)Lkx0/a;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iput-object v1, v0, Lrn/k;->d:Lkx0/a;

    .line 17
    .line 18
    new-instance v1, Ld8/c;

    .line 19
    .line 20
    invoke-direct {v1, p0}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iput-object v1, v0, Lrn/k;->e:Ld8/c;

    .line 24
    .line 25
    new-instance p0, Lj1/a;

    .line 26
    .line 27
    const/16 v2, 0x1d

    .line 28
    .line 29
    invoke-direct {p0, v1, v2}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    new-instance v2, Lb81/b;

    .line 33
    .line 34
    const/16 v3, 0x17

    .line 35
    .line 36
    invoke-direct {v2, v3, v1, p0}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v2}, Ltn/a;->a(Ltn/b;)Lkx0/a;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    iput-object p0, v0, Lrn/k;->f:Lkx0/a;

    .line 44
    .line 45
    iget-object p0, v0, Lrn/k;->e:Ld8/c;

    .line 46
    .line 47
    new-instance v1, Lhu/g0;

    .line 48
    .line 49
    const/4 v2, 0x1

    .line 50
    invoke-direct {v1, p0, v2}, Lhu/g0;-><init>(Lkx0/a;I)V

    .line 51
    .line 52
    .line 53
    iput-object v1, v0, Lrn/k;->g:Lhu/g0;

    .line 54
    .line 55
    new-instance v1, Lyn/e;

    .line 56
    .line 57
    invoke-direct {v1, p0}, Lyn/e;-><init>(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v1}, Ltn/a;->a(Ltn/b;)Lkx0/a;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    iget-object v1, v0, Lrn/k;->g:Lhu/g0;

    .line 65
    .line 66
    new-instance v2, Lyn/i;

    .line 67
    .line 68
    invoke-direct {v2, v1, p0}, Lyn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    invoke-static {v2}, Ltn/a;->a(Ltn/b;)Lkx0/a;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    iput-object v5, v0, Lrn/k;->h:Lkx0/a;

    .line 76
    .line 77
    new-instance p0, Lpy/a;

    .line 78
    .line 79
    const/16 v1, 0x19

    .line 80
    .line 81
    invoke-direct {p0, v1}, Lpy/a;-><init>(I)V

    .line 82
    .line 83
    .line 84
    iget-object v1, v0, Lrn/k;->e:Ld8/c;

    .line 85
    .line 86
    new-instance v6, Lrn/i;

    .line 87
    .line 88
    const/16 v2, 0x16

    .line 89
    .line 90
    invoke-direct {v6, v1, v5, p0, v2}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    iget-object v4, v0, Lrn/k;->d:Lkx0/a;

    .line 94
    .line 95
    move-object v7, v5

    .line 96
    iget-object v5, v0, Lrn/k;->f:Lkx0/a;

    .line 97
    .line 98
    new-instance v3, Landroidx/lifecycle/c1;

    .line 99
    .line 100
    const/16 v9, 0x14

    .line 101
    .line 102
    move-object v8, v7

    .line 103
    invoke-direct/range {v3 .. v9}, Landroidx/lifecycle/c1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 104
    .line 105
    .line 106
    move-object p0, v3

    .line 107
    new-instance v3, Lss/b;

    .line 108
    .line 109
    const/16 v11, 0xb

    .line 110
    .line 111
    move-object v9, v7

    .line 112
    move-object v10, v7

    .line 113
    move-object v7, v6

    .line 114
    move-object v6, v8

    .line 115
    move-object v8, v4

    .line 116
    move-object v4, v1

    .line 117
    invoke-direct/range {v3 .. v11}, Lss/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 118
    .line 119
    .line 120
    move-object v1, v7

    .line 121
    move-object v7, v6

    .line 122
    move-object v6, v1

    .line 123
    move-object v1, v3

    .line 124
    move-object v4, v8

    .line 125
    new-instance v3, Lun/a;

    .line 126
    .line 127
    const/4 v8, 0x6

    .line 128
    move-object v5, v7

    .line 129
    invoke-direct/range {v3 .. v8}, Lun/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    new-instance v2, Lrn/i;

    .line 133
    .line 134
    const/4 v4, 0x1

    .line 135
    invoke-direct {v2, p0, v1, v3, v4}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 136
    .line 137
    .line 138
    invoke-static {v2}, Ltn/a;->a(Ltn/b;)Lkx0/a;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    iput-object p0, v0, Lrn/k;->i:Lkx0/a;

    .line 143
    .line 144
    return-object v0

    .line 145
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    new-instance v0, Ljava/lang/StringBuilder;

    .line 148
    .line 149
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 150
    .line 151
    .line 152
    const-class v1, Landroid/content/Context;

    .line 153
    .line 154
    invoke-virtual {v1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    const-string v1, " must be set"

    .line 162
    .line 163
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    throw p0
.end method

.method public b(Ljava/lang/String;Lq51/e;)Lkp/r8;
    .locals 12

    .line 1
    const-string v0, "decode(...)"

    .line 2
    .line 3
    iget-object p0, p0, Lca/d;->d:Landroid/content/Context;

    .line 4
    .line 5
    invoke-static {p0}, Lq51/r;->e(Landroid/content/Context;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0, p1, p2}, Lq51/r;->b(Ljava/lang/String;Ljava/lang/String;Lq51/e;)Lq51/d;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const/4 p2, 0x0

    .line 14
    if-eqz p0, :cond_2

    .line 15
    .line 16
    invoke-virtual {p0}, Lq51/d;->a()Lkp/r8;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    instance-of v2, v1, Lg91/b;

    .line 21
    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    check-cast v1, Lg91/b;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move-object v1, p2

    .line 28
    :goto_0
    if-eqz v1, :cond_1

    .line 29
    .line 30
    iget-object v1, v1, Lg91/b;->a:Ljava/lang/Object;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move-object v1, p2

    .line 34
    :goto_1
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 35
    .line 36
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_2

    .line 41
    .line 42
    new-instance v1, Ljava/io/File;

    .line 43
    .line 44
    iget-object p0, p0, Lq51/d;->a:Ljava/lang/String;

    .line 45
    .line 46
    invoke-direct {v1, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move-object v1, p2

    .line 51
    :goto_2
    if-eqz v1, :cond_5

    .line 52
    .line 53
    :try_start_0
    invoke-static {}, Lq51/r;->a()Lkp/r8;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    instance-of v2, p0, Lg91/a;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_3

    .line 58
    .line 59
    if-eqz v2, :cond_3

    .line 60
    .line 61
    :try_start_1
    check-cast p0, Lg91/a;

    .line 62
    .line 63
    new-instance p2, Lg91/a;

    .line 64
    .line 65
    iget-object p0, p0, Lg91/a;->a:Lq51/p;

    .line 66
    .line 67
    invoke-direct {p2, p0}, Lg91/a;-><init>(Lq51/p;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 68
    .line 69
    .line 70
    return-object p2

    .line 71
    :goto_3
    move-object v7, p1

    .line 72
    goto/16 :goto_7

    .line 73
    .line 74
    :catch_0
    move-exception v0

    .line 75
    move-object p0, v0

    .line 76
    goto :goto_3

    .line 77
    :cond_3
    :try_start_2
    check-cast p0, Lg91/b;

    .line 78
    .line 79
    iget-object p0, p0, Lg91/b;->a:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Lq51/b;

    .line 82
    .line 83
    invoke-static {v1}, Lwx0/i;->d(Ljava/io/File;)[B

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    new-instance v3, Ljava/lang/String;

    .line 88
    .line 89
    sget-object v4, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 90
    .line 91
    invoke-direct {v3, v2, v4}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_3

    .line 92
    .line 93
    .line 94
    :try_start_3
    new-instance v4, Lorg/json/JSONObject;

    .line 95
    .line 96
    invoke-direct {v4, v3}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1

    .line 97
    .line 98
    .line 99
    move-object p2, v4

    .line 100
    :catch_1
    const/4 v3, 0x0

    .line 101
    if-eqz p2, :cond_4

    .line 102
    .line 103
    :try_start_4
    new-array p0, v3, [Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {p2, p0}, Lf91/b;->a(Lorg/json/JSONObject;[Ljava/lang/String;)I

    .line 106
    .line 107
    .line 108
    new-array p0, v3, [Ljava/lang/String;

    .line 109
    .line 110
    invoke-static {p2, p0}, Lf91/b;->b(Lorg/json/JSONObject;[Ljava/lang/String;)J

    .line 111
    .line 112
    .line 113
    move-result-wide v4

    .line 114
    const-string p0, "iv"

    .line 115
    .line 116
    new-array v2, v3, [Ljava/lang/String;

    .line 117
    .line 118
    invoke-static {p2, p0, v2}, Lf91/b;->d(Lorg/json/JSONObject;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    const/4 v2, 0x2

    .line 123
    invoke-static {p0, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    const-string v6, "content"

    .line 131
    .line 132
    new-array v3, v3, [Ljava/lang/String;

    .line 133
    .line 134
    invoke-static {p2, v6, v3}, Lf91/b;->d(Lorg/json/JSONObject;Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p2

    .line 138
    invoke-static {p2, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 139
    .line 140
    .line 141
    move-result-object p2

    .line 142
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 143
    .line 144
    .line 145
    move-object v10, p0

    .line 146
    move-object v11, p2

    .line 147
    :goto_4
    move-wide v8, v4

    .line 148
    goto :goto_5

    .line 149
    :cond_4
    :try_start_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    const/16 p0, 0x10

    .line 153
    .line 154
    invoke-static {v2, v3, p0}, Lmx0/n;->n([BII)[B

    .line 155
    .line 156
    .line 157
    move-result-object p2

    .line 158
    array-length v0, v2

    .line 159
    invoke-static {v2, p0, v0}, Lmx0/n;->n([BII)[B

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    const-wide/16 v4, 0x0

    .line 164
    .line 165
    move-object v11, p0

    .line 166
    move-object v10, p2

    .line 167
    goto :goto_4

    .line 168
    :goto_5
    new-instance p0, Lg91/b;

    .line 169
    .line 170
    new-instance v6, Lq51/a;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_3

    .line 171
    .line 172
    move-object v7, p1

    .line 173
    :try_start_6
    invoke-direct/range {v6 .. v11}, Lq51/a;-><init>(Ljava/lang/String;J[B[B)V

    .line 174
    .line 175
    .line 176
    invoke-direct {p0, v6}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_2

    .line 177
    .line 178
    .line 179
    goto :goto_8

    .line 180
    :catch_2
    move-exception v0

    .line 181
    :goto_6
    move-object p0, v0

    .line 182
    goto :goto_7

    .line 183
    :catch_3
    move-exception v0

    .line 184
    move-object v7, p1

    .line 185
    goto :goto_6

    .line 186
    :goto_7
    new-instance p1, Lq51/q;

    .line 187
    .line 188
    const/4 p2, 0x0

    .line 189
    invoke-direct {p1, v7, v1, p2}, Lq51/q;-><init>(Ljava/lang/String;Ljava/io/File;I)V

    .line 190
    .line 191
    .line 192
    sget-object p2, Lq51/r;->a:Lw51/b;

    .line 193
    .line 194
    invoke-static {p2, p0, p1}, Lw51/c;->a(Lw51/b;Ljava/lang/Exception;Lay0/a;)V

    .line 195
    .line 196
    .line 197
    new-instance p1, Lg91/a;

    .line 198
    .line 199
    new-instance p2, Lq51/f;

    .line 200
    .line 201
    invoke-direct {p2, p0}, Lq51/f;-><init>(Ljava/lang/Throwable;)V

    .line 202
    .line 203
    .line 204
    invoke-direct {p1, p2}, Lg91/a;-><init>(Lq51/p;)V

    .line 205
    .line 206
    .line 207
    move-object p0, p1

    .line 208
    :goto_8
    return-object p0

    .line 209
    :cond_5
    new-instance p0, Lg91/b;

    .line 210
    .line 211
    invoke-direct {p0, p2}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    return-object p0
.end method

.method public c(Ljava/lang/String;Lq51/e;)Lkp/r8;
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lca/d;->d:Landroid/content/Context;

    .line 7
    .line 8
    invoke-static {p0}, Lq51/r;->e(Landroid/content/Context;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p0, p1, p2}, Lq51/r;->b(Ljava/lang/String;Ljava/lang/String;Lq51/e;)Lq51/d;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    if-nez p0, :cond_0

    .line 17
    .line 18
    new-instance p0, Lg91/b;

    .line 19
    .line 20
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 21
    .line 22
    invoke-direct {p0, p1}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_0
    invoke-virtual {p0}, Lq51/d;->a()Lkp/r8;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    instance-of p2, p1, Lg91/b;

    .line 31
    .line 32
    if-eqz p2, :cond_2

    .line 33
    .line 34
    check-cast p1, Lg91/b;

    .line 35
    .line 36
    iget-object p1, p1, Lg91/b;->a:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Ljava/lang/Boolean;

    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    if-eqz p1, :cond_1

    .line 45
    .line 46
    :try_start_0
    new-instance p1, Lg91/b;

    .line 47
    .line 48
    new-instance p2, Ljava/io/File;

    .line 49
    .line 50
    iget-object p0, p0, Lq51/d;->a:Ljava/lang/String;

    .line 51
    .line 52
    invoke-direct {p2, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/io/File;->delete()Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {p1, p0}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 64
    .line 65
    .line 66
    return-object p1

    .line 67
    :catch_0
    move-exception p0

    .line 68
    new-instance p1, Lg91/a;

    .line 69
    .line 70
    new-instance p2, Lq51/i;

    .line 71
    .line 72
    invoke-static {p0}, Lkp/y5;->e(Ljava/lang/Exception;)Le91/b;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-direct {p2, p0}, Lq51/p;-><init>(Le91/b;)V

    .line 77
    .line 78
    .line 79
    invoke-direct {p1, p2}, Lg91/a;-><init>(Lq51/p;)V

    .line 80
    .line 81
    .line 82
    return-object p1

    .line 83
    :cond_1
    new-instance p0, Lg91/b;

    .line 84
    .line 85
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 86
    .line 87
    invoke-direct {p0, p1}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    return-object p0

    .line 91
    :cond_2
    instance-of p0, p1, Lg91/a;

    .line 92
    .line 93
    if-eqz p0, :cond_3

    .line 94
    .line 95
    return-object p1

    .line 96
    :cond_3
    new-instance p0, La8/r0;

    .line 97
    .line 98
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 99
    .line 100
    .line 101
    throw p0
.end method

.method public l(Lu/x0;)Lf8/m;
    .locals 4

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object p0, p0, Lca/d;->d:Landroid/content/Context;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, "com.amazon.hardware.tv_screen"

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    :goto_0
    iget-object p0, p1, Lu/x0;->c:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lt7/o;

    .line 27
    .line 28
    iget-object p0, p0, Lt7/o;->n:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {p0}, Lt7/d0;->h(Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    new-instance v0, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v1, "Creating an asynchronous MediaCodec adapter for track type "

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {p0}, Lw7/w;->v(I)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    const-string v1, "DMCodecAdapterFactory"

    .line 53
    .line 54
    invoke-static {v1, v0}, Lw7/a;->s(Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    new-instance v0, Lc2/k;

    .line 58
    .line 59
    new-instance v1, Lf8/c;

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    invoke-direct {v1, p0, v2}, Lf8/c;-><init>(II)V

    .line 63
    .line 64
    .line 65
    new-instance v2, Lf8/c;

    .line 66
    .line 67
    const/4 v3, 0x1

    .line 68
    invoke-direct {v2, p0, v3}, Lf8/c;-><init>(II)V

    .line 69
    .line 70
    .line 71
    const/4 p0, 0x5

    .line 72
    invoke-direct {v0, p0, v1, v2}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, p1}, Lc2/k;->r(Lu/x0;)Lf8/d;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    :cond_1
    new-instance p0, La61/a;

    .line 81
    .line 82
    const/4 v0, 0x5

    .line 83
    invoke-direct {p0, v0}, La61/a;-><init>(I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, p1}, La61/a;->l(Lu/x0;)Lf8/m;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0
.end method
