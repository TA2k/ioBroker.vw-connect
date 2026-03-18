.class public final synthetic Le2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;ZZ)V
    .locals 0

    .line 1
    iput p1, p0, Le2/a;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Le2/a;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-boolean p3, p0, Le2/a;->e:Z

    .line 6
    .line 7
    iput-boolean p4, p0, Le2/a;->f:Z

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Le2/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le2/a;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luf/a;

    .line 9
    .line 10
    check-cast p1, Luf/l;

    .line 11
    .line 12
    const-string v1, "currentState"

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p1, Luf/l;->b:Luf/a;

    .line 18
    .line 19
    iget-boolean v2, p0, Le2/a;->e:Z

    .line 20
    .line 21
    iget-boolean p0, p0, Le2/a;->f:Z

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    invoke-virtual {v1, v0}, Luf/a;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_0

    .line 32
    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    move v5, v4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v5, v3

    .line 38
    :goto_0
    invoke-virtual {v1, v0}, Luf/a;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-eqz v6, :cond_1

    .line 43
    .line 44
    if-eqz p0, :cond_1

    .line 45
    .line 46
    move v6, v4

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    move v6, v3

    .line 49
    :goto_1
    invoke-static {v1, v6, v5}, Luf/a;->a(Luf/a;ZZ)Luf/a;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/4 v1, 0x0

    .line 55
    :goto_2
    iget-object v5, p1, Luf/l;->c:Ljava/util/List;

    .line 56
    .line 57
    check-cast v5, Ljava/lang/Iterable;

    .line 58
    .line 59
    new-instance v6, Ljava/util/ArrayList;

    .line 60
    .line 61
    const/16 v7, 0xa

    .line 62
    .line 63
    invoke-static {v5, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 68
    .line 69
    .line 70
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    if-eqz v7, :cond_5

    .line 79
    .line 80
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    check-cast v7, Luf/a;

    .line 85
    .line 86
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v8

    .line 90
    if-eqz v8, :cond_3

    .line 91
    .line 92
    if-eqz v2, :cond_3

    .line 93
    .line 94
    move v8, v4

    .line 95
    goto :goto_4

    .line 96
    :cond_3
    move v8, v3

    .line 97
    :goto_4
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v9

    .line 101
    if-eqz v9, :cond_4

    .line 102
    .line 103
    if-eqz p0, :cond_4

    .line 104
    .line 105
    move v9, v4

    .line 106
    goto :goto_5

    .line 107
    :cond_4
    move v9, v3

    .line 108
    :goto_5
    invoke-static {v7, v9, v8}, Luf/a;->a(Luf/a;ZZ)Luf/a;

    .line 109
    .line 110
    .line 111
    move-result-object v7

    .line 112
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_5
    const/16 p0, 0x79

    .line 117
    .line 118
    invoke-static {p1, v1, v6, v3, p0}, Luf/l;->a(Luf/l;Luf/a;Ljava/util/ArrayList;ZI)Luf/l;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    return-object p0

    .line 123
    :pswitch_0
    iget-object v0, p0, Le2/a;->g:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Ljava/util/ArrayList;

    .line 126
    .line 127
    check-cast p1, Lm1/f;

    .line 128
    .line 129
    const-string v1, "$this$LazyColumn"

    .line 130
    .line 131
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    new-instance v2, Lal/n;

    .line 139
    .line 140
    const/4 v3, 0x5

    .line 141
    invoke-direct {v2, v0, v3}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 142
    .line 143
    .line 144
    new-instance v3, Lik/d;

    .line 145
    .line 146
    iget-boolean v4, p0, Le2/a;->e:Z

    .line 147
    .line 148
    iget-boolean p0, p0, Le2/a;->f:Z

    .line 149
    .line 150
    invoke-direct {v3, v0, v4, p0}, Lik/d;-><init>(Ljava/util/ArrayList;ZZ)V

    .line 151
    .line 152
    .line 153
    new-instance p0, Lt2/b;

    .line 154
    .line 155
    const/4 v0, 0x1

    .line 156
    const v4, 0x799532c4

    .line 157
    .line 158
    .line 159
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 160
    .line 161
    .line 162
    const/4 v0, 0x0

    .line 163
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 164
    .line 165
    .line 166
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    return-object p0

    .line 169
    :pswitch_1
    iget-object v0, p0, Le2/a;->g:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v0, Le2/l;

    .line 172
    .line 173
    check-cast p1, Ld4/l;

    .line 174
    .line 175
    invoke-interface {v0}, Le2/l;->a()J

    .line 176
    .line 177
    .line 178
    move-result-wide v3

    .line 179
    sget-object v0, Le2/d0;->c:Ld4/z;

    .line 180
    .line 181
    new-instance v1, Le2/c0;

    .line 182
    .line 183
    iget-boolean v2, p0, Le2/a;->e:Z

    .line 184
    .line 185
    if-eqz v2, :cond_6

    .line 186
    .line 187
    sget-object v2, Lt1/b0;->e:Lt1/b0;

    .line 188
    .line 189
    goto :goto_6

    .line 190
    :cond_6
    sget-object v2, Lt1/b0;->f:Lt1/b0;

    .line 191
    .line 192
    :goto_6
    iget-boolean p0, p0, Le2/a;->f:Z

    .line 193
    .line 194
    if-eqz p0, :cond_7

    .line 195
    .line 196
    sget-object p0, Le2/b0;->d:Le2/b0;

    .line 197
    .line 198
    :goto_7
    move-object v5, p0

    .line 199
    goto :goto_8

    .line 200
    :cond_7
    sget-object p0, Le2/b0;->f:Le2/b0;

    .line 201
    .line 202
    goto :goto_7

    .line 203
    :goto_8
    const-wide v6, 0x7fffffff7fffffffL

    .line 204
    .line 205
    .line 206
    .line 207
    .line 208
    and-long/2addr v6, v3

    .line 209
    const-wide v8, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 210
    .line 211
    .line 212
    .line 213
    .line 214
    cmp-long p0, v6, v8

    .line 215
    .line 216
    if-eqz p0, :cond_8

    .line 217
    .line 218
    const/4 p0, 0x1

    .line 219
    :goto_9
    move v6, p0

    .line 220
    goto :goto_a

    .line 221
    :cond_8
    const/4 p0, 0x0

    .line 222
    goto :goto_9

    .line 223
    :goto_a
    invoke-direct/range {v1 .. v6}, Le2/c0;-><init>(Lt1/b0;JLe2/b0;Z)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {p1, v0, v1}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 230
    .line 231
    return-object p0

    .line 232
    nop

    .line 233
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
