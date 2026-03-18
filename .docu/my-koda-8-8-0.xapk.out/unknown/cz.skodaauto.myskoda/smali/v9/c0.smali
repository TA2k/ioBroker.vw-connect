.class public final Lv9/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/util/List;

.field public final c:[Lo8/i0;

.field public final d:Lca/j;


# direct methods
.method public constructor <init>(Ljava/util/List;I)V
    .locals 1

    .line 1
    iput p2, p0, Lv9/c0;->a:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lv9/c0;->b:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    new-array p1, p1, [Lo8/i0;

    .line 16
    .line 17
    iput-object p1, p0, Lv9/c0;->c:[Lo8/i0;

    .line 18
    .line 19
    new-instance p1, Lca/j;

    .line 20
    .line 21
    new-instance p2, Lrx/b;

    .line 22
    .line 23
    const/16 v0, 0xc

    .line 24
    .line 25
    invoke-direct {p2, p0, v0}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p1, p2}, Lca/j;-><init>(Lx7/r;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lv9/c0;->d:Lca/j;

    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lv9/c0;->b:Ljava/util/List;

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    new-array p1, p1, [Lo8/i0;

    .line 44
    .line 45
    iput-object p1, p0, Lv9/c0;->c:[Lo8/i0;

    .line 46
    .line 47
    new-instance p1, Lca/j;

    .line 48
    .line 49
    new-instance p2, Lrx/b;

    .line 50
    .line 51
    const/16 v0, 0xd

    .line 52
    .line 53
    invoke-direct {p2, p0, v0}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    invoke-direct {p1, p2}, Lca/j;-><init>(Lx7/r;)V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Lv9/c0;->d:Lca/j;

    .line 60
    .line 61
    const/4 p0, 0x3

    .line 62
    invoke-virtual {p1, p0}, Lca/j;->m(I)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public a(JLw7/p;)V
    .locals 4

    .line 1
    invoke-virtual {p3}, Lw7/p;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x9

    .line 6
    .line 7
    if-ge v0, v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p3}, Lw7/p;->j()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p3}, Lw7/p;->j()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {p3}, Lw7/p;->w()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/16 v3, 0x1b2

    .line 23
    .line 24
    if-ne v0, v3, :cond_1

    .line 25
    .line 26
    const v0, 0x47413934

    .line 27
    .line 28
    .line 29
    if-ne v1, v0, :cond_1

    .line 30
    .line 31
    const/4 v0, 0x3

    .line 32
    if-ne v2, v0, :cond_1

    .line 33
    .line 34
    iget-object p0, p0, Lv9/c0;->d:Lca/j;

    .line 35
    .line 36
    invoke-virtual {p0, p1, p2, p3}, Lca/j;->a(JLw7/p;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    :goto_0
    return-void
.end method

.method public final b(Lo8/q;Lh11/h;)V
    .locals 9

    .line 1
    iget v0, p0, Lv9/c0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    move v1, v0

    .line 8
    :goto_0
    iget-object v2, p0, Lv9/c0;->c:[Lo8/i0;

    .line 9
    .line 10
    array-length v3, v2

    .line 11
    if-ge v1, v3, :cond_2

    .line 12
    .line 13
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 17
    .line 18
    .line 19
    iget v3, p2, Lh11/h;->f:I

    .line 20
    .line 21
    const/4 v4, 0x3

    .line 22
    invoke-interface {p1, v3, v4}, Lo8/q;->q(II)Lo8/i0;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    iget-object v4, p0, Lv9/c0;->b:Ljava/util/List;

    .line 27
    .line 28
    invoke-interface {v4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    check-cast v4, Lt7/o;

    .line 33
    .line 34
    iget-object v5, v4, Lt7/o;->n:Ljava/lang/String;

    .line 35
    .line 36
    const-string v6, "application/cea-608"

    .line 37
    .line 38
    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    if-nez v6, :cond_1

    .line 43
    .line 44
    const-string v6, "application/cea-708"

    .line 45
    .line 46
    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    if-eqz v6, :cond_0

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_0
    move v6, v0

    .line 54
    goto :goto_2

    .line 55
    :cond_1
    :goto_1
    const/4 v6, 0x1

    .line 56
    :goto_2
    new-instance v7, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    const-string v8, "Invalid closed caption MIME type provided: "

    .line 59
    .line 60
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v7

    .line 70
    invoke-static {v6, v7}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 71
    .line 72
    .line 73
    new-instance v6, Lt7/n;

    .line 74
    .line 75
    invoke-direct {v6}, Lt7/n;-><init>()V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 79
    .line 80
    .line 81
    iget-object v7, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v7, Ljava/lang/String;

    .line 84
    .line 85
    iput-object v7, v6, Lt7/n;->a:Ljava/lang/String;

    .line 86
    .line 87
    const-string v7, "video/mp2t"

    .line 88
    .line 89
    invoke-static {v7}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    iput-object v7, v6, Lt7/n;->l:Ljava/lang/String;

    .line 94
    .line 95
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    iput-object v5, v6, Lt7/n;->m:Ljava/lang/String;

    .line 100
    .line 101
    iget v5, v4, Lt7/o;->e:I

    .line 102
    .line 103
    iput v5, v6, Lt7/n;->e:I

    .line 104
    .line 105
    iget-object v5, v4, Lt7/o;->d:Ljava/lang/String;

    .line 106
    .line 107
    iput-object v5, v6, Lt7/n;->d:Ljava/lang/String;

    .line 108
    .line 109
    iget v5, v4, Lt7/o;->K:I

    .line 110
    .line 111
    iput v5, v6, Lt7/n;->J:I

    .line 112
    .line 113
    iget-object v4, v4, Lt7/o;->q:Ljava/util/List;

    .line 114
    .line 115
    iput-object v4, v6, Lt7/n;->p:Ljava/util/List;

    .line 116
    .line 117
    invoke-static {v6, v3}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 118
    .line 119
    .line 120
    aput-object v3, v2, v1

    .line 121
    .line 122
    add-int/lit8 v1, v1, 0x1

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_2
    return-void

    .line 126
    :pswitch_0
    const/4 v0, 0x0

    .line 127
    move v1, v0

    .line 128
    :goto_3
    iget-object v2, p0, Lv9/c0;->c:[Lo8/i0;

    .line 129
    .line 130
    array-length v3, v2

    .line 131
    if-ge v1, v3, :cond_6

    .line 132
    .line 133
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 137
    .line 138
    .line 139
    iget v3, p2, Lh11/h;->f:I

    .line 140
    .line 141
    const/4 v4, 0x3

    .line 142
    invoke-interface {p1, v3, v4}, Lo8/q;->q(II)Lo8/i0;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    iget-object v4, p0, Lv9/c0;->b:Ljava/util/List;

    .line 147
    .line 148
    invoke-interface {v4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    check-cast v4, Lt7/o;

    .line 153
    .line 154
    iget-object v5, v4, Lt7/o;->n:Ljava/lang/String;

    .line 155
    .line 156
    const-string v6, "application/cea-608"

    .line 157
    .line 158
    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v6

    .line 162
    if-nez v6, :cond_4

    .line 163
    .line 164
    const-string v6, "application/cea-708"

    .line 165
    .line 166
    invoke-virtual {v6, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v6

    .line 170
    if-eqz v6, :cond_3

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_3
    move v6, v0

    .line 174
    goto :goto_5

    .line 175
    :cond_4
    :goto_4
    const/4 v6, 0x1

    .line 176
    :goto_5
    new-instance v7, Ljava/lang/StringBuilder;

    .line 177
    .line 178
    const-string v8, "Invalid closed caption MIME type provided: "

    .line 179
    .line 180
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    invoke-static {v6, v7}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 191
    .line 192
    .line 193
    iget-object v6, v4, Lt7/o;->a:Ljava/lang/String;

    .line 194
    .line 195
    if-eqz v6, :cond_5

    .line 196
    .line 197
    goto :goto_6

    .line 198
    :cond_5
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 199
    .line 200
    .line 201
    iget-object v6, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v6, Ljava/lang/String;

    .line 204
    .line 205
    :goto_6
    new-instance v7, Lt7/n;

    .line 206
    .line 207
    invoke-direct {v7}, Lt7/n;-><init>()V

    .line 208
    .line 209
    .line 210
    iput-object v6, v7, Lt7/n;->a:Ljava/lang/String;

    .line 211
    .line 212
    const-string v6, "video/mp2t"

    .line 213
    .line 214
    invoke-static {v6}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v6

    .line 218
    iput-object v6, v7, Lt7/n;->l:Ljava/lang/String;

    .line 219
    .line 220
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v5

    .line 224
    iput-object v5, v7, Lt7/n;->m:Ljava/lang/String;

    .line 225
    .line 226
    iget v5, v4, Lt7/o;->e:I

    .line 227
    .line 228
    iput v5, v7, Lt7/n;->e:I

    .line 229
    .line 230
    iget-object v5, v4, Lt7/o;->d:Ljava/lang/String;

    .line 231
    .line 232
    iput-object v5, v7, Lt7/n;->d:Ljava/lang/String;

    .line 233
    .line 234
    iget v5, v4, Lt7/o;->K:I

    .line 235
    .line 236
    iput v5, v7, Lt7/n;->J:I

    .line 237
    .line 238
    iget-object v4, v4, Lt7/o;->q:Ljava/util/List;

    .line 239
    .line 240
    iput-object v4, v7, Lt7/n;->p:Ljava/util/List;

    .line 241
    .line 242
    invoke-static {v7, v3}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 243
    .line 244
    .line 245
    aput-object v3, v2, v1

    .line 246
    .line 247
    add-int/lit8 v1, v1, 0x1

    .line 248
    .line 249
    goto :goto_3

    .line 250
    :cond_6
    return-void

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
