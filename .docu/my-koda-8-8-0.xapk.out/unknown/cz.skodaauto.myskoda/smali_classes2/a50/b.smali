.class public final synthetic La50/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:La50/j;


# direct methods
.method public synthetic constructor <init>(La50/j;I)V
    .locals 0

    .line 1
    iput p2, p0, La50/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La50/b;->e:La50/j;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()Llx0/e;
    .locals 9

    .line 1
    iget v0, p0, La50/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/k;

    .line 7
    .line 8
    const-string v7, "onPois(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, La50/j;

    .line 13
    .line 14
    iget-object v5, p0, La50/b;->e:La50/j;

    .line 15
    .line 16
    const-string v6, "onPois"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onPoiCategory(Lcz/skodaauto/myskoda/library/mapplaces/model/PoiCategory;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, La50/j;

    .line 29
    .line 30
    iget-object v6, p0, La50/b;->e:La50/j;

    .line 31
    .line 32
    const-string v7, "onPoiCategory"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, La50/b;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    iget-object p0, p0, La50/b;->e:La50/j;

    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p1, Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    iget-object p1, p0, La50/j;->l:Lrq0/f;

    .line 21
    .line 22
    new-instance v0, Lsq0/c;

    .line 23
    .line 24
    iget-object p0, p0, La50/j;->m:Lij0/a;

    .line 25
    .line 26
    new-array v4, v1, [Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ljj0/f;

    .line 29
    .line 30
    const v5, 0x7f1205fa

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const/4 v4, 0x6

    .line 38
    invoke-direct {v0, v4, p0, v3, v3}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1, v0, v1, p2}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    if-ne p0, p1, :cond_0

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move-object p0, v2

    .line 51
    :goto_0
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 52
    .line 53
    if-ne p0, p1, :cond_1

    .line 54
    .line 55
    move-object v2, p0

    .line 56
    :cond_1
    return-object v2

    .line 57
    :pswitch_0
    move-object v8, p1

    .line 58
    check-cast v8, Lbl0/h0;

    .line 59
    .line 60
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    check-cast p1, La50/i;

    .line 65
    .line 66
    if-eqz v8, :cond_2

    .line 67
    .line 68
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    packed-switch p2, :pswitch_data_1

    .line 73
    .line 74
    .line 75
    new-instance p0, La8/r0;

    .line 76
    .line 77
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :pswitch_1
    const p2, 0x7f12069c

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :pswitch_2
    const p2, 0x7f120699

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :pswitch_3
    const p2, 0x7f12069b

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :pswitch_4
    const p2, 0x7f12069a

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :pswitch_5
    const p2, 0x7f120698

    .line 98
    .line 99
    .line 100
    goto :goto_1

    .line 101
    :pswitch_6
    const p2, 0x7f120697

    .line 102
    .line 103
    .line 104
    :goto_1
    iget-object v0, p0, La50/j;->m:Lij0/a;

    .line 105
    .line 106
    new-array v4, v1, [Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Ljj0/f;

    .line 109
    .line 110
    invoke-virtual {v0, p2, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    goto :goto_2

    .line 115
    :cond_2
    move-object p2, v3

    .line 116
    :goto_2
    if-nez p2, :cond_3

    .line 117
    .line 118
    const-string p2, ""

    .line 119
    .line 120
    :cond_3
    move-object v4, p2

    .line 121
    const/4 p2, 0x1

    .line 122
    if-eqz v8, :cond_4

    .line 123
    .line 124
    sget-object v0, Lbl0/h0;->g:Lbl0/h0;

    .line 125
    .line 126
    sget-object v5, Lbl0/h0;->h:Lbl0/h0;

    .line 127
    .line 128
    filled-new-array {v0, v5}, [Lbl0/h0;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-interface {v0, v8}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    if-ne v0, p2, :cond_4

    .line 141
    .line 142
    move v5, p2

    .line 143
    goto :goto_3

    .line 144
    :cond_4
    move v5, v1

    .line 145
    :goto_3
    if-eqz v8, :cond_8

    .line 146
    .line 147
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    if-eqz v0, :cond_7

    .line 152
    .line 153
    const/4 v6, 0x4

    .line 154
    if-eq v0, v6, :cond_6

    .line 155
    .line 156
    const/4 v6, 0x5

    .line 157
    if-eq v0, v6, :cond_5

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_5
    const v0, 0x7f1206a6

    .line 161
    .line 162
    .line 163
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    goto :goto_4

    .line 168
    :cond_6
    const v0, 0x7f120688

    .line 169
    .line 170
    .line 171
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    goto :goto_4

    .line 176
    :cond_7
    const v0, 0x7f120627

    .line 177
    .line 178
    .line 179
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    :cond_8
    :goto_4
    move-object v6, v3

    .line 184
    if-eqz v8, :cond_9

    .line 185
    .line 186
    sget-object v0, Lbl0/h0;->d:Lbl0/h0;

    .line 187
    .line 188
    if-ne v8, v0, :cond_9

    .line 189
    .line 190
    move v7, p2

    .line 191
    goto :goto_5

    .line 192
    :cond_9
    move v7, v1

    .line 193
    :goto_5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 194
    .line 195
    .line 196
    new-instance v3, La50/i;

    .line 197
    .line 198
    const/4 v9, 0x0

    .line 199
    invoke-direct/range {v3 .. v9}, La50/i;-><init>(Ljava/lang/String;ZLjava/lang/Integer;ZLbl0/h0;Z)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {p0, v3}, Lql0/j;->g(Lql0/h;)V

    .line 203
    .line 204
    .line 205
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 206
    .line 207
    return-object v2

    .line 208
    nop

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch

    .line 210
    .line 211
    .line 212
    .line 213
    .line 214
    .line 215
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, La50/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyy0/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 20
    .line 21
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    :cond_0
    return v1

    .line 30
    :pswitch_0
    instance-of v0, p1, Lyy0/j;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 44
    .line 45
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    :cond_1
    return v1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, La50/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
