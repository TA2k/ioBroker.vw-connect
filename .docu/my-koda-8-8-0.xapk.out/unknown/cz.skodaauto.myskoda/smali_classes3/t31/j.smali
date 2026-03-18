.class public final synthetic Lt31/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt31/n;


# direct methods
.method public synthetic constructor <init>(Lt31/n;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt31/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt31/j;->e:Lt31/n;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lt31/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ln7/b;

    .line 7
    .line 8
    const-string v0, "$this$LifecycleStartEffect"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sget-object v0, Lt31/g;->a:Lt31/g;

    .line 14
    .line 15
    iget-object p0, p0, Lt31/j;->e:Lt31/n;

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lt31/n;->f(Lt31/i;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Ly21/e;

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    invoke-direct {v0, p1, p0, v1}, Ly21/e;-><init>(Ln7/b;Lq41/b;I)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    move-object v2, p1

    .line 28
    check-cast v2, Li31/b;

    .line 29
    .line 30
    const-string p1, "$this$updateCurrentAppointmentUseCase"

    .line 31
    .line 32
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lt31/j;->e:Lt31/n;

    .line 36
    .line 37
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p1, Lt31/o;

    .line 42
    .line 43
    iget-object p1, p1, Lt31/o;->c:Ljava/util/List;

    .line 44
    .line 45
    check-cast p1, Ljava/lang/Iterable;

    .line 46
    .line 47
    new-instance v0, Ljava/util/ArrayList;

    .line 48
    .line 49
    const/16 v1, 0xa

    .line 50
    .line 51
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    invoke-direct {v0, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    const-string v4, "<this>"

    .line 67
    .line 68
    if-eqz v3, :cond_0

    .line 69
    .line 70
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    check-cast v3, Lp31/h;

    .line 75
    .line 76
    iget-object v5, v3, Lp31/h;->a:Li31/h0;

    .line 77
    .line 78
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    new-instance v4, Li31/g0;

    .line 82
    .line 83
    iget v6, v5, Li31/h0;->b:I

    .line 84
    .line 85
    iget-object v5, v5, Li31/h0;->a:Ljava/lang/String;

    .line 86
    .line 87
    invoke-direct {v4, v6, v5}, Li31/g0;-><init>(ILjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iget-boolean v3, v3, Lp31/h;->c:Z

    .line 91
    .line 92
    new-instance v5, Li31/a0;

    .line 93
    .line 94
    invoke-direct {v5, v4, v3}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_0
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    check-cast p1, Lt31/o;

    .line 106
    .line 107
    iget-object p1, p1, Lt31/o;->d:Ljava/util/List;

    .line 108
    .line 109
    check-cast p1, Ljava/lang/Iterable;

    .line 110
    .line 111
    new-instance v3, Ljava/util/ArrayList;

    .line 112
    .line 113
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 118
    .line 119
    .line 120
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    if-eqz v5, :cond_1

    .line 129
    .line 130
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    check-cast v5, Lp31/e;

    .line 135
    .line 136
    iget-object v6, v5, Lp31/e;->a:Li31/y;

    .line 137
    .line 138
    invoke-static {v6, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    new-instance v7, Li31/z;

    .line 142
    .line 143
    iget v8, v6, Li31/y;->c:I

    .line 144
    .line 145
    iget v9, v6, Li31/y;->a:I

    .line 146
    .line 147
    iget-object v6, v6, Li31/y;->b:Ljava/lang/String;

    .line 148
    .line 149
    invoke-direct {v7, v8, v9, v6}, Li31/z;-><init>(IILjava/lang/String;)V

    .line 150
    .line 151
    .line 152
    iget-boolean v5, v5, Lp31/e;->b:Z

    .line 153
    .line 154
    new-instance v6, Li31/a0;

    .line 155
    .line 156
    invoke-direct {v6, v7, v5}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_1
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    check-cast p1, Lt31/o;

    .line 168
    .line 169
    iget-object p1, p1, Lt31/o;->e:Ljava/util/List;

    .line 170
    .line 171
    check-cast p1, Ljava/lang/Iterable;

    .line 172
    .line 173
    new-instance v5, Ljava/util/ArrayList;

    .line 174
    .line 175
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    invoke-direct {v5, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 180
    .line 181
    .line 182
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    if-eqz v1, :cond_2

    .line 191
    .line 192
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    check-cast v1, Lp31/d;

    .line 197
    .line 198
    iget-object v6, v1, Lp31/d;->a:Li31/u;

    .line 199
    .line 200
    invoke-static {v6, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    new-instance v7, Li31/v;

    .line 204
    .line 205
    iget v8, v6, Li31/u;->a:I

    .line 206
    .line 207
    invoke-virtual {v6}, Li31/u;->a()Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v6

    .line 211
    invoke-direct {v7, v8, v6}, Li31/v;-><init>(ILjava/lang/String;)V

    .line 212
    .line 213
    .line 214
    iget-boolean v1, v1, Lp31/d;->b:Z

    .line 215
    .line 216
    new-instance v6, Li31/a0;

    .line 217
    .line 218
    invoke-direct {v6, v7, v1}, Li31/a0;-><init>(Ljava/lang/Object;Z)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    goto :goto_2

    .line 225
    :cond_2
    new-instance v4, Li31/b0;

    .line 226
    .line 227
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 228
    .line 229
    invoke-direct {v4, v0, v3, p1, v5}, Li31/b0;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {p0}, Lq41/b;->a()Lq41/a;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    check-cast p0, Lt31/o;

    .line 237
    .line 238
    iget-object p0, p0, Lt31/o;->f:Ll4/v;

    .line 239
    .line 240
    iget-object p0, p0, Ll4/v;->a:Lg4/g;

    .line 241
    .line 242
    iget-object v7, p0, Lg4/g;->e:Ljava/lang/String;

    .line 243
    .line 244
    const/4 v9, 0x0

    .line 245
    const/16 v10, 0x6d

    .line 246
    .line 247
    const/4 v3, 0x0

    .line 248
    const/4 v5, 0x0

    .line 249
    const/4 v6, 0x0

    .line 250
    const/4 v8, 0x0

    .line 251
    invoke-static/range {v2 .. v10}, Li31/b;->a(Li31/b;Ljava/lang/String;Li31/b0;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;I)Li31/b;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    return-object p0

    .line 256
    nop

    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
