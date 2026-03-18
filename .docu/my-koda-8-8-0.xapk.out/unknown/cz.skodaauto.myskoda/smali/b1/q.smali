.class public final Lb1/q;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:J


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;JI)V
    .locals 0

    .line 1
    iput p4, p0, Lb1/q;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/q;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-wide p2, p0, Lb1/q;->h:J

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lb1/q;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvv/a1;

    .line 7
    .line 8
    const-string v0, "layoutResult"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v2, p1, Lvv/a1;->a:Ljava/util/ArrayList;

    .line 14
    .line 15
    iget-object v3, p1, Lvv/a1;->b:Ljava/util/ArrayList;

    .line 16
    .line 17
    iget-object p1, p0, Lb1/q;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p1, Lvv/c1;

    .line 20
    .line 21
    iget-object v0, p1, Lvv/c1;->c:Le3/s;

    .line 22
    .line 23
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-wide v0, v0, Le3/s;->a:J

    .line 27
    .line 28
    sget-wide v4, Le3/s;->i:J

    .line 29
    .line 30
    cmp-long v4, v0, v4

    .line 31
    .line 32
    if-eqz v4, :cond_0

    .line 33
    .line 34
    :goto_0
    move-wide v4, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    iget-wide v0, p0, Lb1/q;->h:J

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :goto_1
    iget-object p0, p1, Lvv/c1;->d:Ljava/lang/Float;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    new-instance v1, Lvv/y0;

    .line 46
    .line 47
    invoke-direct/range {v1 .. v6}, Lvv/y0;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;JF)V

    .line 48
    .line 49
    .line 50
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 51
    .line 52
    invoke-static {p0, v1}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_0
    iget-object v0, p0, Lb1/q;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Lb1/r;

    .line 60
    .line 61
    iget-object v1, v0, Lb1/r;->u:Lb1/t;

    .line 62
    .line 63
    invoke-virtual {v1}, Lb1/t;->b()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_2

    .line 72
    .line 73
    iget-wide v1, v0, Lb1/r;->v:J

    .line 74
    .line 75
    sget-wide v3, Landroidx/compose/animation/a;->a:J

    .line 76
    .line 77
    invoke-static {v1, v2, v3, v4}, Lt4/l;->a(JJ)Z

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-eqz p1, :cond_1

    .line 82
    .line 83
    iget-wide p0, p0, Lb1/q;->h:J

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_1
    iget-wide p0, v0, Lb1/r;->v:J

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_2
    iget-object p0, v0, Lb1/r;->u:Lb1/t;

    .line 90
    .line 91
    iget-object p0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 92
    .line 93
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    check-cast p0, Ll2/t2;

    .line 98
    .line 99
    if-eqz p0, :cond_3

    .line 100
    .line 101
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Lt4/l;

    .line 106
    .line 107
    iget-wide p0, p0, Lt4/l;->a:J

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_3
    const-wide/16 p0, 0x0

    .line 111
    .line 112
    :goto_2
    new-instance v0, Lt4/l;

    .line 113
    .line 114
    invoke-direct {v0, p0, p1}, Lt4/l;-><init>(J)V

    .line 115
    .line 116
    .line 117
    return-object v0

    .line 118
    :pswitch_1
    check-cast p1, Lc1/r1;

    .line 119
    .line 120
    invoke-interface {p1}, Lc1/r1;->b()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    iget-object v1, p0, Lb1/q;->g:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v1, Lb1/r;

    .line 127
    .line 128
    iget-object v2, v1, Lb1/r;->u:Lb1/t;

    .line 129
    .line 130
    invoke-virtual {v2}, Lb1/t;->b()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    const-wide/16 v2, 0x0

    .line 139
    .line 140
    if-eqz v0, :cond_5

    .line 141
    .line 142
    iget-wide v4, v1, Lb1/r;->v:J

    .line 143
    .line 144
    sget-wide v6, Landroidx/compose/animation/a;->a:J

    .line 145
    .line 146
    invoke-static {v4, v5, v6, v7}, Lt4/l;->a(JJ)Z

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    if-eqz v0, :cond_4

    .line 151
    .line 152
    iget-wide v4, p0, Lb1/q;->h:J

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_4
    iget-wide v4, v1, Lb1/r;->v:J

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_5
    iget-object p0, v1, Lb1/r;->u:Lb1/t;

    .line 159
    .line 160
    iget-object p0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 161
    .line 162
    invoke-interface {p1}, Lc1/r1;->b()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    invoke-virtual {p0, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    check-cast p0, Ll2/t2;

    .line 171
    .line 172
    if-eqz p0, :cond_6

    .line 173
    .line 174
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    check-cast p0, Lt4/l;

    .line 179
    .line 180
    iget-wide v4, p0, Lt4/l;->a:J

    .line 181
    .line 182
    goto :goto_3

    .line 183
    :cond_6
    move-wide v4, v2

    .line 184
    :goto_3
    iget-object p0, v1, Lb1/r;->u:Lb1/t;

    .line 185
    .line 186
    iget-object p0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 187
    .line 188
    invoke-interface {p1}, Lc1/r1;->a()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    check-cast p0, Ll2/t2;

    .line 197
    .line 198
    if-eqz p0, :cond_7

    .line 199
    .line 200
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    check-cast p0, Lt4/l;

    .line 205
    .line 206
    iget-wide v2, p0, Lt4/l;->a:J

    .line 207
    .line 208
    :cond_7
    iget-object p0, v1, Lb1/r;->t:Ll2/b1;

    .line 209
    .line 210
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    check-cast p0, Lb1/f1;

    .line 215
    .line 216
    if-eqz p0, :cond_8

    .line 217
    .line 218
    iget-object p0, p0, Lb1/f1;->a:Lay0/n;

    .line 219
    .line 220
    new-instance p1, Lt4/l;

    .line 221
    .line 222
    invoke-direct {p1, v4, v5}, Lt4/l;-><init>(J)V

    .line 223
    .line 224
    .line 225
    new-instance v0, Lt4/l;

    .line 226
    .line 227
    invoke-direct {v0, v2, v3}, Lt4/l;-><init>(J)V

    .line 228
    .line 229
    .line 230
    invoke-interface {p0, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    check-cast p0, Lc1/a0;

    .line 235
    .line 236
    if-nez p0, :cond_9

    .line 237
    .line 238
    :cond_8
    const/high16 p0, 0x43c80000    # 400.0f

    .line 239
    .line 240
    const/4 p1, 0x5

    .line 241
    const/4 v0, 0x0

    .line 242
    const/4 v1, 0x0

    .line 243
    invoke-static {v0, p0, v1, p1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    :cond_9
    return-object p0

    .line 248
    nop

    .line 249
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
