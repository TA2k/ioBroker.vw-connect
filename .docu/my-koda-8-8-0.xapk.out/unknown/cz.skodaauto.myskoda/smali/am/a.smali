.class public final synthetic Lam/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt3/e1;


# direct methods
.method public synthetic constructor <init>(Lt3/e1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lam/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lam/a;->e:Lt3/e1;

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
    .locals 8

    .line 1
    iget v0, p0, Lam/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lt3/d1;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 10
    .line 11
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 12
    .line 13
    .line 14
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    const/4 v0, 0x0

    .line 18
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 19
    .line 20
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :pswitch_1
    const/4 v0, 0x0

    .line 25
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 26
    .line 27
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :pswitch_2
    const/4 v0, 0x0

    .line 32
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 33
    .line 34
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :pswitch_3
    const/4 v0, 0x0

    .line 39
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 40
    .line 41
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :pswitch_4
    const/4 v0, 0x0

    .line 46
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 47
    .line 48
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_5
    invoke-virtual {p1}, Lt3/d1;->d()Lt4/m;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 57
    .line 58
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 59
    .line 60
    const-wide/16 v2, 0x0

    .line 61
    .line 62
    const/4 v4, 0x0

    .line 63
    const/4 v5, 0x0

    .line 64
    if-eq v0, v1, :cond_1

    .line 65
    .line 66
    invoke-virtual {p1}, Lt3/d1;->f()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-nez v0, :cond_0

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_0
    invoke-virtual {p1}, Lt3/d1;->f()I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget v1, p0, Lt3/e1;->d:I

    .line 78
    .line 79
    sub-int/2addr v0, v1

    .line 80
    long-to-int v1, v2

    .line 81
    sub-int/2addr v0, v1

    .line 82
    int-to-long v2, v0

    .line 83
    const/16 v0, 0x20

    .line 84
    .line 85
    shl-long/2addr v2, v0

    .line 86
    int-to-long v0, v1

    .line 87
    const-wide v6, 0xffffffffL

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    and-long/2addr v0, v6

    .line 93
    or-long/2addr v0, v2

    .line 94
    invoke-static {p1, p0}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 95
    .line 96
    .line 97
    iget-wide v2, p0, Lt3/e1;->h:J

    .line 98
    .line 99
    invoke-static {v0, v1, v2, v3}, Lt4/j;->d(JJ)J

    .line 100
    .line 101
    .line 102
    move-result-wide v0

    .line 103
    invoke-virtual {p0, v0, v1, v4, v5}, Lt3/e1;->l0(JFLay0/k;)V

    .line 104
    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_1
    :goto_1
    invoke-static {p1, p0}, Lt3/d1;->b(Lt3/d1;Lt3/e1;)V

    .line 108
    .line 109
    .line 110
    iget-wide v0, p0, Lt3/e1;->h:J

    .line 111
    .line 112
    invoke-static {v2, v3, v0, v1}, Lt4/j;->d(JJ)J

    .line 113
    .line 114
    .line 115
    move-result-wide v0

    .line 116
    invoke-virtual {p0, v0, v1, v4, v5}, Lt3/e1;->l0(JFLay0/k;)V

    .line 117
    .line 118
    .line 119
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_6
    const/4 v0, 0x0

    .line 123
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 124
    .line 125
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 126
    .line 127
    .line 128
    goto :goto_0

    .line 129
    :pswitch_7
    const/4 v0, 0x0

    .line 130
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 131
    .line 132
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 133
    .line 134
    .line 135
    goto :goto_0

    .line 136
    :pswitch_8
    const-string v0, "$this$layout"

    .line 137
    .line 138
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const/4 v0, 0x0

    .line 142
    const/4 v1, 0x0

    .line 143
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 144
    .line 145
    invoke-virtual {p1, p0, v0, v0, v1}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 146
    .line 147
    .line 148
    goto/16 :goto_0

    .line 149
    .line 150
    :pswitch_9
    const-string v0, "$this$layout"

    .line 151
    .line 152
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 156
    .line 157
    if-eqz p0, :cond_2

    .line 158
    .line 159
    const/4 v0, 0x0

    .line 160
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 161
    .line 162
    .line 163
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0

    .line 166
    :pswitch_a
    const-string v0, "$this$layout"

    .line 167
    .line 168
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    const/4 v0, 0x0

    .line 172
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 173
    .line 174
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 175
    .line 176
    .line 177
    goto/16 :goto_0

    .line 178
    .line 179
    :pswitch_b
    const/4 v0, 0x0

    .line 180
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 181
    .line 182
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 183
    .line 184
    .line 185
    goto/16 :goto_0

    .line 186
    .line 187
    :pswitch_c
    const/4 v0, 0x0

    .line 188
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 189
    .line 190
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 191
    .line 192
    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :pswitch_d
    const/4 v0, 0x0

    .line 196
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 197
    .line 198
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 199
    .line 200
    .line 201
    goto/16 :goto_0

    .line 202
    .line 203
    :pswitch_e
    const/4 v0, 0x0

    .line 204
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 205
    .line 206
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 207
    .line 208
    .line 209
    goto/16 :goto_0

    .line 210
    .line 211
    :pswitch_f
    const/4 v0, 0x0

    .line 212
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 213
    .line 214
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_0

    .line 218
    .line 219
    :pswitch_10
    const/4 v0, 0x0

    .line 220
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 221
    .line 222
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 223
    .line 224
    .line 225
    goto/16 :goto_0

    .line 226
    .line 227
    :pswitch_11
    const/4 v0, 0x0

    .line 228
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 229
    .line 230
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 231
    .line 232
    .line 233
    goto/16 :goto_0

    .line 234
    .line 235
    :pswitch_12
    const/4 v0, 0x0

    .line 236
    iget-object p0, p0, Lam/a;->e:Lt3/e1;

    .line 237
    .line 238
    invoke-static {p1, p0, v0, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 239
    .line 240
    .line 241
    goto/16 :goto_0

    .line 242
    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
