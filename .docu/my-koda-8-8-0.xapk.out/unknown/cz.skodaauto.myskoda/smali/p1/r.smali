.class public final synthetic Lp1/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lp1/v;


# direct methods
.method public synthetic constructor <init>(Lp1/v;I)V
    .locals 0

    .line 1
    iput p2, p0, Lp1/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lp1/r;->e:Lp1/v;

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
    .locals 12

    .line 1
    iget v0, p0, Lp1/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp1/r;->e:Lp1/v;

    .line 7
    .line 8
    check-cast p1, Lo1/j0;

    .line 9
    .line 10
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {v1}, Lv2/f;->e()Lay0/k;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :goto_0
    move-object v2, v0

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    goto :goto_0

    .line 24
    :goto_1
    invoke-static {v1}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    :try_start_0
    iget p0, p0, Lp1/v;->e:I

    .line 29
    .line 30
    invoke-virtual {p1, p0}, Lo1/j0;->a(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    .line 33
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :catchall_0
    move-exception v0

    .line 40
    move-object p0, v0

    .line 41
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :pswitch_0
    check-cast p1, Ljava/lang/Float;

    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget-object p0, p0, Lp1/r;->e:Lp1/v;

    .line 52
    .line 53
    invoke-static {p0}, Ljp/dd;->b(Lp1/v;)J

    .line 54
    .line 55
    .line 56
    move-result-wide v1

    .line 57
    iget v3, p0, Lp1/v;->i:F

    .line 58
    .line 59
    add-float/2addr v3, v0

    .line 60
    float-to-double v4, v3

    .line 61
    invoke-static {v4, v5}, Lcy0/a;->j(D)J

    .line 62
    .line 63
    .line 64
    move-result-wide v4

    .line 65
    long-to-float v6, v4

    .line 66
    sub-float/2addr v3, v6

    .line 67
    iput v3, p0, Lp1/v;->i:F

    .line 68
    .line 69
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    const v6, 0x38d1b717    # 1.0E-4f

    .line 74
    .line 75
    .line 76
    cmpg-float v3, v3, v6

    .line 77
    .line 78
    if-gez v3, :cond_1

    .line 79
    .line 80
    goto/16 :goto_7

    .line 81
    .line 82
    :cond_1
    add-long v6, v1, v4

    .line 83
    .line 84
    iget-wide v8, p0, Lp1/v;->h:J

    .line 85
    .line 86
    iget-wide v10, p0, Lp1/v;->g:J

    .line 87
    .line 88
    invoke-static/range {v6 .. v11}, Lkp/r9;->g(JJJ)J

    .line 89
    .line 90
    .line 91
    move-result-wide v3

    .line 92
    cmp-long v0, v6, v3

    .line 93
    .line 94
    const/4 v5, 0x0

    .line 95
    const/4 v6, 0x1

    .line 96
    if-eqz v0, :cond_2

    .line 97
    .line 98
    move v0, v6

    .line 99
    goto :goto_2

    .line 100
    :cond_2
    move v0, v5

    .line 101
    :goto_2
    sub-long/2addr v3, v1

    .line 102
    long-to-float v1, v3

    .line 103
    iput v1, p0, Lp1/v;->j:F

    .line 104
    .line 105
    invoke-static {v3, v4}, Ljava/lang/Math;->abs(J)J

    .line 106
    .line 107
    .line 108
    move-result-wide v7

    .line 109
    const-wide/16 v9, 0x0

    .line 110
    .line 111
    cmp-long v2, v7, v9

    .line 112
    .line 113
    const/4 v7, 0x0

    .line 114
    if-eqz v2, :cond_5

    .line 115
    .line 116
    iget-object v2, p0, Lp1/v;->G:Ll2/j1;

    .line 117
    .line 118
    cmpl-float v8, v1, v7

    .line 119
    .line 120
    if-lez v8, :cond_3

    .line 121
    .line 122
    move v8, v6

    .line 123
    goto :goto_3

    .line 124
    :cond_3
    move v8, v5

    .line 125
    :goto_3
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 126
    .line 127
    .line 128
    move-result-object v8

    .line 129
    invoke-virtual {v2, v8}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iget-object v2, p0, Lp1/v;->H:Ll2/j1;

    .line 133
    .line 134
    cmpg-float v1, v1, v7

    .line 135
    .line 136
    if-gez v1, :cond_4

    .line 137
    .line 138
    move v5, v6

    .line 139
    :cond_4
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    invoke-virtual {v2, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    :cond_5
    iget-object v1, p0, Lp1/v;->p:Ll2/j1;

    .line 147
    .line 148
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    check-cast v1, Lp1/o;

    .line 153
    .line 154
    long-to-int v2, v3

    .line 155
    neg-int v5, v2

    .line 156
    invoke-virtual {v1, v5}, Lp1/o;->a(I)Lp1/o;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    if-eqz v1, :cond_7

    .line 161
    .line 162
    iget-object v8, p0, Lp1/v;->b:Lp1/o;

    .line 163
    .line 164
    if-eqz v8, :cond_7

    .line 165
    .line 166
    invoke-virtual {v8, v5}, Lp1/o;->a(I)Lp1/o;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    if-eqz v5, :cond_6

    .line 171
    .line 172
    iput-object v5, p0, Lp1/v;->b:Lp1/o;

    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_6
    const/4 v1, 0x0

    .line 176
    :cond_7
    :goto_4
    if-eqz v1, :cond_8

    .line 177
    .line 178
    iget-boolean v2, p0, Lp1/v;->a:Z

    .line 179
    .line 180
    invoke-virtual {p0, v1, v2, v6}, Lp1/v;->h(Lp1/o;ZZ)V

    .line 181
    .line 182
    .line 183
    iget-object p0, p0, Lp1/v;->C:Ll2/b1;

    .line 184
    .line 185
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    invoke-interface {p0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_8
    iget-object v1, p0, Lp1/v;->d:Lh8/o;

    .line 192
    .line 193
    iget-object v5, v1, Lh8/o;->b:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v5, Lp1/v;

    .line 196
    .line 197
    iget-object v1, v1, Lh8/o;->d:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v1, Ll2/f1;

    .line 200
    .line 201
    invoke-virtual {v5}, Lp1/v;->o()I

    .line 202
    .line 203
    .line 204
    move-result v6

    .line 205
    if-nez v6, :cond_9

    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_9
    int-to-float v2, v2

    .line 209
    invoke-virtual {v5}, Lp1/v;->o()I

    .line 210
    .line 211
    .line 212
    move-result v5

    .line 213
    int-to-float v5, v5

    .line 214
    div-float v7, v2, v5

    .line 215
    .line 216
    :goto_5
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 217
    .line 218
    .line 219
    move-result v2

    .line 220
    add-float/2addr v2, v7

    .line 221
    invoke-virtual {v1, v2}, Ll2/f1;->p(F)V

    .line 222
    .line 223
    .line 224
    iget-object p0, p0, Lp1/v;->y:Ll2/j1;

    .line 225
    .line 226
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    check-cast p0, Lv3/h0;

    .line 231
    .line 232
    if-eqz p0, :cond_a

    .line 233
    .line 234
    invoke-virtual {p0}, Lv3/h0;->l()V

    .line 235
    .line 236
    .line 237
    :cond_a
    :goto_6
    if-eqz v0, :cond_b

    .line 238
    .line 239
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 240
    .line 241
    .line 242
    move-result-object p1

    .line 243
    :cond_b
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 244
    .line 245
    .line 246
    move-result v0

    .line 247
    :goto_7
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 248
    .line 249
    .line 250
    move-result-object p0

    .line 251
    return-object p0

    .line 252
    nop

    .line 253
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
