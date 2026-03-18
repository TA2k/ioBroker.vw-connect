.class public final synthetic Lle/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz9/y;


# direct methods
.method public synthetic constructor <init>(Lz9/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Lle/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lle/a;->e:Lz9/y;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lle/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    const/4 v1, 0x6

    .line 8
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 9
    .line 10
    const-string v2, "/subscribe"

    .line 11
    .line 12
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 13
    .line 14
    .line 15
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    new-instance v0, Lz70/e0;

    .line 19
    .line 20
    const/16 v1, 0x12

    .line 21
    .line 22
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 26
    .line 27
    const-string v1, "/overview"

    .line 28
    .line 29
    invoke-virtual {p0, v1, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :pswitch_1
    new-instance v0, Lz9/z;

    .line 34
    .line 35
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 36
    .line 37
    iget-object v1, p0, Lz9/y;->a:Landroid/content/Context;

    .line 38
    .line 39
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 40
    .line 41
    iget-object p0, p0, Lca/g;->s:Lz9/k0;

    .line 42
    .line 43
    const-string v2, "context"

    .line 44
    .line 45
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v1, "navigatorProvider"

    .line 49
    .line 50
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object v0

    .line 57
    :pswitch_2
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 58
    .line 59
    iget-object v0, p0, Lz9/y;->f:Lb/i0;

    .line 60
    .line 61
    iget-boolean v1, p0, Lz9/y;->g:Z

    .line 62
    .line 63
    if-eqz v1, :cond_0

    .line 64
    .line 65
    invoke-virtual {p0}, Lz9/y;->c()I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    const/4 v1, 0x1

    .line 70
    if-le p0, v1, :cond_0

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_0
    const/4 v1, 0x0

    .line 74
    :goto_1
    invoke-virtual {v0, v1}, Lb/a0;->setEnabled(Z)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :pswitch_3
    const/4 v0, 0x0

    .line 79
    const/4 v1, 0x6

    .line 80
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 81
    .line 82
    const-string v2, "MULTIPLE_FIXED_RATE_INTERMEDIATE_DAY_SUCCESS"

    .line 83
    .line 84
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_4
    const/4 v0, 0x0

    .line 89
    const/4 v1, 0x6

    .line 90
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 91
    .line 92
    const-string v2, "MULTIPLE_FIXED_RATE_SETUP_PRICE"

    .line 93
    .line 94
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :pswitch_5
    const/4 v0, 0x0

    .line 99
    const/4 v1, 0x6

    .line 100
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 101
    .line 102
    const-string v2, "MULTIPLE_FIXED_RATE_PRICE_SELECTION"

    .line 103
    .line 104
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :pswitch_6
    const/4 v0, 0x0

    .line 109
    const/4 v1, 0x6

    .line 110
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 111
    .line 112
    const-string v2, "MULTIPLE_FIXED_RATE_SETUP_DAYS"

    .line 113
    .line 114
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :pswitch_7
    const/4 v0, 0x0

    .line 119
    const/4 v1, 0x6

    .line 120
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 121
    .line 122
    const-string v2, "MULTIPLE_FIXED_RATE_INTERMEDIATE_SEASON_SUCCESS"

    .line 123
    .line 124
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    :pswitch_8
    const/4 v0, 0x0

    .line 129
    const/4 v1, 0x6

    .line 130
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 131
    .line 132
    const-string v2, "MULTIPLE_FIXED_RATE_SETUP_SEASONS"

    .line 133
    .line 134
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :pswitch_9
    const/4 v0, 0x0

    .line 139
    const/4 v1, 0x6

    .line 140
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 141
    .line 142
    const-string v2, "MULTIPLE_FIXED_RATE_DAYS_SELECTION"

    .line 143
    .line 144
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 145
    .line 146
    .line 147
    goto/16 :goto_0

    .line 148
    .line 149
    :pswitch_a
    const/4 v0, 0x0

    .line 150
    const/4 v1, 0x6

    .line 151
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 152
    .line 153
    const-string v2, "DYNAMIC_RATE_GRAPH"

    .line 154
    .line 155
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 156
    .line 157
    .line 158
    goto/16 :goto_0

    .line 159
    .line 160
    :pswitch_b
    const/4 v0, 0x0

    .line 161
    const/4 v1, 0x6

    .line 162
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 163
    .line 164
    const-string v2, "MULTIPLE_FIXED_RATE_GRAPH"

    .line 165
    .line 166
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 167
    .line 168
    .line 169
    goto/16 :goto_0

    .line 170
    .line 171
    :pswitch_c
    const/4 v0, 0x0

    .line 172
    const/4 v1, 0x6

    .line 173
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 174
    .line 175
    const-string v2, "FIXED_RATE_GRAPH"

    .line 176
    .line 177
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 178
    .line 179
    .line 180
    goto/16 :goto_0

    .line 181
    .line 182
    :pswitch_d
    const/4 v0, 0x0

    .line 183
    const/4 v1, 0x6

    .line 184
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 185
    .line 186
    const-string v2, "SETUP_CURRENCY"

    .line 187
    .line 188
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 189
    .line 190
    .line 191
    goto/16 :goto_0

    .line 192
    .line 193
    :pswitch_e
    new-instance v0, Leh/d;

    .line 194
    .line 195
    const/4 v1, 0x2

    .line 196
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 197
    .line 198
    invoke-direct {v0, p0, v1}, Leh/d;-><init>(Lz9/y;I)V

    .line 199
    .line 200
    .line 201
    const-string v1, "KOLA_OVERVIEW_ROUTE"

    .line 202
    .line 203
    invoke-virtual {p0, v1, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 204
    .line 205
    .line 206
    goto/16 :goto_0

    .line 207
    .line 208
    :pswitch_f
    const/4 v0, 0x0

    .line 209
    const/4 v1, 0x6

    .line 210
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 211
    .line 212
    const-string v2, "KOLA_WIZARD_SUCCESS_ROUTE"

    .line 213
    .line 214
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_0

    .line 218
    .line 219
    :pswitch_10
    const/4 v0, 0x0

    .line 220
    const/4 v1, 0x6

    .line 221
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 222
    .line 223
    const-string v2, "KOLA_WIZARD_ROUTE"

    .line 224
    .line 225
    invoke-static {p0, v2, v0, v1}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 226
    .line 227
    .line 228
    goto/16 :goto_0

    .line 229
    .line 230
    :pswitch_11
    new-instance v0, Leh/d;

    .line 231
    .line 232
    const/4 v1, 0x1

    .line 233
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 234
    .line 235
    invoke-direct {v0, p0, v1}, Leh/d;-><init>(Lz9/y;I)V

    .line 236
    .line 237
    .line 238
    const-string v1, "KOLA_WIZARD_ONBOARDING_ROUTE"

    .line 239
    .line 240
    invoke-virtual {p0, v1, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 241
    .line 242
    .line 243
    goto/16 :goto_0

    .line 244
    .line 245
    :pswitch_12
    iget-object p0, p0, Lle/a;->e:Lz9/y;

    .line 246
    .line 247
    invoke-virtual {p0}, Lz9/y;->g()V

    .line 248
    .line 249
    .line 250
    goto/16 :goto_0

    .line 251
    .line 252
    nop

    .line 253
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
