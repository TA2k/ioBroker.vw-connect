.class public final synthetic Le31/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Le31/t0;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Le31/t0;->d:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    sget-object v0, Lf2/z;->a:Ll2/u2;

    .line 10
    .line 11
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 12
    .line 13
    return-object v0

    .line 14
    :pswitch_0
    int-to-float v0, v1

    .line 15
    new-instance v1, Lt4/f;

    .line 16
    .line 17
    invoke-direct {v1, v0}, Lt4/f;-><init>(F)V

    .line 18
    .line 19
    .line 20
    return-object v1

    .line 21
    :pswitch_1
    sget-object v0, Lf2/y;->a:Ll2/u2;

    .line 22
    .line 23
    sget-object v0, Lf2/q;->a:Lf2/q;

    .line 24
    .line 25
    return-object v0

    .line 26
    :pswitch_2
    sget-object v0, Lf2/i;->a:Ll2/e0;

    .line 27
    .line 28
    const/high16 v0, 0x3f800000    # 1.0f

    .line 29
    .line 30
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    return-object v0

    .line 35
    :pswitch_3
    const-wide v0, 0xff6200eeL

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 41
    .line 42
    .line 43
    move-result-wide v3

    .line 44
    const-wide v0, 0xff3700b3L

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 50
    .line 51
    .line 52
    move-result-wide v5

    .line 53
    const-wide v0, 0xff03dac6L

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 59
    .line 60
    .line 61
    move-result-wide v7

    .line 62
    const-wide v0, 0xff018786L

    .line 63
    .line 64
    .line 65
    .line 66
    .line 67
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 68
    .line 69
    .line 70
    move-result-wide v9

    .line 71
    sget-wide v11, Le3/s;->e:J

    .line 72
    .line 73
    const-wide v0, 0xffb00020L

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 79
    .line 80
    .line 81
    move-result-wide v15

    .line 82
    sget-wide v19, Le3/s;->b:J

    .line 83
    .line 84
    new-instance v2, Lf2/g;

    .line 85
    .line 86
    move-wide v13, v11

    .line 87
    move-wide/from16 v17, v11

    .line 88
    .line 89
    move-wide/from16 v21, v19

    .line 90
    .line 91
    move-wide/from16 v23, v19

    .line 92
    .line 93
    move-wide/from16 v25, v11

    .line 94
    .line 95
    invoke-direct/range {v2 .. v26}, Lf2/g;-><init>(JJJJJJJJJJJJ)V

    .line 96
    .line 97
    .line 98
    return-object v2

    .line 99
    :pswitch_4
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    return-object v0

    .line 104
    :pswitch_5
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/ApiClient;->d()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    return-object v0

    .line 109
    :pswitch_6
    new-instance v0, Leq0/c;

    .line 110
    .line 111
    int-to-float v1, v1

    .line 112
    invoke-direct {v0, v1}, Leq0/c;-><init>(F)V

    .line 113
    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_7
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    return-object v0

    .line 123
    :pswitch_8
    new-instance v0, Luz0/d;

    .line 124
    .line 125
    sget-object v2, Ltb/u;->a:Ltb/u;

    .line 126
    .line 127
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 128
    .line 129
    .line 130
    return-object v0

    .line 131
    :pswitch_9
    new-instance v0, Luz0/d;

    .line 132
    .line 133
    sget-object v2, Leg/g;->a:Leg/g;

    .line 134
    .line 135
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 136
    .line 137
    .line 138
    return-object v0

    .line 139
    :pswitch_a
    new-instance v0, Luz0/d;

    .line 140
    .line 141
    sget-object v2, Lee/d;->a:Lee/d;

    .line 142
    .line 143
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 144
    .line 145
    .line 146
    return-object v0

    .line 147
    :pswitch_b
    new-instance v0, Luz0/d;

    .line 148
    .line 149
    sget-object v2, Lee/a;->a:Lee/a;

    .line 150
    .line 151
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 152
    .line 153
    .line 154
    return-object v0

    .line 155
    :pswitch_c
    new-instance v0, Luz0/d;

    .line 156
    .line 157
    sget-object v2, Le31/w3;->a:Le31/w3;

    .line 158
    .line 159
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 160
    .line 161
    .line 162
    return-object v0

    .line 163
    :pswitch_d
    new-instance v0, Luz0/d;

    .line 164
    .line 165
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 166
    .line 167
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 168
    .line 169
    .line 170
    return-object v0

    .line 171
    :pswitch_e
    new-instance v0, Luz0/d;

    .line 172
    .line 173
    sget-object v2, Le31/j3;->a:Le31/j3;

    .line 174
    .line 175
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 176
    .line 177
    .line 178
    return-object v0

    .line 179
    :pswitch_f
    new-instance v0, Luz0/d;

    .line 180
    .line 181
    sget-object v2, Le31/a3;->a:Le31/a3;

    .line 182
    .line 183
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 184
    .line 185
    .line 186
    return-object v0

    .line 187
    :pswitch_10
    new-instance v0, Luz0/d;

    .line 188
    .line 189
    sget-object v2, Le31/g3;->a:Le31/g3;

    .line 190
    .line 191
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 192
    .line 193
    .line 194
    return-object v0

    .line 195
    :pswitch_11
    new-instance v0, Luz0/d;

    .line 196
    .line 197
    sget-object v2, Le31/t3;->a:Le31/t3;

    .line 198
    .line 199
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 200
    .line 201
    .line 202
    return-object v0

    .line 203
    :pswitch_12
    new-instance v0, Luz0/d;

    .line 204
    .line 205
    sget-object v2, Le31/x1;->a:Le31/x1;

    .line 206
    .line 207
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 208
    .line 209
    .line 210
    return-object v0

    .line 211
    :pswitch_13
    new-instance v0, Luz0/d;

    .line 212
    .line 213
    sget-object v2, Le31/m1;->a:Le31/m1;

    .line 214
    .line 215
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 216
    .line 217
    .line 218
    return-object v0

    .line 219
    :pswitch_14
    const-string v0, "technology.cariad.appointmentbooking.base.data.models.ResetMode"

    .line 220
    .line 221
    invoke-static {}, Le31/k2;->values()[Le31/k2;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    invoke-static {v0, v1}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    return-object v0

    .line 230
    :pswitch_15
    new-instance v0, Luz0/d;

    .line 231
    .line 232
    sget-object v2, Le31/a2;->a:Le31/a2;

    .line 233
    .line 234
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 235
    .line 236
    .line 237
    return-object v0

    .line 238
    :pswitch_16
    sget-object v0, Le31/k2;->Companion:Le31/j2;

    .line 239
    .line 240
    invoke-virtual {v0}, Le31/j2;->serializer()Lqz0/a;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    return-object v0

    .line 245
    :pswitch_17
    sget-object v0, Le31/w1;->Companion:Le31/v1;

    .line 246
    .line 247
    invoke-virtual {v0}, Le31/v1;->serializer()Lqz0/a;

    .line 248
    .line 249
    .line 250
    move-result-object v0

    .line 251
    return-object v0

    .line 252
    :pswitch_18
    const-string v0, "technology.cariad.appointmentbooking.base.data.models.ModelType"

    .line 253
    .line 254
    invoke-static {}, Le31/w1;->values()[Le31/w1;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    invoke-static {v0, v1}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    return-object v0

    .line 263
    :pswitch_19
    new-instance v0, Luz0/d;

    .line 264
    .line 265
    sget-object v2, Le31/c1;->a:Le31/c1;

    .line 266
    .line 267
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 268
    .line 269
    .line 270
    return-object v0

    .line 271
    :pswitch_1a
    new-instance v0, Luz0/d;

    .line 272
    .line 273
    sget-object v2, Le31/i1;->a:Le31/i1;

    .line 274
    .line 275
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 276
    .line 277
    .line 278
    return-object v0

    .line 279
    :pswitch_1b
    new-instance v0, Luz0/d;

    .line 280
    .line 281
    sget-object v2, Le31/z0;->a:Le31/z0;

    .line 282
    .line 283
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 284
    .line 285
    .line 286
    return-object v0

    .line 287
    :pswitch_1c
    new-instance v0, Luz0/d;

    .line 288
    .line 289
    sget-object v2, Le31/f1;->a:Le31/f1;

    .line 290
    .line 291
    invoke-direct {v0, v2, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 292
    .line 293
    .line 294
    return-object v0

    .line 295
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
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
