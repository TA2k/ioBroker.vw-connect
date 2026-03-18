.class synthetic Lcom/google/android/filament/Texture$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Texture;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1009
    name = null
.end annotation


# static fields
.field static final synthetic $SwitchMap$com$google$android$filament$Texture$Format:[I

.field static final synthetic $SwitchMap$com$google$android$filament$Texture$Type:[I


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    invoke-static {}, Lcom/google/android/filament/Texture$Type;->values()[Lcom/google/android/filament/Texture$Type;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    sput-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    :try_start_0
    sget-object v2, Lcom/google/android/filament/Texture$Type;->UBYTE:Lcom/google/android/filament/Texture$Type;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    :catch_0
    const/4 v0, 0x2

    .line 20
    :try_start_1
    sget-object v2, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 21
    .line 22
    sget-object v3, Lcom/google/android/filament/Texture$Type;->BYTE:Lcom/google/android/filament/Texture$Type;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    aput v0, v2, v3
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 29
    .line 30
    :catch_1
    const/4 v2, 0x3

    .line 31
    :try_start_2
    sget-object v3, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 32
    .line 33
    sget-object v4, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    .line 34
    .line 35
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    aput v2, v3, v4
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 40
    .line 41
    :catch_2
    const/4 v3, 0x4

    .line 42
    :try_start_3
    sget-object v4, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 43
    .line 44
    sget-object v5, Lcom/google/android/filament/Texture$Type;->USHORT:Lcom/google/android/filament/Texture$Type;

    .line 45
    .line 46
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    aput v3, v4, v5
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 51
    .line 52
    :catch_3
    const/4 v4, 0x5

    .line 53
    :try_start_4
    sget-object v5, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 54
    .line 55
    sget-object v6, Lcom/google/android/filament/Texture$Type;->SHORT:Lcom/google/android/filament/Texture$Type;

    .line 56
    .line 57
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    aput v4, v5, v6
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 62
    .line 63
    :catch_4
    const/4 v5, 0x6

    .line 64
    :try_start_5
    sget-object v6, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 65
    .line 66
    sget-object v7, Lcom/google/android/filament/Texture$Type;->HALF:Lcom/google/android/filament/Texture$Type;

    .line 67
    .line 68
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 69
    .line 70
    .line 71
    move-result v7

    .line 72
    aput v5, v6, v7
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 73
    .line 74
    :catch_5
    const/4 v6, 0x7

    .line 75
    :try_start_6
    sget-object v7, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 76
    .line 77
    sget-object v8, Lcom/google/android/filament/Texture$Type;->UINT:Lcom/google/android/filament/Texture$Type;

    .line 78
    .line 79
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v8

    .line 83
    aput v6, v7, v8
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 84
    .line 85
    :catch_6
    const/16 v7, 0x8

    .line 86
    .line 87
    :try_start_7
    sget-object v8, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 88
    .line 89
    sget-object v9, Lcom/google/android/filament/Texture$Type;->INT:Lcom/google/android/filament/Texture$Type;

    .line 90
    .line 91
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    aput v7, v8, v9
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 96
    .line 97
    :catch_7
    const/16 v8, 0x9

    .line 98
    .line 99
    :try_start_8
    sget-object v9, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 100
    .line 101
    sget-object v10, Lcom/google/android/filament/Texture$Type;->FLOAT:Lcom/google/android/filament/Texture$Type;

    .line 102
    .line 103
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 104
    .line 105
    .line 106
    move-result v10

    .line 107
    aput v8, v9, v10
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 108
    .line 109
    :catch_8
    const/16 v9, 0xa

    .line 110
    .line 111
    :try_start_9
    sget-object v10, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 112
    .line 113
    sget-object v11, Lcom/google/android/filament/Texture$Type;->UINT_10F_11F_11F_REV:Lcom/google/android/filament/Texture$Type;

    .line 114
    .line 115
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 116
    .line 117
    .line 118
    move-result v11

    .line 119
    aput v9, v10, v11
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 120
    .line 121
    :catch_9
    const/16 v10, 0xb

    .line 122
    .line 123
    :try_start_a
    sget-object v11, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 124
    .line 125
    sget-object v12, Lcom/google/android/filament/Texture$Type;->USHORT_565:Lcom/google/android/filament/Texture$Type;

    .line 126
    .line 127
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 128
    .line 129
    .line 130
    move-result v12

    .line 131
    aput v10, v11, v12
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 132
    .line 133
    :catch_a
    invoke-static {}, Lcom/google/android/filament/Texture$Format;->values()[Lcom/google/android/filament/Texture$Format;

    .line 134
    .line 135
    .line 136
    move-result-object v11

    .line 137
    array-length v11, v11

    .line 138
    new-array v11, v11, [I

    .line 139
    .line 140
    sput-object v11, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 141
    .line 142
    :try_start_b
    sget-object v12, Lcom/google/android/filament/Texture$Format;->R:Lcom/google/android/filament/Texture$Format;

    .line 143
    .line 144
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 145
    .line 146
    .line 147
    move-result v12

    .line 148
    aput v1, v11, v12
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 149
    .line 150
    :catch_b
    :try_start_c
    sget-object v1, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 151
    .line 152
    sget-object v11, Lcom/google/android/filament/Texture$Format;->R_INTEGER:Lcom/google/android/filament/Texture$Format;

    .line 153
    .line 154
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 155
    .line 156
    .line 157
    move-result v11

    .line 158
    aput v0, v1, v11
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 159
    .line 160
    :catch_c
    :try_start_d
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 161
    .line 162
    sget-object v1, Lcom/google/android/filament/Texture$Format;->DEPTH_COMPONENT:Lcom/google/android/filament/Texture$Format;

    .line 163
    .line 164
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 165
    .line 166
    .line 167
    move-result v1

    .line 168
    aput v2, v0, v1
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 169
    .line 170
    :catch_d
    :try_start_e
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 171
    .line 172
    sget-object v1, Lcom/google/android/filament/Texture$Format;->ALPHA:Lcom/google/android/filament/Texture$Format;

    .line 173
    .line 174
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    aput v3, v0, v1
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 179
    .line 180
    :catch_e
    :try_start_f
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 181
    .line 182
    sget-object v1, Lcom/google/android/filament/Texture$Format;->RG:Lcom/google/android/filament/Texture$Format;

    .line 183
    .line 184
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    aput v4, v0, v1
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 189
    .line 190
    :catch_f
    :try_start_10
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 191
    .line 192
    sget-object v1, Lcom/google/android/filament/Texture$Format;->RG_INTEGER:Lcom/google/android/filament/Texture$Format;

    .line 193
    .line 194
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 195
    .line 196
    .line 197
    move-result v1

    .line 198
    aput v5, v0, v1
    :try_end_10
    .catch Ljava/lang/NoSuchFieldError; {:try_start_10 .. :try_end_10} :catch_10

    .line 199
    .line 200
    :catch_10
    :try_start_11
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 201
    .line 202
    sget-object v1, Lcom/google/android/filament/Texture$Format;->DEPTH_STENCIL:Lcom/google/android/filament/Texture$Format;

    .line 203
    .line 204
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 205
    .line 206
    .line 207
    move-result v1

    .line 208
    aput v6, v0, v1
    :try_end_11
    .catch Ljava/lang/NoSuchFieldError; {:try_start_11 .. :try_end_11} :catch_11

    .line 209
    .line 210
    :catch_11
    :try_start_12
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 211
    .line 212
    sget-object v1, Lcom/google/android/filament/Texture$Format;->STENCIL_INDEX:Lcom/google/android/filament/Texture$Format;

    .line 213
    .line 214
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 215
    .line 216
    .line 217
    move-result v1

    .line 218
    aput v7, v0, v1
    :try_end_12
    .catch Ljava/lang/NoSuchFieldError; {:try_start_12 .. :try_end_12} :catch_12

    .line 219
    .line 220
    :catch_12
    :try_start_13
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 221
    .line 222
    sget-object v1, Lcom/google/android/filament/Texture$Format;->RGB:Lcom/google/android/filament/Texture$Format;

    .line 223
    .line 224
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 225
    .line 226
    .line 227
    move-result v1

    .line 228
    aput v8, v0, v1
    :try_end_13
    .catch Ljava/lang/NoSuchFieldError; {:try_start_13 .. :try_end_13} :catch_13

    .line 229
    .line 230
    :catch_13
    :try_start_14
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 231
    .line 232
    sget-object v1, Lcom/google/android/filament/Texture$Format;->RGB_INTEGER:Lcom/google/android/filament/Texture$Format;

    .line 233
    .line 234
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 235
    .line 236
    .line 237
    move-result v1

    .line 238
    aput v9, v0, v1
    :try_end_14
    .catch Ljava/lang/NoSuchFieldError; {:try_start_14 .. :try_end_14} :catch_14

    .line 239
    .line 240
    :catch_14
    :try_start_15
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 241
    .line 242
    sget-object v1, Lcom/google/android/filament/Texture$Format;->RGBA:Lcom/google/android/filament/Texture$Format;

    .line 243
    .line 244
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    aput v10, v0, v1
    :try_end_15
    .catch Ljava/lang/NoSuchFieldError; {:try_start_15 .. :try_end_15} :catch_15

    .line 249
    .line 250
    :catch_15
    :try_start_16
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 251
    .line 252
    sget-object v1, Lcom/google/android/filament/Texture$Format;->RGBA_INTEGER:Lcom/google/android/filament/Texture$Format;

    .line 253
    .line 254
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 255
    .line 256
    .line 257
    move-result v1

    .line 258
    const/16 v2, 0xc

    .line 259
    .line 260
    aput v2, v0, v1
    :try_end_16
    .catch Ljava/lang/NoSuchFieldError; {:try_start_16 .. :try_end_16} :catch_16

    .line 261
    .line 262
    :catch_16
    return-void
.end method
