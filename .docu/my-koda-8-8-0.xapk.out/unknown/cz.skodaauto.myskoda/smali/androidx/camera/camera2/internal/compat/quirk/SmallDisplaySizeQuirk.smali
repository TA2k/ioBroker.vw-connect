.class public Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/p1;


# static fields
.field public static final a:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;->a:Ljava/util/HashMap;

    .line 7
    .line 8
    new-instance v1, Landroid/util/Size;

    .line 9
    .line 10
    const/16 v2, 0x438

    .line 11
    .line 12
    const/16 v3, 0x924

    .line 13
    .line 14
    invoke-direct {v1, v2, v3}, Landroid/util/Size;-><init>(II)V

    .line 15
    .line 16
    .line 17
    const-string v4, "REDMI NOTE 8"

    .line 18
    .line 19
    invoke-virtual {v0, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    new-instance v1, Landroid/util/Size;

    .line 23
    .line 24
    invoke-direct {v1, v2, v3}, Landroid/util/Size;-><init>(II)V

    .line 25
    .line 26
    .line 27
    const-string v4, "REDMI NOTE 7"

    .line 28
    .line 29
    invoke-virtual {v0, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    new-instance v1, Landroid/util/Size;

    .line 33
    .line 34
    const/16 v4, 0x618

    .line 35
    .line 36
    const/16 v5, 0x2d0

    .line 37
    .line 38
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 39
    .line 40
    .line 41
    const-string v4, "SM-A207M"

    .line 42
    .line 43
    invoke-virtual {v0, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    new-instance v1, Landroid/util/Size;

    .line 47
    .line 48
    invoke-direct {v1, v2, v3}, Landroid/util/Size;-><init>(II)V

    .line 49
    .line 50
    .line 51
    const-string v4, "REDMI NOTE 7S"

    .line 52
    .line 53
    invoke-virtual {v0, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    new-instance v1, Landroid/util/Size;

    .line 57
    .line 58
    const/16 v4, 0x640

    .line 59
    .line 60
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 61
    .line 62
    .line 63
    const-string v6, "SM-A127F"

    .line 64
    .line 65
    invoke-virtual {v0, v6, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    new-instance v1, Landroid/util/Size;

    .line 69
    .line 70
    const/16 v6, 0x960

    .line 71
    .line 72
    invoke-direct {v1, v2, v6}, Landroid/util/Size;-><init>(II)V

    .line 73
    .line 74
    .line 75
    const-string v7, "SM-A536E"

    .line 76
    .line 77
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    new-instance v1, Landroid/util/Size;

    .line 81
    .line 82
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 83
    .line 84
    .line 85
    const-string v7, "220233L2I"

    .line 86
    .line 87
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    new-instance v1, Landroid/util/Size;

    .line 91
    .line 92
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 93
    .line 94
    .line 95
    const-string v7, "V2149"

    .line 96
    .line 97
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    new-instance v1, Landroid/util/Size;

    .line 101
    .line 102
    invoke-direct {v1, v2, v3}, Landroid/util/Size;-><init>(II)V

    .line 103
    .line 104
    .line 105
    const-string v3, "VIVO 1920"

    .line 106
    .line 107
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    new-instance v1, Landroid/util/Size;

    .line 111
    .line 112
    invoke-direct {v1, v2, v6}, Landroid/util/Size;-><init>(II)V

    .line 113
    .line 114
    .line 115
    const-string v3, "CPH2223"

    .line 116
    .line 117
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    new-instance v1, Landroid/util/Size;

    .line 121
    .line 122
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 123
    .line 124
    .line 125
    const-string v3, "V2029"

    .line 126
    .line 127
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    new-instance v1, Landroid/util/Size;

    .line 131
    .line 132
    const/16 v3, 0x5f0

    .line 133
    .line 134
    invoke-direct {v1, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 135
    .line 136
    .line 137
    const-string v7, "CPH1901"

    .line 138
    .line 139
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    new-instance v1, Landroid/util/Size;

    .line 143
    .line 144
    invoke-direct {v1, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 145
    .line 146
    .line 147
    const-string v7, "REDMI Y3"

    .line 148
    .line 149
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    new-instance v1, Landroid/util/Size;

    .line 153
    .line 154
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 155
    .line 156
    .line 157
    const-string v7, "SM-A045M"

    .line 158
    .line 159
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    new-instance v1, Landroid/util/Size;

    .line 163
    .line 164
    const/16 v7, 0x968

    .line 165
    .line 166
    invoke-direct {v1, v2, v7}, Landroid/util/Size;-><init>(II)V

    .line 167
    .line 168
    .line 169
    const-string v8, "SM-A146U"

    .line 170
    .line 171
    invoke-virtual {v0, v8, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    new-instance v1, Landroid/util/Size;

    .line 175
    .line 176
    invoke-direct {v1, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 177
    .line 178
    .line 179
    const-string v8, "CPH1909"

    .line 180
    .line 181
    invoke-virtual {v0, v8, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    new-instance v1, Landroid/util/Size;

    .line 185
    .line 186
    invoke-direct {v1, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 187
    .line 188
    .line 189
    const-string v8, "NOKIA 4.2"

    .line 190
    .line 191
    invoke-virtual {v0, v8, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    new-instance v1, Landroid/util/Size;

    .line 195
    .line 196
    const/16 v8, 0x5a0

    .line 197
    .line 198
    const/16 v9, 0xb90

    .line 199
    .line 200
    invoke-direct {v1, v8, v9}, Landroid/util/Size;-><init>(II)V

    .line 201
    .line 202
    .line 203
    const-string v8, "SM-G960U1"

    .line 204
    .line 205
    invoke-virtual {v0, v8, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    new-instance v1, Landroid/util/Size;

    .line 209
    .line 210
    invoke-direct {v1, v2, v7}, Landroid/util/Size;-><init>(II)V

    .line 211
    .line 212
    .line 213
    const-string v7, "SM-A137F"

    .line 214
    .line 215
    invoke-virtual {v0, v7, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    new-instance v1, Landroid/util/Size;

    .line 219
    .line 220
    invoke-direct {v1, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 221
    .line 222
    .line 223
    const-string v3, "VIVO 1816"

    .line 224
    .line 225
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    new-instance v1, Landroid/util/Size;

    .line 229
    .line 230
    const/16 v3, 0x64c

    .line 231
    .line 232
    invoke-direct {v1, v5, v3}, Landroid/util/Size;-><init>(II)V

    .line 233
    .line 234
    .line 235
    const-string v3, "INFINIX X6817"

    .line 236
    .line 237
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    new-instance v1, Landroid/util/Size;

    .line 241
    .line 242
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 243
    .line 244
    .line 245
    const-string v3, "SM-A037F"

    .line 246
    .line 247
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    new-instance v1, Landroid/util/Size;

    .line 251
    .line 252
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 253
    .line 254
    .line 255
    const-string v3, "NOKIA 2.4"

    .line 256
    .line 257
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    new-instance v1, Landroid/util/Size;

    .line 261
    .line 262
    invoke-direct {v1, v5, v4}, Landroid/util/Size;-><init>(II)V

    .line 263
    .line 264
    .line 265
    const-string v3, "SM-A125M"

    .line 266
    .line 267
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    new-instance v1, Landroid/util/Size;

    .line 271
    .line 272
    invoke-direct {v1, v2, v6}, Landroid/util/Size;-><init>(II)V

    .line 273
    .line 274
    .line 275
    const-string v2, "INFINIX X670"

    .line 276
    .line 277
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
