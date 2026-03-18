.class public final Ly01/j;
.super Ly01/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ly01/j;->b:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;ILjava/io/StringWriter;)I
    .locals 7

    .line 1
    iget p0, p0, Ly01/j;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/16 v0, 0x5c

    .line 11
    .line 12
    if-ne p0, v0, :cond_3

    .line 13
    .line 14
    add-int/lit8 p0, p2, 0x1

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-ge p0, v0, :cond_3

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    const/16 v0, 0x75

    .line 27
    .line 28
    if-ne p0, v0, :cond_3

    .line 29
    .line 30
    const/4 p0, 0x2

    .line 31
    :goto_0
    add-int v1, p2, p0

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-ge v1, v2, :cond_0

    .line 38
    .line 39
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-ne v2, v0, :cond_0

    .line 44
    .line 45
    add-int/lit8 p0, p0, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-ge v1, v0, :cond_1

    .line 53
    .line 54
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    const/16 v1, 0x2b

    .line 59
    .line 60
    if-ne v0, v1, :cond_1

    .line 61
    .line 62
    add-int/lit8 p0, p0, 0x1

    .line 63
    .line 64
    :cond_1
    add-int v0, p2, p0

    .line 65
    .line 66
    add-int/lit8 v1, v0, 0x4

    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-gt v1, v2, :cond_2

    .line 73
    .line 74
    invoke-virtual {p1, v0, v1}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    :try_start_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    const/16 v0, 0x10

    .line 83
    .line 84
    invoke-static {p2, v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    int-to-char p2, p2

    .line 89
    invoke-virtual {p3, p2}, Ljava/io/Writer;->write(I)V
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 90
    .line 91
    .line 92
    add-int/lit8 p0, p0, 0x4

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :catch_0
    move-exception p0

    .line 96
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 97
    .line 98
    new-instance p3, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    const-string v0, "Unable to parse unicode value: "

    .line 101
    .line 102
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-direct {p2, p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 113
    .line 114
    .line 115
    throw p2

    .line 116
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 117
    .line 118
    new-instance p3, Ljava/lang/StringBuilder;

    .line 119
    .line 120
    const-string v0, "Less than 4 hex digits in unicode value: \'"

    .line 121
    .line 122
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    invoke-virtual {p1, p2, v0}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string p1, "\' due to end of CharSequence"

    .line 137
    .line 138
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_3
    const/4 p0, 0x0

    .line 150
    :goto_1
    return p0

    .line 151
    :pswitch_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    sub-int/2addr p0, p2

    .line 156
    const/4 v0, 0x1

    .line 157
    sub-int/2addr p0, v0

    .line 158
    new-instance v1, Ljava/lang/StringBuilder;

    .line 159
    .line 160
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    const/16 v3, 0x5c

    .line 168
    .line 169
    if-ne v2, v3, :cond_5

    .line 170
    .line 171
    if-lez p0, :cond_5

    .line 172
    .line 173
    add-int/lit8 v2, p2, 0x1

    .line 174
    .line 175
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 176
    .line 177
    .line 178
    move-result v3

    .line 179
    const/16 v4, 0x30

    .line 180
    .line 181
    if-lt v3, v4, :cond_5

    .line 182
    .line 183
    const/16 v5, 0x37

    .line 184
    .line 185
    if-gt v3, v5, :cond_5

    .line 186
    .line 187
    add-int/lit8 v3, p2, 0x2

    .line 188
    .line 189
    add-int/lit8 p2, p2, 0x3

    .line 190
    .line 191
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 192
    .line 193
    .line 194
    move-result v6

    .line 195
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    if-le p0, v0, :cond_4

    .line 199
    .line 200
    invoke-virtual {p1, v3}, Ljava/lang/String;->charAt(I)C

    .line 201
    .line 202
    .line 203
    move-result v6

    .line 204
    if-lt v6, v4, :cond_4

    .line 205
    .line 206
    if-gt v6, v5, :cond_4

    .line 207
    .line 208
    invoke-virtual {p1, v3}, Ljava/lang/String;->charAt(I)C

    .line 209
    .line 210
    .line 211
    move-result v3

    .line 212
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    const/4 v3, 0x2

    .line 216
    if-le p0, v3, :cond_4

    .line 217
    .line 218
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 219
    .line 220
    .line 221
    move-result p0

    .line 222
    if-lt p0, v4, :cond_4

    .line 223
    .line 224
    const/16 v2, 0x33

    .line 225
    .line 226
    if-gt p0, v2, :cond_4

    .line 227
    .line 228
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 229
    .line 230
    .line 231
    move-result p0

    .line 232
    if-lt p0, v4, :cond_4

    .line 233
    .line 234
    if-gt p0, v5, :cond_4

    .line 235
    .line 236
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    :cond_4
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    const/16 p1, 0x8

    .line 248
    .line 249
    invoke-static {p0, p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 250
    .line 251
    .line 252
    move-result p0

    .line 253
    invoke-virtual {p3, p0}, Ljava/io/Writer;->write(I)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->length()I

    .line 257
    .line 258
    .line 259
    move-result p0

    .line 260
    add-int/2addr p0, v0

    .line 261
    goto :goto_2

    .line 262
    :cond_5
    const/4 p0, 0x0

    .line 263
    :goto_2
    return p0

    .line 264
    nop

    .line 265
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
