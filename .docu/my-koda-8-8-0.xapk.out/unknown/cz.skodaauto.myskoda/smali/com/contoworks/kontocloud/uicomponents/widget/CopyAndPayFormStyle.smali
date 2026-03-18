.class Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;,
        Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;,
        Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderSideStyle;,
        Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$BorderStyle;
    }
.end annotation


# instance fields
.field accountHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

.field cardHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

.field cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

.field cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

.field expiryDateEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

.field fontName:Ljava/lang/String;

.field ibanEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

.field labelFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

.field provider:Ljava/lang/String;

.field showCVVHint:Z

.field validationHintFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 5
    .line 6
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 10
    .line 11
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 12
    .line 13
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->expiryDateEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 17
    .line 18
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 19
    .line 20
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 24
    .line 25
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 26
    .line 27
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 31
    .line 32
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 33
    .line 34
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->accountHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 38
    .line 39
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 40
    .line 41
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->ibanEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 45
    .line 46
    const-string v0, "Payon"

    .line 47
    .line 48
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->provider:Ljava/lang/String;

    .line 49
    .line 50
    return-void
.end method

.method private static ColorToCssString(I)Ljava/lang/String;
    .locals 8

    .line 1
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 2
    .line 3
    invoke-static {p0}, Landroid/graphics/Color;->red(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-static {p0}, Landroid/graphics/Color;->green(I)I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {p0}, Landroid/graphics/Color;->blue(I)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-static {p0}, Landroid/graphics/Color;->alpha(I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-double v4, p0

    .line 32
    const-wide v6, 0x406fe00000000000L    # 255.0

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    div-double/2addr v4, v6

    .line 38
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    filled-new-array {v1, v2, v3, p0}, [Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const-string v1, "rgba(%d,%d,%d,%f)"

    .line 47
    .line 48
    invoke-static {v0, v1, p0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method public static bridge synthetic a(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->ColorToCssString(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private toCssCyber()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->provider:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "PayonWithPCIProxy"

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const-string v0, ""

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-string v0, "margin-top: 16px;"

    .line 16
    .line 17
    const-string v2, "margin-top: 4px;"

    .line 18
    .line 19
    :goto_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v4, "body {\nfont-family: \'"

    .line 22
    .line 23
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->fontName:Ljava/lang/String;

    .line 27
    .line 28
    const-string v5, "\';"

    .line 29
    .line 30
    invoke-static {v3, v4, v5}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    const-string v4, "}\n"

    .line 35
    .line 36
    invoke-static {v3, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    const-string v5, ".cw-label {\n"

    .line 41
    .line 42
    invoke-static {v3, v5}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-static {v3}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iget-object v5, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->labelFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 51
    .line 52
    invoke-virtual {v5}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    const-string v6, "\n"

    .line 57
    .line 58
    invoke-static {v3, v5, v6}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-static {v3, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-static {v3, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    const-string v5, ".cw-label:not(:first-child) {\n"

    .line 71
    .line 72
    invoke-static {v3, v5}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    invoke-static {v3}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    iget-object v5, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->labelFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 81
    .line 82
    invoke-virtual {v5}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    invoke-static {v3, v5, v6}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-static {v3, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-static {v0, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    const-string v3, ".cw-hint {\n"

    .line 99
    .line 100
    invoke-static {v0, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    iget-object v3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->validationHintFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 109
    .line 110
    invoke-virtual {v3}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    invoke-static {v0, v3, v6}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-static {v0, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->provider:Ljava/lang/String;

    .line 127
    .line 128
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    const-string v2, ".cw-control-cvv"

    .line 133
    .line 134
    const-string v3, ".cw-control-cardNumber"

    .line 135
    .line 136
    if-eqz v1, :cond_1

    .line 137
    .line 138
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 143
    .line 144
    invoke-virtual {v1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssPayonPci(Ljava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 160
    .line 161
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssPayonPci(Ljava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    goto :goto_1

    .line 173
    :cond_1
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 178
    .line 179
    invoke-virtual {v1, v3}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssCyber(Ljava/lang/String;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 195
    .line 196
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssCyber(Ljava/lang/String;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    :goto_1
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->expiryDateEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 212
    .line 213
    const-string v2, ".cw-control-expiry"

    .line 214
    .line 215
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssCyber(Ljava/lang/String;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 231
    .line 232
    const-string v2, ".cw-control-cardHolder"

    .line 233
    .line 234
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssCyber(Ljava/lang/String;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->accountHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 250
    .line 251
    const-string v2, ".cw-control-accountHolder"

    .line 252
    .line 253
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssCyber(Ljava/lang/String;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 258
    .line 259
    .line 260
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->ibanEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 269
    .line 270
    const-string v1, ".cw-control-iban"

    .line 271
    .line 272
    invoke-virtual {p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCssCyber(Ljava/lang/String;)Ljava/lang/String;

    .line 273
    .line 274
    .line 275
    move-result-object p0

    .line 276
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 277
    .line 278
    .line 279
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    return-object p0
.end method

.method private toCssPayon()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "body {\nfont-family: \'"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->fontName:Ljava/lang/String;

    .line 9
    .line 10
    const-string v2, "\';"

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "}\n"

    .line 17
    .line 18
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v2, ".wpwl-label {\n"

    .line 23
    .line 24
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->labelFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 33
    .line 34
    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const-string v3, "\n"

    .line 39
    .line 40
    invoke-static {v0, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const-string v2, "margin-top: 16px;"

    .line 45
    .line 46
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    const-string v4, ".wpwl-label:not(:first-child) {\n"

    .line 55
    .line 56
    invoke-static {v0, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    iget-object v4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->labelFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 65
    .line 66
    invoke-virtual {v4}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    invoke-static {v0, v4, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    const-string v2, ".wpwl-hint {\n"

    .line 83
    .line 84
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    iget-object v2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->validationHintFont:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;

    .line 93
    .line 94
    invoke-virtual {v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$FontStyle;->toCss()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    invoke-static {v0, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    const-string v2, "margin-top: 4px;"

    .line 103
    .line 104
    invoke-static {v0, v2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 117
    .line 118
    const-string v2, ".wpwl-control-cardNumber"

    .line 119
    .line 120
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCss(Ljava/lang/String;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->expiryDateEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 136
    .line 137
    const-string v2, ".wpwl-control-expiry"

    .line 138
    .line 139
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCss(Ljava/lang/String;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 155
    .line 156
    const-string v2, ".wpwl-control-cardHolder"

    .line 157
    .line 158
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCss(Ljava/lang/String;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 174
    .line 175
    const-string v2, ".wpwl-control-cvv"

    .line 176
    .line 177
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCss(Ljava/lang/String;)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    iget-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->accountHolderEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 193
    .line 194
    const-string v2, ".wpwl-control-accountHolder"

    .line 195
    .line 196
    invoke-virtual {v1, v2}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCss(Ljava/lang/String;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->ibanEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 212
    .line 213
    const-string v1, ".wpwl-control-accountIban"

    .line 214
    .line 215
    invoke-virtual {p0, v1}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toCss(Ljava/lang/String;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    return-object p0
.end method


# virtual methods
.method public setPaymentOptionProvider(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->provider:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public toCardNumberPlaceholderJson()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cardNumberEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toJson()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public toCss()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->provider:Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "Payon"

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->toCssPayon()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->toCssCyber()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public toCvvPlaceholderJson()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle;->cvvEditTextStyle:Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CopyAndPayFormStyle$EditTextStyle;->toJson()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
