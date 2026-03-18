.class public final Ld4/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ld4/b0;->d:I

    iput-object p1, p0, Ld4/b0;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/util/Comparator;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ld4/b0;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld4/b0;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 6

    .line 1
    iget v0, p0, Ld4/b0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lw71/c;

    .line 7
    .line 8
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lw71/c;

    .line 11
    .line 12
    iget-wide v0, p1, Lw71/c;->a:D

    .line 13
    .line 14
    iget-wide v2, p0, Lw71/c;->a:D

    .line 15
    .line 16
    sub-double/2addr v0, v2

    .line 17
    mul-double/2addr v0, v0

    .line 18
    iget-wide v4, p1, Lw71/c;->b:D

    .line 19
    .line 20
    iget-wide p0, p0, Lw71/c;->b:D

    .line 21
    .line 22
    sub-double/2addr v4, p0

    .line 23
    mul-double/2addr v4, v4

    .line 24
    add-double/2addr v4, v0

    .line 25
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast p2, Lw71/c;

    .line 34
    .line 35
    iget-wide v4, p2, Lw71/c;->a:D

    .line 36
    .line 37
    sub-double/2addr v4, v2

    .line 38
    mul-double/2addr v4, v4

    .line 39
    iget-wide v1, p2, Lw71/c;->b:D

    .line 40
    .line 41
    sub-double/2addr v1, p0

    .line 42
    mul-double/2addr v1, v1

    .line 43
    add-double/2addr v1, v4

    .line 44
    invoke-static {v1, v2}, Ljava/lang/Math;->sqrt(D)D

    .line 45
    .line 46
    .line 47
    move-result-wide p0

    .line 48
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-static {v0, p0}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    return p0

    .line 57
    :pswitch_0
    check-cast p1, Landroid/text/style/LeadingMarginSpan;

    .line 58
    .line 59
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Landroid/text/Spanned;

    .line 62
    .line 63
    invoke-interface {p0, p1}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    check-cast p2, Landroid/text/style/LeadingMarginSpan;

    .line 72
    .line 73
    invoke-interface {p0, p2}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-static {p1, p0}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    return p0

    .line 86
    :pswitch_1
    check-cast p1, Landroid/util/Rational;

    .line 87
    .line 88
    check-cast p2, Landroid/util/Rational;

    .line 89
    .line 90
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p0, Landroid/util/Rational;

    .line 93
    .line 94
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    cmpl-float v1, p1, v0

    .line 103
    .line 104
    if-lez v1, :cond_0

    .line 105
    .line 106
    div-float/2addr v0, p1

    .line 107
    goto :goto_0

    .line 108
    :cond_0
    div-float v0, p1, v0

    .line 109
    .line 110
    :goto_0
    invoke-virtual {p2}, Landroid/util/Rational;->floatValue()F

    .line 111
    .line 112
    .line 113
    move-result p1

    .line 114
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 115
    .line 116
    .line 117
    move-result p0

    .line 118
    cmpl-float p2, p1, p0

    .line 119
    .line 120
    if-lez p2, :cond_1

    .line 121
    .line 122
    div-float/2addr p0, p1

    .line 123
    goto :goto_1

    .line 124
    :cond_1
    div-float p0, p1, p0

    .line 125
    .line 126
    :goto_1
    invoke-static {p0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    return p0

    .line 131
    :pswitch_2
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast p0, La5/f;

    .line 134
    .line 135
    invoke-virtual {p0, p1, p2}, La5/f;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-eqz p0, :cond_2

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_2
    check-cast p1, Li31/h0;

    .line 143
    .line 144
    iget p0, p1, Li31/h0;->e:I

    .line 145
    .line 146
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    check-cast p2, Li31/h0;

    .line 151
    .line 152
    iget p1, p2, Li31/h0;->e:I

    .line 153
    .line 154
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    :goto_2
    return p0

    .line 163
    :pswitch_3
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast p0, La5/f;

    .line 166
    .line 167
    invoke-virtual {p0, p1, p2}, La5/f;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    if-eqz p0, :cond_3

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_3
    check-cast p1, Li31/y;

    .line 175
    .line 176
    iget-object p0, p1, Li31/y;->b:Ljava/lang/String;

    .line 177
    .line 178
    check-cast p2, Li31/y;

    .line 179
    .line 180
    iget-object p1, p2, Li31/y;->b:Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    :goto_3
    return p0

    .line 187
    :pswitch_4
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast p0, Ld4/b0;

    .line 190
    .line 191
    invoke-virtual {p0, p1, p2}, Ld4/b0;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    if-eqz p0, :cond_4

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :cond_4
    check-cast p1, Ld4/q;

    .line 199
    .line 200
    iget p0, p1, Ld4/q;->g:I

    .line 201
    .line 202
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    check-cast p2, Ld4/q;

    .line 207
    .line 208
    iget p1, p2, Ld4/q;->g:I

    .line 209
    .line 210
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 215
    .line 216
    .line 217
    move-result p0

    .line 218
    :goto_4
    return p0

    .line 219
    :pswitch_5
    iget-object p0, p0, Ld4/b0;->e:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast p0, Ljava/util/Comparator;

    .line 222
    .line 223
    invoke-interface {p0, p1, p2}, Ljava/util/Comparator;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 224
    .line 225
    .line 226
    move-result p0

    .line 227
    if-eqz p0, :cond_5

    .line 228
    .line 229
    goto :goto_5

    .line 230
    :cond_5
    check-cast p1, Ld4/q;

    .line 231
    .line 232
    iget-object p0, p1, Ld4/q;->c:Lv3/h0;

    .line 233
    .line 234
    check-cast p2, Ld4/q;

    .line 235
    .line 236
    iget-object p1, p2, Ld4/q;->c:Lv3/h0;

    .line 237
    .line 238
    sget-object p2, Lv3/h0;->V:Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 239
    .line 240
    invoke-virtual {p2, p0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 241
    .line 242
    .line 243
    move-result p0

    .line 244
    :goto_5
    return p0

    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
