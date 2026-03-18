.class public final Ltv/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Ltv/e;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Ltv/e;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Ltv/e;->h:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 p1, 0x4

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ltv/e;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    check-cast p2, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    check-cast p3, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p3

    .line 24
    check-cast p4, Ljava/lang/Number;

    .line 25
    .line 26
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p4

    .line 30
    iget-object v0, p0, Ltv/e;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Ly2/b;

    .line 33
    .line 34
    iget-object v1, v0, Ly2/b;->f:Landroid/graphics/Rect;

    .line 35
    .line 36
    invoke-virtual {v1, p1, p2, p3, p4}, Landroid/graphics/Rect;->set(IIII)V

    .line 37
    .line 38
    .line 39
    iget-object p1, v0, Ly2/b;->a:Lpv/g;

    .line 40
    .line 41
    iget-object p2, v0, Ly2/b;->c:Lw3/t;

    .line 42
    .line 43
    iget-object p0, p0, Ltv/e;->h:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lv3/h0;

    .line 46
    .line 47
    iget p0, p0, Lv3/h0;->e:I

    .line 48
    .line 49
    iget-object p3, v0, Ly2/b;->f:Landroid/graphics/Rect;

    .line 50
    .line 51
    iget-object p1, p1, Lpv/g;->e:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p1, Landroid/view/autofill/AutofillManager;

    .line 54
    .line 55
    invoke-virtual {p1, p2, p0, p3}, Landroid/view/autofill/AutofillManager;->requestAutofill(Landroid/view/View;ILandroid/graphics/Rect;)V

    .line 56
    .line 57
    .line 58
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    check-cast p2, Ljava/lang/Number;

    .line 68
    .line 69
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 70
    .line 71
    .line 72
    move-result p2

    .line 73
    move-object v7, p3

    .line 74
    check-cast v7, Ll2/o;

    .line 75
    .line 76
    check-cast p4, Ljava/lang/Number;

    .line 77
    .line 78
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 79
    .line 80
    .line 81
    move-result p3

    .line 82
    and-int/lit8 p4, p3, 0xe

    .line 83
    .line 84
    if-nez p4, :cond_1

    .line 85
    .line 86
    move-object p4, v7

    .line 87
    check-cast p4, Ll2/t;

    .line 88
    .line 89
    invoke-virtual {p4, p1}, Ll2/t;->e(I)Z

    .line 90
    .line 91
    .line 92
    move-result p4

    .line 93
    if-eqz p4, :cond_0

    .line 94
    .line 95
    const/4 p4, 0x4

    .line 96
    goto :goto_0

    .line 97
    :cond_0
    const/4 p4, 0x2

    .line 98
    :goto_0
    or-int/2addr p4, p3

    .line 99
    goto :goto_1

    .line 100
    :cond_1
    move p4, p3

    .line 101
    :goto_1
    and-int/lit8 p3, p3, 0x70

    .line 102
    .line 103
    if-nez p3, :cond_3

    .line 104
    .line 105
    move-object p3, v7

    .line 106
    check-cast p3, Ll2/t;

    .line 107
    .line 108
    invoke-virtual {p3, p2}, Ll2/t;->e(I)Z

    .line 109
    .line 110
    .line 111
    move-result p3

    .line 112
    if-eqz p3, :cond_2

    .line 113
    .line 114
    const/16 p3, 0x20

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_2
    const/16 p3, 0x10

    .line 118
    .line 119
    :goto_2
    or-int/2addr p4, p3

    .line 120
    :cond_3
    and-int/lit16 p3, p4, 0x2db

    .line 121
    .line 122
    const/16 p4, 0x92

    .line 123
    .line 124
    if-ne p3, p4, :cond_5

    .line 125
    .line 126
    move-object p3, v7

    .line 127
    check-cast p3, Ll2/t;

    .line 128
    .line 129
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 130
    .line 131
    .line 132
    move-result p4

    .line 133
    if-nez p4, :cond_4

    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_4
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 137
    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_5
    :goto_3
    iget-object p3, p0, Ltv/e;->g:Ljava/lang/Object;

    .line 141
    .line 142
    move-object v0, p3

    .line 143
    check-cast v0, Lvv/m0;

    .line 144
    .line 145
    iget-object p0, p0, Ltv/e;->h:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast p0, [Lay0/k;

    .line 148
    .line 149
    array-length p3, p0

    .line 150
    rem-int/2addr p1, p3

    .line 151
    aget-object p0, p0, p1

    .line 152
    .line 153
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    move-object v1, p0

    .line 162
    check-cast v1, Ljava/lang/String;

    .line 163
    .line 164
    const/4 v6, 0x0

    .line 165
    const/4 v8, 0x0

    .line 166
    const/4 v2, 0x0

    .line 167
    const/4 v3, 0x0

    .line 168
    const/4 v4, 0x0

    .line 169
    const/4 v5, 0x0

    .line 170
    invoke-static/range {v0 .. v8}, Lvv/l0;->c(Lvv/m0;Ljava/lang/String;Lx2/s;Lay0/k;IZILl2/o;I)V

    .line 171
    .line 172
    .line 173
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 174
    .line 175
    return-object p0

    .line 176
    :pswitch_1
    check-cast p1, Lt4/c;

    .line 177
    .line 178
    check-cast p2, Ljava/lang/String;

    .line 179
    .line 180
    check-cast p3, Ll2/o;

    .line 181
    .line 182
    check-cast p4, Ljava/lang/Number;

    .line 183
    .line 184
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 185
    .line 186
    .line 187
    move-result p4

    .line 188
    const-string v0, "$this$$receiver"

    .line 189
    .line 190
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    const-string p1, "it"

    .line 194
    .line 195
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    and-int/lit16 p1, p4, 0x281

    .line 199
    .line 200
    const/16 p2, 0x80

    .line 201
    .line 202
    if-ne p1, p2, :cond_7

    .line 203
    .line 204
    move-object p1, p3

    .line 205
    check-cast p1, Ll2/t;

    .line 206
    .line 207
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 208
    .line 209
    .line 210
    move-result p2

    .line 211
    if-nez p2, :cond_6

    .line 212
    .line 213
    goto :goto_5

    .line 214
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 215
    .line 216
    .line 217
    goto :goto_6

    .line 218
    :cond_7
    :goto_5
    iget-object p1, p0, Ltv/e;->g:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast p1, Lvv/m0;

    .line 221
    .line 222
    iget-object p0, p0, Ltv/e;->h:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast p0, Llp/la;

    .line 225
    .line 226
    check-cast p0, Luv/i;

    .line 227
    .line 228
    iget-object p0, p0, Luv/i;->a:Ljava/lang/String;

    .line 229
    .line 230
    const/4 p2, 0x0

    .line 231
    invoke-static {p1, p0, p3, p2}, Llp/j0;->a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V

    .line 232
    .line 233
    .line 234
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
