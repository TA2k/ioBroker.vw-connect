.class public final synthetic Lb50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:La50/i;


# direct methods
.method public synthetic constructor <init>(La50/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb50/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb50/a;->e:La50/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lb50/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v3

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_3

    .line 32
    .line 33
    iget-object p0, p0, Lb50/a;->e:La50/i;

    .line 34
    .line 35
    iget-boolean p2, p0, La50/i;->b:Z

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    const v1, -0xbf6ed93

    .line 39
    .line 40
    .line 41
    if-eqz p2, :cond_1

    .line 42
    .line 43
    const p2, 0x20a8f8ab

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 47
    .line 48
    .line 49
    const-string p2, "poi_picker_map"

    .line 50
    .line 51
    const/16 v2, 0x36

    .line 52
    .line 53
    invoke-static {v2, p2, p1, v0}, Ldl0/e;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 54
    .line 55
    .line 56
    :goto_1
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_1
    invoke-virtual {p1, v1}, Ll2/t;->Y(I)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :goto_2
    iget-boolean p0, p0, La50/i;->d:Z

    .line 65
    .line 66
    if-eqz p0, :cond_2

    .line 67
    .line 68
    const p0, 0x20a90668

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 72
    .line 73
    .line 74
    const/4 p0, 0x6

    .line 75
    invoke-static {v0, p1, p0}, Ldl0/e;->f(Lx2/s;Ll2/o;I)V

    .line 76
    .line 77
    .line 78
    :goto_3
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 79
    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_2
    invoke-virtual {p1, v1}, Ll2/t;->Y(I)V

    .line 83
    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 87
    .line 88
    .line 89
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 93
    .line 94
    const/4 v1, 0x2

    .line 95
    const/4 v2, 0x1

    .line 96
    const/4 v3, 0x0

    .line 97
    if-eq v0, v1, :cond_4

    .line 98
    .line 99
    move v0, v2

    .line 100
    goto :goto_5

    .line 101
    :cond_4
    move v0, v3

    .line 102
    :goto_5
    and-int/2addr p2, v2

    .line 103
    check-cast p1, Ll2/t;

    .line 104
    .line 105
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 106
    .line 107
    .line 108
    move-result p2

    .line 109
    if-eqz p2, :cond_7

    .line 110
    .line 111
    iget-object p0, p0, Lb50/a;->e:La50/i;

    .line 112
    .line 113
    iget-object p0, p0, La50/i;->e:Lbl0/h0;

    .line 114
    .line 115
    if-nez p0, :cond_5

    .line 116
    .line 117
    const/4 p0, -0x1

    .line 118
    goto :goto_6

    .line 119
    :cond_5
    sget-object p2, Lb50/e;->a:[I

    .line 120
    .line 121
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    aget p0, p2, p0

    .line 126
    .line 127
    :goto_6
    const/4 p2, 0x5

    .line 128
    if-ne p0, p2, :cond_6

    .line 129
    .line 130
    const p0, 0xd183a83

    .line 131
    .line 132
    .line 133
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    const-string p0, "poi_picker_map"

    .line 137
    .line 138
    const/4 p2, 0x6

    .line 139
    invoke-static {p0, p1, p2}, Lxk0/e0;->b(Ljava/lang/String;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 143
    .line 144
    .line 145
    goto :goto_7

    .line 146
    :cond_6
    const p0, -0x6a0f2d3b

    .line 147
    .line 148
    .line 149
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    goto :goto_7

    .line 156
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 157
    .line 158
    .line 159
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    return-object p0

    .line 162
    :pswitch_1
    and-int/lit8 v0, p2, 0x3

    .line 163
    .line 164
    const/4 v1, 0x1

    .line 165
    const/4 v2, 0x0

    .line 166
    const/4 v3, 0x2

    .line 167
    if-eq v0, v3, :cond_8

    .line 168
    .line 169
    move v0, v1

    .line 170
    goto :goto_8

    .line 171
    :cond_8
    move v0, v2

    .line 172
    :goto_8
    and-int/2addr p2, v1

    .line 173
    check-cast p1, Ll2/t;

    .line 174
    .line 175
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 176
    .line 177
    .line 178
    move-result p2

    .line 179
    if-eqz p2, :cond_c

    .line 180
    .line 181
    iget-object p0, p0, Lb50/a;->e:La50/i;

    .line 182
    .line 183
    iget-object p0, p0, La50/i;->e:Lbl0/h0;

    .line 184
    .line 185
    if-nez p0, :cond_9

    .line 186
    .line 187
    const/4 p0, -0x1

    .line 188
    goto :goto_9

    .line 189
    :cond_9
    sget-object p2, Lb50/e;->a:[I

    .line 190
    .line 191
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    aget p0, p2, p0

    .line 196
    .line 197
    :goto_9
    const/4 p2, 0x6

    .line 198
    const-string v0, "poi_picker_map"

    .line 199
    .line 200
    if-eq p0, v1, :cond_b

    .line 201
    .line 202
    if-eq p0, v3, :cond_b

    .line 203
    .line 204
    const/4 v1, 0x3

    .line 205
    if-eq p0, v1, :cond_a

    .line 206
    .line 207
    const/4 v1, 0x4

    .line 208
    if-eq p0, v1, :cond_a

    .line 209
    .line 210
    const p0, 0x34ccf826

    .line 211
    .line 212
    .line 213
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 217
    .line 218
    .line 219
    goto :goto_a

    .line 220
    :cond_a
    const p0, -0x489e9afe

    .line 221
    .line 222
    .line 223
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 224
    .line 225
    .line 226
    invoke-static {v0, p1, p2}, Lxk0/h;->e0(Ljava/lang/String;Ll2/o;I)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    goto :goto_a

    .line 233
    :cond_b
    const p0, -0x489eb09e

    .line 234
    .line 235
    .line 236
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 237
    .line 238
    .line 239
    invoke-static {v0, p1, p2}, Lxk0/h;->d0(Ljava/lang/String;Ll2/o;I)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 243
    .line 244
    .line 245
    goto :goto_a

    .line 246
    :cond_c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 247
    .line 248
    .line 249
    :goto_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 250
    .line 251
    return-object p0

    .line 252
    nop

    .line 253
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
