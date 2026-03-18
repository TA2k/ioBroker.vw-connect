.class public final synthetic Ly21/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz21/g;


# direct methods
.method public synthetic constructor <init>(Lz21/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly21/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly21/c;->e:Lz21/g;

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
    .locals 4

    .line 1
    iget v0, p0, Ly21/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Ljava/util/Date;

    .line 11
    .line 12
    invoke-direct {v1}, Ljava/util/Date;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/util/Calendar;->setTime(Ljava/util/Date;)V

    .line 16
    .line 17
    .line 18
    const/4 v1, 0x5

    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-virtual {v0, v1, v2}, Ljava/util/Calendar;->add(II)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 24
    .line 25
    iget-object p0, p0, Lz21/g;->b:Lz9/y;

    .line 26
    .line 27
    filled-new-array {p0, v0}, [Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_0
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 37
    .line 38
    iget-object p0, p0, Lz21/g;->b:Lz9/y;

    .line 39
    .line 40
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_1
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 50
    .line 51
    iget-object p0, p0, Lz21/g;->b:Lz9/y;

    .line 52
    .line 53
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_2
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 63
    .line 64
    iget-object p0, p0, Lz21/g;->b:Lz9/y;

    .line 65
    .line 66
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_3
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 76
    .line 77
    iget-object v0, p0, Lz21/g;->e:Lg1/q;

    .line 78
    .line 79
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v0, Lz70/a;

    .line 82
    .line 83
    iget-object v0, v0, Lz70/a;->a:Lij0/a;

    .line 84
    .line 85
    const/4 v1, 0x0

    .line 86
    new-array v1, v1, [Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Ljj0/f;

    .line 89
    .line 90
    const v2, 0x7f12079d

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v1, p0, Lz21/g;->e:Lg1/q;

    .line 98
    .line 99
    iget-object v1, v1, Lg1/q;->b:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v1, Lz70/d;

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    const-string v1, ""

    .line 107
    .line 108
    iget-object p0, p0, Lz21/g;->g:Lay0/k;

    .line 109
    .line 110
    filled-new-array {v0, v1, p0}, [Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_4
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 120
    .line 121
    iget-object v0, p0, Lz21/g;->e:Lg1/q;

    .line 122
    .line 123
    iget-object v0, v0, Lg1/q;->g:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lz70/b;

    .line 126
    .line 127
    iget-object v0, v0, Lz70/b;->a:Lij0/a;

    .line 128
    .line 129
    const/4 v1, 0x0

    .line 130
    new-array v1, v1, [Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v0, Ljj0/f;

    .line 133
    .line 134
    const v2, 0x7f1207b8

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    iget-object p0, p0, Lz21/g;->g:Lay0/k;

    .line 142
    .line 143
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :pswitch_5
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 153
    .line 154
    iget-object v0, p0, Lz21/g;->b:Lz9/y;

    .line 155
    .line 156
    iget-object p0, p0, Lz21/g;->e:Lg1/q;

    .line 157
    .line 158
    iget-object p0, p0, Lg1/q;->b:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast p0, Lz70/d;

    .line 161
    .line 162
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    return-object p0

    .line 171
    :pswitch_6
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 172
    .line 173
    iget-object p0, p0, Lz21/g;->b:Lz9/y;

    .line 174
    .line 175
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    return-object p0

    .line 184
    :pswitch_7
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 185
    .line 186
    iget-object v0, p0, Lz21/g;->b:Lz9/y;

    .line 187
    .line 188
    iget-object v1, p0, Lz21/g;->e:Lg1/q;

    .line 189
    .line 190
    iget-object v1, v1, Lg1/q;->g:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v1, Lz70/b;

    .line 193
    .line 194
    iget-object v1, v1, Lz70/b;->a:Lij0/a;

    .line 195
    .line 196
    const/4 v2, 0x0

    .line 197
    new-array v2, v2, [Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v1, Ljj0/f;

    .line 200
    .line 201
    const v3, 0x7f1207b8

    .line 202
    .line 203
    .line 204
    invoke-virtual {v1, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v1

    .line 208
    const-string v2, ""

    .line 209
    .line 210
    iget-object p0, p0, Lz21/g;->g:Lay0/k;

    .line 211
    .line 212
    filled-new-array {v0, v1, v2, p0}, [Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    return-object p0

    .line 221
    :pswitch_8
    iget-object p0, p0, Ly21/c;->e:Lz21/g;

    .line 222
    .line 223
    iget-object p0, p0, Lz21/g;->b:Lz9/y;

    .line 224
    .line 225
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    invoke-static {p0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    return-object p0

    .line 234
    nop

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
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
