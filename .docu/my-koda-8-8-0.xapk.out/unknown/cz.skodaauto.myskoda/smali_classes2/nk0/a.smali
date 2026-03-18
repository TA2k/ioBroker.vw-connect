.class public final synthetic Lnk0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Leo0/b;


# direct methods
.method public synthetic constructor <init>(Leo0/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lnk0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnk0/a;->e:Leo0/b;

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
    .locals 9

    .line 1
    iget v0, p0, Lnk0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lk21/a;

    .line 4
    .line 5
    check-cast p2, Lg21/a;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v0, "$this$scopedFactory"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "it"

    .line 16
    .line 17
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p2, Lok0/l;

    .line 21
    .line 22
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 23
    .line 24
    const-class v1, Lfg0/d;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-virtual {p1, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lfg0/d;

    .line 36
    .line 37
    const-class v3, Lml0/i;

    .line 38
    .line 39
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-virtual {p1, v3, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Lml0/i;

    .line 48
    .line 49
    const-class v4, Lfg0/a;

    .line 50
    .line 51
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-virtual {p1, v4, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    check-cast v4, Lfg0/a;

    .line 60
    .line 61
    iget-object p0, p0, Lnk0/a;->e:Leo0/b;

    .line 62
    .line 63
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-class v5, Lwj0/j0;

    .line 70
    .line 71
    invoke-virtual {v0, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {p1, v0, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lwj0/j0;

    .line 80
    .line 81
    invoke-direct {p2, v1, v3, v4, p0}, Lok0/l;-><init>(Lfg0/d;Lml0/i;Lfg0/a;Lwj0/j0;)V

    .line 82
    .line 83
    .line 84
    return-object p2

    .line 85
    :pswitch_0
    const-string v0, "$this$scopedFactory"

    .line 86
    .line 87
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string v0, "it"

    .line 91
    .line 92
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    new-instance p2, Lok0/e;

    .line 96
    .line 97
    iget-object p0, p0, Lnk0/a;->e:Leo0/b;

    .line 98
    .line 99
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 100
    .line 101
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 106
    .line 107
    const-class v2, Lok0/d;

    .line 108
    .line 109
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    const/4 v3, 0x0

    .line 114
    invoke-virtual {p1, v2, v0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    check-cast v0, Lok0/d;

    .line 119
    .line 120
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    const-class v2, Lok0/g;

    .line 125
    .line 126
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-virtual {p1, v1, p0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    check-cast p0, Lok0/g;

    .line 135
    .line 136
    invoke-direct {p2, v0, p0}, Lok0/e;-><init>(Lok0/d;Lok0/g;)V

    .line 137
    .line 138
    .line 139
    return-object p2

    .line 140
    :pswitch_1
    const-string v0, "$this$scopedViewModel"

    .line 141
    .line 142
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const-string v0, "it"

    .line 146
    .line 147
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    iget-object p0, p0, Lnk0/a;->e:Leo0/b;

    .line 151
    .line 152
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 153
    .line 154
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 155
    .line 156
    .line 157
    move-result-object p2

    .line 158
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 159
    .line 160
    const-class v1, Lok0/e;

    .line 161
    .line 162
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    const/4 v2, 0x0

    .line 167
    invoke-virtual {p1, v1, p2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p2

    .line 171
    move-object v4, p2

    .line 172
    check-cast v4, Lok0/e;

    .line 173
    .line 174
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    const-class p2, Lok0/l;

    .line 179
    .line 180
    invoke-virtual {v0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 181
    .line 182
    .line 183
    move-result-object p2

    .line 184
    invoke-virtual {p1, p2, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    move-object v8, p0

    .line 189
    check-cast v8, Lok0/l;

    .line 190
    .line 191
    const-class p0, Ltn0/b;

    .line 192
    .line 193
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    invoke-virtual {p1, p0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    move-object v5, p0

    .line 202
    check-cast v5, Ltn0/b;

    .line 203
    .line 204
    const-class p0, Ltn0/e;

    .line 205
    .line 206
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    invoke-virtual {p1, p0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    move-object v7, p0

    .line 215
    check-cast v7, Ltn0/e;

    .line 216
    .line 217
    const-class p0, Lfg0/a;

    .line 218
    .line 219
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    invoke-virtual {p1, p0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    move-object v6, p0

    .line 228
    check-cast v6, Lfg0/a;

    .line 229
    .line 230
    new-instance v3, Lqk0/c;

    .line 231
    .line 232
    invoke-direct/range {v3 .. v8}, Lqk0/c;-><init>(Lok0/e;Ltn0/b;Lfg0/a;Ltn0/e;Lok0/l;)V

    .line 233
    .line 234
    .line 235
    return-object v3

    .line 236
    nop

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
