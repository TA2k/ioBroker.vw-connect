.class public final Ltv/m;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Luv/q;


# direct methods
.method public synthetic constructor <init>(Luv/q;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltv/m;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ltv/m;->g:Luv/q;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ltv/m;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvv/v0;

    .line 7
    .line 8
    const-string v0, "$this$Table"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Ltv/m;->g:Luv/q;

    .line 14
    .line 15
    sget-object v0, Ltv/c;->n:Ltv/c;

    .line 16
    .line 17
    invoke-static {p0, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-static {p0}, Lky0/l;->g(Lky0/g;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Luv/q;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    sget-object v0, Ltv/c;->o:Ltv/c;

    .line 30
    .line 31
    invoke-static {p0, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    new-instance v0, Lky0/f;

    .line 36
    .line 37
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 38
    .line 39
    .line 40
    :goto_0
    invoke-virtual {v0}, Lky0/f;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_0

    .line 45
    .line 46
    invoke-virtual {v0}, Lky0/f;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, Luv/q;

    .line 51
    .line 52
    new-instance v1, Ltv/m;

    .line 53
    .line 54
    const/4 v2, 0x1

    .line 55
    invoke-direct {v1, p0, v2}, Ltv/m;-><init>(Luv/q;I)V

    .line 56
    .line 57
    .line 58
    iget-object p0, p1, Lvv/v0;->a:Ljava/util/ArrayList;

    .line 59
    .line 60
    new-instance v2, Lvv/r0;

    .line 61
    .line 62
    invoke-direct {v2}, Lvv/r0;-><init>()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1, v2}, Ltv/m;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_0
    check-cast p1, Lvv/r0;

    .line 76
    .line 77
    const-string v0, "$this$row"

    .line 78
    .line 79
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    sget-object v0, Ltv/c;->m:Ltv/c;

    .line 83
    .line 84
    iget-object p0, p0, Ltv/m;->g:Luv/q;

    .line 85
    .line 86
    invoke-static {p0, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    new-instance v0, Lky0/f;

    .line 91
    .line 92
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 93
    .line 94
    .line 95
    :goto_1
    invoke-virtual {v0}, Lky0/f;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-eqz p0, :cond_1

    .line 100
    .line 101
    invoke-virtual {v0}, Lky0/f;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Luv/q;

    .line 106
    .line 107
    new-instance v1, Ltv/d;

    .line 108
    .line 109
    const/4 v2, 0x3

    .line 110
    invoke-direct {v1, p0, v2}, Ltv/d;-><init>(Luv/q;I)V

    .line 111
    .line 112
    .line 113
    new-instance p0, Lt2/b;

    .line 114
    .line 115
    const/4 v2, 0x1

    .line 116
    const v3, -0x12b76451

    .line 117
    .line 118
    .line 119
    invoke-direct {p0, v1, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 120
    .line 121
    .line 122
    new-instance v1, Lvv/b1;

    .line 123
    .line 124
    iget-object v2, p1, Lvv/r0;->a:Lvv/b1;

    .line 125
    .line 126
    iget-object v2, v2, Lvv/b1;->a:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v2, Ljava/util/Collection;

    .line 129
    .line 130
    invoke-static {v2, p0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-direct {v1, p0}, Lvv/b1;-><init>(Ljava/util/List;)V

    .line 135
    .line 136
    .line 137
    iput-object v1, p1, Lvv/r0;->a:Lvv/b1;

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    return-object p0

    .line 143
    :pswitch_1
    check-cast p1, Lvv/r0;

    .line 144
    .line 145
    const-string v0, "$this$Table"

    .line 146
    .line 147
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    sget-object v0, Ltv/c;->j:Ltv/c;

    .line 151
    .line 152
    iget-object p0, p0, Ltv/m;->g:Luv/q;

    .line 153
    .line 154
    invoke-static {p0, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    invoke-static {p0}, Lky0/l;->g(Lky0/g;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    check-cast p0, Luv/q;

    .line 163
    .line 164
    if-eqz p0, :cond_2

    .line 165
    .line 166
    sget-object v0, Ltv/c;->k:Ltv/c;

    .line 167
    .line 168
    invoke-static {p0, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-static {p0}, Lky0/l;->g(Lky0/g;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    check-cast p0, Luv/q;

    .line 177
    .line 178
    if-eqz p0, :cond_2

    .line 179
    .line 180
    sget-object v0, Ltv/c;->l:Ltv/c;

    .line 181
    .line 182
    invoke-static {p0, v0}, Llp/m0;->b(Luv/q;Lay0/k;)Lky0/g;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    new-instance v0, Lky0/f;

    .line 187
    .line 188
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 189
    .line 190
    .line 191
    :goto_2
    invoke-virtual {v0}, Lky0/f;->hasNext()Z

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    if-eqz p0, :cond_2

    .line 196
    .line 197
    invoke-virtual {v0}, Lky0/f;->next()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    check-cast p0, Luv/q;

    .line 202
    .line 203
    new-instance v1, Ltv/d;

    .line 204
    .line 205
    const/4 v2, 0x2

    .line 206
    invoke-direct {v1, p0, v2}, Ltv/d;-><init>(Luv/q;I)V

    .line 207
    .line 208
    .line 209
    new-instance p0, Lt2/b;

    .line 210
    .line 211
    const/4 v2, 0x1

    .line 212
    const v3, -0x5e75ec45

    .line 213
    .line 214
    .line 215
    invoke-direct {p0, v1, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 216
    .line 217
    .line 218
    new-instance v1, Lvv/b1;

    .line 219
    .line 220
    iget-object v2, p1, Lvv/r0;->a:Lvv/b1;

    .line 221
    .line 222
    iget-object v2, v2, Lvv/b1;->a:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast v2, Ljava/util/Collection;

    .line 225
    .line 226
    invoke-static {v2, p0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    invoke-direct {v1, p0}, Lvv/b1;-><init>(Ljava/util/List;)V

    .line 231
    .line 232
    .line 233
    iput-object v1, p1, Lvv/r0;->a:Lvv/b1;

    .line 234
    .line 235
    goto :goto_2

    .line 236
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
