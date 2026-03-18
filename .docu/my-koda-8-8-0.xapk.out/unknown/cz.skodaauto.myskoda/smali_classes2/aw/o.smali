.class public final Law/o;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Law/o;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Law/o;->g:Lay0/k;

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
    .locals 6

    .line 1
    iget v0, p0, Law/o;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroid/webkit/WebView;

    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_0
    check-cast p1, Lv3/j0;

    .line 22
    .line 23
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_1
    check-cast p1, Lt4/l;

    .line 35
    .line 36
    iget-wide v0, p1, Lt4/l;->a:J

    .line 37
    .line 38
    const-wide v2, 0xffffffffL

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    and-long/2addr v0, v2

    .line 44
    long-to-int p1, v0

    .line 45
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 50
    .line 51
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    check-cast p0, Ljava/lang/Number;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    const/4 p1, 0x0

    .line 62
    int-to-long v0, p1

    .line 63
    const/16 p1, 0x20

    .line 64
    .line 65
    shl-long/2addr v0, p1

    .line 66
    int-to-long p0, p0

    .line 67
    and-long/2addr p0, v2

    .line 68
    or-long/2addr p0, v0

    .line 69
    new-instance v0, Lt4/j;

    .line 70
    .line 71
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 72
    .line 73
    .line 74
    return-object v0

    .line 75
    :pswitch_2
    check-cast p1, Lt4/l;

    .line 76
    .line 77
    iget-wide v0, p1, Lt4/l;->a:J

    .line 78
    .line 79
    const-wide v2, 0xffffffffL

    .line 80
    .line 81
    .line 82
    .line 83
    .line 84
    and-long/2addr v0, v2

    .line 85
    long-to-int p1, v0

    .line 86
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 91
    .line 92
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    check-cast p0, Ljava/lang/Number;

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    const/4 p1, 0x0

    .line 103
    int-to-long v0, p1

    .line 104
    const/16 p1, 0x20

    .line 105
    .line 106
    shl-long/2addr v0, p1

    .line 107
    int-to-long p0, p0

    .line 108
    and-long/2addr p0, v2

    .line 109
    or-long/2addr p0, v0

    .line 110
    new-instance v0, Lt4/j;

    .line 111
    .line 112
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 113
    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_3
    check-cast p1, Lt4/l;

    .line 117
    .line 118
    iget-wide v0, p1, Lt4/l;->a:J

    .line 119
    .line 120
    const/16 p1, 0x20

    .line 121
    .line 122
    shr-long v2, v0, p1

    .line 123
    .line 124
    long-to-int v2, v2

    .line 125
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 130
    .line 131
    invoke-interface {p0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    check-cast p0, Ljava/lang/Number;

    .line 136
    .line 137
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    const-wide v2, 0xffffffffL

    .line 142
    .line 143
    .line 144
    .line 145
    .line 146
    and-long/2addr v0, v2

    .line 147
    long-to-int v0, v0

    .line 148
    int-to-long v4, p0

    .line 149
    shl-long p0, v4, p1

    .line 150
    .line 151
    int-to-long v0, v0

    .line 152
    and-long/2addr v0, v2

    .line 153
    or-long/2addr p0, v0

    .line 154
    new-instance v0, Lt4/l;

    .line 155
    .line 156
    invoke-direct {v0, p0, p1}, Lt4/l;-><init>(J)V

    .line 157
    .line 158
    .line 159
    return-object v0

    .line 160
    :pswitch_4
    check-cast p1, Lt4/l;

    .line 161
    .line 162
    iget-wide v0, p1, Lt4/l;->a:J

    .line 163
    .line 164
    const/16 p1, 0x20

    .line 165
    .line 166
    shr-long v2, v0, p1

    .line 167
    .line 168
    long-to-int v2, v2

    .line 169
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object v2

    .line 173
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 174
    .line 175
    invoke-interface {p0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    check-cast p0, Ljava/lang/Number;

    .line 180
    .line 181
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 182
    .line 183
    .line 184
    move-result p0

    .line 185
    const-wide v2, 0xffffffffL

    .line 186
    .line 187
    .line 188
    .line 189
    .line 190
    and-long/2addr v0, v2

    .line 191
    long-to-int v0, v0

    .line 192
    int-to-long v4, p0

    .line 193
    shl-long p0, v4, p1

    .line 194
    .line 195
    int-to-long v0, v0

    .line 196
    and-long/2addr v0, v2

    .line 197
    or-long/2addr p0, v0

    .line 198
    new-instance v0, Lt4/l;

    .line 199
    .line 200
    invoke-direct {v0, p0, p1}, Lt4/l;-><init>(J)V

    .line 201
    .line 202
    .line 203
    return-object v0

    .line 204
    :pswitch_5
    check-cast p1, Landroid/webkit/WebView;

    .line 205
    .line 206
    const-string v0, "it"

    .line 207
    .line 208
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    iget-object p0, p0, Law/o;->g:Lay0/k;

    .line 212
    .line 213
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 217
    .line 218
    return-object p0

    .line 219
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
