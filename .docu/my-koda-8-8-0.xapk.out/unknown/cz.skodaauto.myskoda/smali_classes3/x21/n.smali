.class public final Lx21/n;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx21/y;


# direct methods
.method public synthetic constructor <init>(Lx21/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Lx21/n;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lx21/n;->g:Lx21/y;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lx21/n;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lx21/n;->g:Lx21/y;

    .line 7
    .line 8
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lx21/n;->g:Lx21/y;

    .line 14
    .line 15
    invoke-virtual {p0}, Lx21/y;->d()Lx21/x;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0}, Lx21/x;->b()J

    .line 22
    .line 23
    .line 24
    move-result-wide v1

    .line 25
    const/16 v3, 0x20

    .line 26
    .line 27
    shr-long v4, v1, v3

    .line 28
    .line 29
    long-to-int v4, v4

    .line 30
    int-to-float v4, v4

    .line 31
    const-wide v5, 0xffffffffL

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    and-long/2addr v1, v5

    .line 37
    long-to-int v1, v1

    .line 38
    int-to-float v1, v1

    .line 39
    invoke-static {v4, v1}, Ljp/bf;->a(FF)J

    .line 40
    .line 41
    .line 42
    move-result-wide v1

    .line 43
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-static {v1, v2, v4}, Llp/ee;->c(JLg1/w1;)F

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    invoke-virtual {v0}, Lx21/x;->c()J

    .line 52
    .line 53
    .line 54
    move-result-wide v7

    .line 55
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    const-string v0, "orientation"

    .line 60
    .line 61
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-eqz p0, :cond_1

    .line 69
    .line 70
    const/4 v0, 0x1

    .line 71
    if-ne p0, v0, :cond_0

    .line 72
    .line 73
    shr-long v2, v7, v3

    .line 74
    .line 75
    :goto_0
    long-to-int p0, v2

    .line 76
    goto :goto_1

    .line 77
    :cond_0
    new-instance p0, La8/r0;

    .line 78
    .line 79
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :cond_1
    and-long v2, v7, v5

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :goto_1
    int-to-float p0, p0

    .line 87
    add-float/2addr v1, p0

    .line 88
    const/high16 p0, 0x3f800000    # 1.0f

    .line 89
    .line 90
    sub-float/2addr v1, p0

    .line 91
    goto :goto_2

    .line 92
    :cond_2
    const/4 v1, 0x0

    .line 93
    :goto_2
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    :pswitch_1
    iget-object p0, p0, Lx21/n;->g:Lx21/y;

    .line 99
    .line 100
    invoke-virtual {p0}, Lx21/y;->d()Lx21/x;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    if-eqz v0, :cond_5

    .line 105
    .line 106
    iget-object v1, p0, Lx21/y;->a:Lt1/j0;

    .line 107
    .line 108
    invoke-virtual {v1}, Lt1/j0;->m()Lpv/g;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    iget-object v2, v1, Lpv/g;->e:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v2, Lm1/l;

    .line 115
    .line 116
    invoke-virtual {v1}, Lpv/g;->g()Lg1/w1;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    const-wide v3, 0xffffffffL

    .line 125
    .line 126
    .line 127
    .line 128
    .line 129
    const/16 v5, 0x20

    .line 130
    .line 131
    if-eqz v1, :cond_4

    .line 132
    .line 133
    const/4 v6, 0x1

    .line 134
    if-ne v1, v6, :cond_3

    .line 135
    .line 136
    invoke-virtual {v2}, Lm1/l;->e()J

    .line 137
    .line 138
    .line 139
    move-result-wide v1

    .line 140
    shr-long/2addr v1, v5

    .line 141
    :goto_3
    long-to-int v1, v1

    .line 142
    goto :goto_4

    .line 143
    :cond_3
    new-instance p0, La8/r0;

    .line 144
    .line 145
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_4
    invoke-virtual {v2}, Lm1/l;->e()J

    .line 150
    .line 151
    .line 152
    move-result-wide v1

    .line 153
    and-long/2addr v1, v3

    .line 154
    goto :goto_3

    .line 155
    :goto_4
    int-to-float v1, v1

    .line 156
    invoke-virtual {v0}, Lx21/x;->b()J

    .line 157
    .line 158
    .line 159
    move-result-wide v6

    .line 160
    shr-long v8, v6, v5

    .line 161
    .line 162
    long-to-int v0, v8

    .line 163
    int-to-float v0, v0

    .line 164
    and-long v2, v6, v3

    .line 165
    .line 166
    long-to-int v2, v2

    .line 167
    int-to-float v2, v2

    .line 168
    invoke-static {v0, v2}, Ljp/bf;->a(FF)J

    .line 169
    .line 170
    .line 171
    move-result-wide v2

    .line 172
    invoke-virtual {p0}, Lx21/y;->f()Lg1/w1;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    invoke-static {v2, v3, p0}, Llp/ee;->c(JLg1/w1;)F

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    sub-float/2addr v1, p0

    .line 181
    const/high16 p0, 0x3f800000    # 1.0f

    .line 182
    .line 183
    sub-float/2addr v1, p0

    .line 184
    goto :goto_5

    .line 185
    :cond_5
    const/4 v1, 0x0

    .line 186
    :goto_5
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    return-object p0

    .line 191
    :pswitch_2
    iget-object p0, p0, Lx21/n;->g:Lx21/y;

    .line 192
    .line 193
    iget-object p0, p0, Lx21/y;->a:Lt1/j0;

    .line 194
    .line 195
    invoke-virtual {p0}, Lt1/j0;->m()Lpv/g;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    return-object p0

    .line 200
    :pswitch_3
    iget-object p0, p0, Lx21/n;->g:Lx21/y;

    .line 201
    .line 202
    iget-object p0, p0, Lx21/y;->k:Ll2/j1;

    .line 203
    .line 204
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    if-eqz p0, :cond_6

    .line 209
    .line 210
    const/4 p0, 0x1

    .line 211
    goto :goto_6

    .line 212
    :cond_6
    const/4 p0, 0x0

    .line 213
    :goto_6
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    return-object p0

    .line 218
    nop

    .line 219
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
