.class public final synthetic Lal/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lx2/s;ZLay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lal/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lal/r;->e:Lx2/s;

    iput-boolean p2, p0, Lal/r;->f:Z

    iput-object p3, p0, Lal/r;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(ZLx2/s;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lal/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lal/r;->f:Z

    iput-object p2, p0, Lal/r;->e:Lx2/s;

    iput-object p3, p0, Lal/r;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lal/r;->d:I

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
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x1

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v2

    .line 24
    :goto_0
    and-int/2addr p2, v3

    .line 25
    move-object v9, p1

    .line 26
    check-cast v9, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_5

    .line 33
    .line 34
    iget-boolean p1, p0, Lal/r;->f:Z

    .line 35
    .line 36
    if-ne p1, v3, :cond_1

    .line 37
    .line 38
    const p2, -0x72f10c2e

    .line 39
    .line 40
    .line 41
    const v0, 0x7f120bcc

    .line 42
    .line 43
    .line 44
    :goto_1
    invoke-static {p2, v0, v9, v9, v2}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    move-object v5, p2

    .line 49
    goto :goto_2

    .line 50
    :cond_1
    if-nez p1, :cond_4

    .line 51
    .line 52
    const p2, -0x72f1004e

    .line 53
    .line 54
    .line 55
    const v0, 0x7f120baf

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :goto_2
    invoke-virtual {v9, p1}, Ll2/t;->h(Z)Z

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    iget-object v0, p0, Lal/r;->g:Lay0/k;

    .line 64
    .line 65
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    or-int/2addr p2, v1

    .line 70
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    if-nez p2, :cond_2

    .line 75
    .line 76
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 77
    .line 78
    if-ne v1, p2, :cond_3

    .line 79
    .line 80
    :cond_2
    new-instance v1, Lal/s;

    .line 81
    .line 82
    invoke-direct {v1, v0, p1}, Lal/s;-><init>(Lay0/k;Z)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    move-object v7, v1

    .line 89
    check-cast v7, Lay0/a;

    .line 90
    .line 91
    const/16 v10, 0x6000

    .line 92
    .line 93
    const/4 v11, 0x4

    .line 94
    iget-object v4, p0, Lal/r;->e:Lx2/s;

    .line 95
    .line 96
    const/4 v6, 0x0

    .line 97
    const-string v8, "wallbox_onboarding_success_continue_onboarding_Cta"

    .line 98
    .line 99
    invoke-static/range {v4 .. v11}, Ljp/nd;->b(Lx2/s;Ljava/lang/String;ZLay0/a;Ljava/lang/String;Ll2/o;II)V

    .line 100
    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_4
    const p0, -0x72f11808

    .line 104
    .line 105
    .line 106
    invoke-static {p0, v9, v2}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    throw p0

    .line 111
    :cond_5
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 112
    .line 113
    .line 114
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 118
    .line 119
    const/4 v1, 0x2

    .line 120
    const/4 v2, 0x1

    .line 121
    const/4 v3, 0x0

    .line 122
    if-eq v0, v1, :cond_6

    .line 123
    .line 124
    move v0, v2

    .line 125
    goto :goto_4

    .line 126
    :cond_6
    move v0, v3

    .line 127
    :goto_4
    and-int/2addr p2, v2

    .line 128
    move-object v7, p1

    .line 129
    check-cast v7, Ll2/t;

    .line 130
    .line 131
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 132
    .line 133
    .line 134
    move-result p1

    .line 135
    if-eqz p1, :cond_a

    .line 136
    .line 137
    iget-boolean p1, p0, Lal/r;->f:Z

    .line 138
    .line 139
    if-nez p1, :cond_9

    .line 140
    .line 141
    const p1, -0x3961d7dd

    .line 142
    .line 143
    .line 144
    invoke-virtual {v7, p1}, Ll2/t;->Y(I)V

    .line 145
    .line 146
    .line 147
    const p1, 0x7f120bcc

    .line 148
    .line 149
    .line 150
    invoke-static {v7, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    iget-object p1, p0, Lal/r;->g:Lay0/k;

    .line 155
    .line 156
    invoke-virtual {v7, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result p2

    .line 160
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    if-nez p2, :cond_7

    .line 165
    .line 166
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 167
    .line 168
    if-ne v0, p2, :cond_8

    .line 169
    .line 170
    :cond_7
    new-instance v0, Lak/n;

    .line 171
    .line 172
    const/4 p2, 0x7

    .line 173
    invoke-direct {v0, p2, p1}, Lak/n;-><init>(ILay0/k;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    :cond_8
    move-object v6, v0

    .line 180
    check-cast v6, Lay0/a;

    .line 181
    .line 182
    const/4 v8, 0x0

    .line 183
    const/4 v9, 0x0

    .line 184
    iget-object v4, p0, Lal/r;->e:Lx2/s;

    .line 185
    .line 186
    invoke-static/range {v4 .. v9}, Ljp/nd;->a(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 187
    .line 188
    .line 189
    :goto_5
    invoke-virtual {v7, v3}, Ll2/t;->q(Z)V

    .line 190
    .line 191
    .line 192
    goto :goto_6

    .line 193
    :cond_9
    const p0, -0x39a02427

    .line 194
    .line 195
    .line 196
    invoke-virtual {v7, p0}, Ll2/t;->Y(I)V

    .line 197
    .line 198
    .line 199
    goto :goto_5

    .line 200
    :cond_a
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 201
    .line 202
    .line 203
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0

    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
