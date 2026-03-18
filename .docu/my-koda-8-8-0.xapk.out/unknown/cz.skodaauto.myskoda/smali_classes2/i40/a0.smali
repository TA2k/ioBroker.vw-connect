.class public final synthetic Li40/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lp1/v;


# direct methods
.method public synthetic constructor <init>(Lp1/v;I)V
    .locals 0

    .line 1
    iput p2, p0, Li40/a0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/a0;->e:Lp1/v;

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
    iget v0, p0, Li40/a0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 7
    .line 8
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 18
    .line 19
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    goto :goto_0

    .line 24
    :pswitch_1
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 25
    .line 26
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    goto :goto_0

    .line 31
    :pswitch_2
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 32
    .line 33
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    goto :goto_0

    .line 38
    :pswitch_3
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 39
    .line 40
    iget-object v0, p0, Lp1/v;->s:Ll2/g1;

    .line 41
    .line 42
    iget-object v1, p0, Lp1/v;->k:Lg1/f0;

    .line 43
    .line 44
    invoke-virtual {v1}, Lg1/f0;->a()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-nez v1, :cond_0

    .line 49
    .line 50
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    goto :goto_1

    .line 55
    :cond_0
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    const/4 v2, -0x1

    .line 60
    if-eq v1, v2, :cond_1

    .line 61
    .line 62
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    iget-object v0, p0, Lp1/v;->d:Lh8/o;

    .line 68
    .line 69
    iget-object v0, v0, Lh8/o;->d:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Ll2/f1;

    .line 72
    .line 73
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    iget-object v1, p0, Lp1/v;->q:Lt4/c;

    .line 82
    .line 83
    sget v2, Lp1/y;->a:F

    .line 84
    .line 85
    invoke-interface {v1, v2}, Lt4/c;->w0(F)F

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {p0}, Lp1/v;->n()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    int-to-float v2, v2

    .line 94
    const/high16 v3, 0x40000000    # 2.0f

    .line 95
    .line 96
    div-float/2addr v2, v3

    .line 97
    invoke-static {v1, v2}, Ljava/lang/Math;->min(FF)F

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    invoke-virtual {p0}, Lp1/v;->n()I

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    int-to-float v2, v2

    .line 106
    div-float/2addr v1, v2

    .line 107
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    cmpl-float v0, v0, v1

    .line 112
    .line 113
    if-ltz v0, :cond_3

    .line 114
    .line 115
    iget-object v0, p0, Lp1/v;->G:Ll2/j1;

    .line 116
    .line 117
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    check-cast v0, Ljava/lang/Boolean;

    .line 122
    .line 123
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    if-eqz v0, :cond_2

    .line 128
    .line 129
    iget v0, p0, Lp1/v;->e:I

    .line 130
    .line 131
    add-int/lit8 v0, v0, 0x1

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_2
    iget v0, p0, Lp1/v;->e:I

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_3
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    :goto_1
    invoke-virtual {p0, v0}, Lp1/v;->j(I)I

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    goto/16 :goto_0

    .line 146
    .line 147
    :pswitch_4
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 148
    .line 149
    iget-object v0, p0, Lp1/v;->k:Lg1/f0;

    .line 150
    .line 151
    invoke-virtual {v0}, Lg1/f0;->a()Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    if-eqz v0, :cond_4

    .line 156
    .line 157
    iget-object p0, p0, Lp1/v;->t:Ll2/g1;

    .line 158
    .line 159
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    goto :goto_2

    .line 164
    :cond_4
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 165
    .line 166
    .line 167
    move-result p0

    .line 168
    :goto_2
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0

    .line 173
    :pswitch_5
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 174
    .line 175
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 176
    .line 177
    .line 178
    move-result p0

    .line 179
    goto/16 :goto_0

    .line 180
    .line 181
    :pswitch_6
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 182
    .line 183
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 184
    .line 185
    .line 186
    move-result p0

    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :pswitch_7
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 190
    .line 191
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    goto/16 :goto_0

    .line 196
    .line 197
    :pswitch_8
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 198
    .line 199
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    goto/16 :goto_0

    .line 204
    .line 205
    :pswitch_9
    iget-object p0, p0, Li40/a0;->e:Lp1/v;

    .line 206
    .line 207
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 208
    .line 209
    .line 210
    move-result p0

    .line 211
    goto/16 :goto_0

    .line 212
    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
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
