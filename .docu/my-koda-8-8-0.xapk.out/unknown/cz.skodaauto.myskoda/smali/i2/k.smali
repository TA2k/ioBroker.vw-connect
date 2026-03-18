.class public final synthetic Li2/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li2/p;


# direct methods
.method public synthetic constructor <init>(Li2/p;I)V
    .locals 0

    .line 1
    iput p2, p0, Li2/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li2/k;->e:Li2/p;

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
    iget v0, p0, Li2/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Li2/k;->e:Li2/p;

    .line 7
    .line 8
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Li2/p;->h:Ll2/h0;

    .line 13
    .line 14
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v1, Llx0/l;

    .line 19
    .line 20
    invoke-direct {v1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-object v1

    .line 24
    :pswitch_0
    iget-object p0, p0, Li2/k;->e:Li2/p;

    .line 25
    .line 26
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_1
    iget-object p0, p0, Li2/k;->e:Li2/p;

    .line 32
    .line 33
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iget-object v1, p0, Li2/p;->g:Ll2/j1;

    .line 38
    .line 39
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v0, v1}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    iget-object v2, p0, Li2/p;->i:Ll2/h0;

    .line 52
    .line 53
    invoke-virtual {v2}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-virtual {v1, v2}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    sub-float/2addr v1, v0

    .line 62
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    if-nez v3, :cond_1

    .line 71
    .line 72
    const v3, 0x358637bd    # 1.0E-6f

    .line 73
    .line 74
    .line 75
    cmpl-float v2, v2, v3

    .line 76
    .line 77
    if-lez v2, :cond_1

    .line 78
    .line 79
    invoke-virtual {p0}, Li2/p;->f()F

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    sub-float/2addr p0, v0

    .line 84
    div-float/2addr p0, v1

    .line 85
    cmpg-float v0, p0, v3

    .line 86
    .line 87
    if-gez v0, :cond_0

    .line 88
    .line 89
    const/4 p0, 0x0

    .line 90
    goto :goto_0

    .line 91
    :cond_0
    const v0, 0x3f7fffef    # 0.999999f

    .line 92
    .line 93
    .line 94
    cmpl-float v0, p0, v0

    .line 95
    .line 96
    if-lez v0, :cond_2

    .line 97
    .line 98
    :cond_1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 99
    .line 100
    :cond_2
    :goto_0
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0

    .line 105
    :pswitch_2
    iget-object p0, p0, Li2/k;->e:Li2/p;

    .line 106
    .line 107
    iget-object v0, p0, Li2/p;->l:Ll2/j1;

    .line 108
    .line 109
    iget-object v1, p0, Li2/p;->g:Ll2/j1;

    .line 110
    .line 111
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    if-nez v0, :cond_7

    .line 116
    .line 117
    iget-object v0, p0, Li2/p;->j:Ll2/f1;

    .line 118
    .line 119
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    if-nez v2, :cond_6

    .line 128
    .line 129
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-virtual {p0, v1}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    cmpg-float v3, v2, v0

    .line 142
    .line 143
    if-nez v3, :cond_3

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_3
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 147
    .line 148
    .line 149
    move-result v2

    .line 150
    if-eqz v2, :cond_4

    .line 151
    .line 152
    goto :goto_1

    .line 153
    :cond_4
    if-gez v3, :cond_5

    .line 154
    .line 155
    const/4 v2, 0x1

    .line 156
    invoke-virtual {p0, v0, v2}, Li2/u0;->b(FZ)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    if-nez v0, :cond_7

    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_5
    const/4 v2, 0x0

    .line 164
    invoke-virtual {p0, v0, v2}, Li2/u0;->b(FZ)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    if-nez v0, :cond_7

    .line 169
    .line 170
    :goto_1
    move-object v0, v1

    .line 171
    goto :goto_2

    .line 172
    :cond_6
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    :cond_7
    :goto_2
    return-object v0

    .line 177
    :pswitch_3
    iget-object p0, p0, Li2/k;->e:Li2/p;

    .line 178
    .line 179
    iget-object v0, p0, Li2/p;->l:Ll2/j1;

    .line 180
    .line 181
    iget-object v1, p0, Li2/p;->g:Ll2/j1;

    .line 182
    .line 183
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    if-nez v0, :cond_9

    .line 188
    .line 189
    iget-object v0, p0, Li2/p;->j:Ll2/f1;

    .line 190
    .line 191
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    if-nez v2, :cond_8

    .line 200
    .line 201
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    const/4 v2, 0x0

    .line 206
    invoke-virtual {p0, v0, v2, v1}, Li2/p;->c(FFLjava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    goto :goto_3

    .line 211
    :cond_8
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    :cond_9
    :goto_3
    return-object v0

    .line 216
    nop

    .line 217
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
