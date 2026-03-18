.class public final synthetic Lh2/c9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/s9;


# direct methods
.method public synthetic constructor <init>(Lh2/s9;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/c9;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/c9;->e:Lh2/s9;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lh2/c9;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld3/b;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iget-object p0, p0, Lh2/c9;->e:Lh2/s9;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lh2/s9;->b(F)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lh2/s9;->o:Ld2/g;

    .line 15
    .line 16
    invoke-virtual {p0}, Ld2/g;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Lh2/c9;->e:Lh2/s9;

    .line 23
    .line 24
    iget-object v0, p0, Lh2/s9;->d:Ll2/f1;

    .line 25
    .line 26
    check-cast p1, Ljava/lang/Float;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    iget-object v1, p0, Lh2/s9;->c:Lgy0/f;

    .line 33
    .line 34
    invoke-interface {v1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    check-cast v2, Ljava/lang/Number;

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    check-cast v3, Ljava/lang/Number;

    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    invoke-static {p1, v2, v3}, Lkp/r9;->d(FFF)F

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    iget v2, p0, Lh2/s9;->a:I

    .line 59
    .line 60
    const/4 v3, 0x0

    .line 61
    const/4 v4, 0x1

    .line 62
    if-lez v2, :cond_2

    .line 63
    .line 64
    add-int/2addr v2, v4

    .line 65
    if-ltz v2, :cond_2

    .line 66
    .line 67
    move v6, p1

    .line 68
    move v7, v6

    .line 69
    move v5, v3

    .line 70
    :goto_1
    invoke-interface {v1}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 71
    .line 72
    .line 73
    move-result-object v8

    .line 74
    check-cast v8, Ljava/lang/Number;

    .line 75
    .line 76
    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    .line 77
    .line 78
    .line 79
    move-result v8

    .line 80
    invoke-interface {v1}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 81
    .line 82
    .line 83
    move-result-object v9

    .line 84
    check-cast v9, Ljava/lang/Number;

    .line 85
    .line 86
    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    int-to-float v10, v5

    .line 91
    int-to-float v11, v2

    .line 92
    div-float/2addr v10, v11

    .line 93
    invoke-static {v8, v9, v10}, Llp/wa;->b(FFF)F

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    sub-float v9, v8, p1

    .line 98
    .line 99
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 100
    .line 101
    .line 102
    move-result v10

    .line 103
    cmpg-float v10, v10, v6

    .line 104
    .line 105
    if-gtz v10, :cond_0

    .line 106
    .line 107
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    move v7, v8

    .line 112
    :cond_0
    if-eq v5, v2, :cond_1

    .line 113
    .line 114
    add-int/lit8 v5, v5, 0x1

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_1
    move p1, v7

    .line 118
    :cond_2
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    cmpg-float v1, p1, v1

    .line 123
    .line 124
    if-nez v1, :cond_3

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_3
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    cmpg-float v0, p1, v0

    .line 132
    .line 133
    if-nez v0, :cond_4

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_4
    iget-object v0, p0, Lh2/s9;->e:Lay0/k;

    .line 137
    .line 138
    if-eqz v0, :cond_5

    .line 139
    .line 140
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_5
    invoke-virtual {p0, p1}, Lh2/s9;->d(F)V

    .line 149
    .line 150
    .line 151
    :goto_2
    iget-object p0, p0, Lh2/s9;->b:Lay0/a;

    .line 152
    .line 153
    if-eqz p0, :cond_6

    .line 154
    .line 155
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    :cond_6
    move v3, v4

    .line 159
    :goto_3
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_1
    check-cast p1, Lt4/l;

    .line 165
    .line 166
    iget-wide v0, p1, Lt4/l;->a:J

    .line 167
    .line 168
    const/16 v2, 0x20

    .line 169
    .line 170
    shr-long/2addr v0, v2

    .line 171
    long-to-int v0, v0

    .line 172
    iget-object p0, p0, Lh2/c9;->e:Lh2/s9;

    .line 173
    .line 174
    iget-object v1, p0, Lh2/s9;->k:Ll2/g1;

    .line 175
    .line 176
    invoke-virtual {v1, v0}, Ll2/g1;->p(I)V

    .line 177
    .line 178
    .line 179
    iget-wide v0, p1, Lt4/l;->a:J

    .line 180
    .line 181
    const-wide v2, 0xffffffffL

    .line 182
    .line 183
    .line 184
    .line 185
    .line 186
    and-long/2addr v0, v2

    .line 187
    long-to-int p1, v0

    .line 188
    iget-object p0, p0, Lh2/s9;->l:Ll2/g1;

    .line 189
    .line 190
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 191
    .line 192
    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
