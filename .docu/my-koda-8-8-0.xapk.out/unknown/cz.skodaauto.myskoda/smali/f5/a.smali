.class public final Lf5/a;
.super Le5/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic n0:I

.field public o0:F


# direct methods
.method public synthetic constructor <init>(Lz4/q;II)V
    .locals 0

    .line 1
    iput p3, p0, Lf5/a;->n0:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Le5/h;-><init>(Lz4/q;I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final apply()V
    .locals 5

    .line 1
    iget v0, p0, Lf5/a;->n0:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Le5/h;->m0:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_5

    .line 22
    .line 23
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    iget-object v3, p0, Le5/h;->k0:Lz4/q;

    .line 28
    .line 29
    invoke-virtual {v3, v2}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v2}, Le5/b;->h()V

    .line 34
    .line 35
    .line 36
    iget-object v3, p0, Le5/b;->R:Ljava/lang/Object;

    .line 37
    .line 38
    if-eqz v3, :cond_1

    .line 39
    .line 40
    invoke-virtual {v2, v3}, Le5/b;->p(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    iget-object v3, p0, Le5/b;->S:Ljava/lang/Object;

    .line 45
    .line 46
    if-eqz v3, :cond_2

    .line 47
    .line 48
    const/16 v4, 0xa

    .line 49
    .line 50
    iput v4, v2, Le5/b;->j0:I

    .line 51
    .line 52
    iput-object v3, v2, Le5/b;->S:Ljava/lang/Object;

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    invoke-virtual {v2, v0}, Le5/b;->p(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :goto_1
    iget-object v3, p0, Le5/b;->U:Ljava/lang/Object;

    .line 59
    .line 60
    if-eqz v3, :cond_3

    .line 61
    .line 62
    const/16 v4, 0xc

    .line 63
    .line 64
    iput v4, v2, Le5/b;->j0:I

    .line 65
    .line 66
    iput-object v3, v2, Le5/b;->U:Ljava/lang/Object;

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    iget-object v3, p0, Le5/b;->V:Ljava/lang/Object;

    .line 70
    .line 71
    if-eqz v3, :cond_4

    .line 72
    .line 73
    invoke-virtual {v2, v3}, Le5/b;->e(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    invoke-virtual {v2, v0}, Le5/b;->e(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :goto_2
    iget v3, p0, Lf5/a;->o0:F

    .line 81
    .line 82
    const/high16 v4, 0x3f000000    # 0.5f

    .line 83
    .line 84
    cmpl-float v4, v3, v4

    .line 85
    .line 86
    if-eqz v4, :cond_0

    .line 87
    .line 88
    iput v3, v2, Le5/b;->i:F

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_5
    return-void

    .line 92
    :pswitch_0
    const/4 v0, 0x0

    .line 93
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v1, p0, Le5/h;->m0:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    :cond_6
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    if-eqz v2, :cond_b

    .line 108
    .line 109
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    iget-object v3, p0, Le5/h;->k0:Lz4/q;

    .line 114
    .line 115
    invoke-virtual {v3, v2}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    invoke-virtual {v2}, Le5/b;->g()V

    .line 120
    .line 121
    .line 122
    iget-object v3, p0, Le5/b;->N:Ljava/lang/Object;

    .line 123
    .line 124
    if-eqz v3, :cond_7

    .line 125
    .line 126
    invoke-virtual {v2, v3}, Le5/b;->o(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_4

    .line 130
    :cond_7
    iget-object v3, p0, Le5/b;->O:Ljava/lang/Object;

    .line 131
    .line 132
    if-eqz v3, :cond_8

    .line 133
    .line 134
    const/4 v4, 0x6

    .line 135
    iput v4, v2, Le5/b;->j0:I

    .line 136
    .line 137
    iput-object v3, v2, Le5/b;->O:Ljava/lang/Object;

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_8
    invoke-virtual {v2, v0}, Le5/b;->o(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :goto_4
    iget-object v3, p0, Le5/b;->P:Ljava/lang/Object;

    .line 144
    .line 145
    if-eqz v3, :cond_9

    .line 146
    .line 147
    const/4 v4, 0x7

    .line 148
    iput v4, v2, Le5/b;->j0:I

    .line 149
    .line 150
    iput-object v3, v2, Le5/b;->P:Ljava/lang/Object;

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_9
    iget-object v3, p0, Le5/b;->Q:Ljava/lang/Object;

    .line 154
    .line 155
    if-eqz v3, :cond_a

    .line 156
    .line 157
    invoke-virtual {v2, v3}, Le5/b;->i(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    goto :goto_5

    .line 161
    :cond_a
    invoke-virtual {v2, v0}, Le5/b;->i(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    :goto_5
    iget v3, p0, Lf5/a;->o0:F

    .line 165
    .line 166
    const/high16 v4, 0x3f000000    # 0.5f

    .line 167
    .line 168
    cmpl-float v4, v3, v4

    .line 169
    .line 170
    if-eqz v4, :cond_6

    .line 171
    .line 172
    iput v3, v2, Le5/b;->h:F

    .line 173
    .line 174
    goto :goto_3

    .line 175
    :cond_b
    return-void

    .line 176
    nop

    .line 177
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
