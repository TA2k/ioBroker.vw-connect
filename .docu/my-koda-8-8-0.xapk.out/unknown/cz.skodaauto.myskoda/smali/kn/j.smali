.class public final Lkn/j;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p6, p0, Lkn/j;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/j;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lkn/j;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lkn/j;->i:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lkn/j;->j:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lkn/j;->k:Ljava/lang/Object;

    .line 12
    .line 13
    const/4 p1, 0x0

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lkn/j;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkn/j;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lx4/t;

    .line 9
    .line 10
    iget-object v1, p0, Lkn/j;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lay0/a;

    .line 13
    .line 14
    iget-object v2, p0, Lkn/j;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lx4/w;

    .line 17
    .line 18
    iget-object v3, p0, Lkn/j;->j:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Ljava/lang/String;

    .line 21
    .line 22
    iget-object p0, p0, Lkn/j;->k:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lt4/m;

    .line 25
    .line 26
    invoke-virtual {v0, v1, v2, v3, p0}, Lx4/t;->k(Lay0/a;Lx4/w;Ljava/lang/String;Lt4/m;)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    iget-object v0, p0, Lkn/j;->h:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lkn/c0;

    .line 35
    .line 36
    iget-object v1, p0, Lkn/j;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Lkn/j0;

    .line 39
    .line 40
    iget-boolean v1, v1, Lkn/j0;->a:Z

    .line 41
    .line 42
    if-nez v1, :cond_0

    .line 43
    .line 44
    goto/16 :goto_0

    .line 45
    .line 46
    :cond_0
    iget v1, v0, Lkn/c0;->p:F

    .line 47
    .line 48
    const/high16 v2, 0x447a0000    # 1000.0f

    .line 49
    .line 50
    cmpg-float v1, v1, v2

    .line 51
    .line 52
    if-gez v1, :cond_2

    .line 53
    .line 54
    iget-object v1, p0, Lkn/j;->i:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v1, Lkn/m0;

    .line 57
    .line 58
    iget-object v2, p0, Lkn/j;->k:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v2, Ll2/b1;

    .line 61
    .line 62
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    check-cast v2, Ld3/b;

    .line 67
    .line 68
    iget-wide v2, v2, Ld3/b;->a:J

    .line 69
    .line 70
    iget-object v4, v1, Lkn/m0;->a:Lt3/y;

    .line 71
    .line 72
    if-nez v4, :cond_1

    .line 73
    .line 74
    invoke-static {v2, v3}, Ld3/b;->f(J)F

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    iget v1, v1, Lkn/m0;->c:I

    .line 79
    .line 80
    int-to-float v1, v1

    .line 81
    cmpl-float v1, v2, v1

    .line 82
    .line 83
    if-ltz v1, :cond_2

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_1
    const-wide/16 v5, 0x0

    .line 87
    .line 88
    invoke-interface {v4, v5, v6}, Lt3/y;->R(J)J

    .line 89
    .line 90
    .line 91
    move-result-wide v5

    .line 92
    invoke-static {v2, v3}, Ld3/b;->e(J)F

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    invoke-static {v2, v3}, Ld3/b;->f(J)F

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    invoke-static {v5, v6}, Ld3/b;->e(J)F

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    iget v8, v1, Lkn/m0;->b:I

    .line 105
    .line 106
    int-to-float v8, v8

    .line 107
    add-float/2addr v3, v8

    .line 108
    cmpl-float v3, v7, v3

    .line 109
    .line 110
    if-ltz v3, :cond_2

    .line 111
    .line 112
    invoke-static {v5, v6}, Ld3/b;->e(J)F

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    iget v8, v1, Lkn/m0;->b:I

    .line 117
    .line 118
    int-to-float v8, v8

    .line 119
    add-float/2addr v3, v8

    .line 120
    invoke-interface {v4}, Lt3/y;->h()J

    .line 121
    .line 122
    .line 123
    move-result-wide v8

    .line 124
    const/16 v10, 0x20

    .line 125
    .line 126
    shr-long/2addr v8, v10

    .line 127
    long-to-int v8, v8

    .line 128
    int-to-float v8, v8

    .line 129
    add-float/2addr v3, v8

    .line 130
    cmpg-float v3, v7, v3

    .line 131
    .line 132
    if-gtz v3, :cond_2

    .line 133
    .line 134
    invoke-static {v5, v6}, Ld3/b;->f(J)F

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    iget v7, v1, Lkn/m0;->c:I

    .line 139
    .line 140
    int-to-float v7, v7

    .line 141
    add-float/2addr v3, v7

    .line 142
    cmpl-float v3, v2, v3

    .line 143
    .line 144
    if-ltz v3, :cond_2

    .line 145
    .line 146
    invoke-static {v5, v6}, Ld3/b;->f(J)F

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    iget v1, v1, Lkn/m0;->c:I

    .line 151
    .line 152
    int-to-float v1, v1

    .line 153
    add-float/2addr v3, v1

    .line 154
    invoke-interface {v4}, Lt3/y;->h()J

    .line 155
    .line 156
    .line 157
    move-result-wide v4

    .line 158
    const-wide v6, 0xffffffffL

    .line 159
    .line 160
    .line 161
    .line 162
    .line 163
    and-long/2addr v4, v6

    .line 164
    long-to-int v1, v4

    .line 165
    int-to-float v1, v1

    .line 166
    add-float/2addr v3, v1

    .line 167
    cmpg-float v1, v2, v3

    .line 168
    .line 169
    if-gtz v1, :cond_2

    .line 170
    .line 171
    goto :goto_0

    .line 172
    :cond_2
    iget-object p0, p0, Lkn/j;->j:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast p0, Lvy0/b0;

    .line 175
    .line 176
    new-instance v1, Lkn/d;

    .line 177
    .line 178
    const/4 v2, 0x3

    .line 179
    const/4 v3, 0x0

    .line 180
    invoke-direct {v1, v0, v3, v2}, Lkn/d;-><init>(Lkn/c0;Lkotlin/coroutines/Continuation;I)V

    .line 181
    .line 182
    .line 183
    const/4 v0, 0x3

    .line 184
    invoke-static {p0, v3, v3, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 185
    .line 186
    .line 187
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 188
    .line 189
    return-object p0

    .line 190
    nop

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
