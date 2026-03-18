.class public final Lkn/n;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Lkn/c0;

.field public final synthetic g:Lvy0/b0;

.field public final synthetic h:Lt4/c;

.field public final synthetic i:F

.field public final synthetic j:Lc1/c;


# direct methods
.method public constructor <init>(Lkn/c0;Lvy0/b0;Lt4/c;FLc1/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkn/n;->f:Lkn/c0;

    .line 2
    .line 3
    iput-object p2, p0, Lkn/n;->g:Lvy0/b0;

    .line 4
    .line 5
    iput-object p3, p0, Lkn/n;->h:Lt4/c;

    .line 6
    .line 7
    iput p4, p0, Lkn/n;->i:F

    .line 8
    .line 9
    iput-object p5, p0, Lkn/n;->j:Lc1/c;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Lt4/l;

    .line 2
    .line 3
    iget-wide v0, p1, Lt4/l;->a:J

    .line 4
    .line 5
    iget-object v3, p0, Lkn/n;->f:Lkn/c0;

    .line 6
    .line 7
    iget-object p1, v3, Lkn/c0;->c:Ll2/g1;

    .line 8
    .line 9
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    const-wide v4, 0xffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    and-long/2addr v0, v4

    .line 19
    long-to-int v0, v0

    .line 20
    if-ne p1, v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v3}, Lkn/c0;->g()F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    :goto_0
    float-to-int v0, p0

    .line 27
    goto/16 :goto_6

    .line 28
    .line 29
    :cond_0
    int-to-float p1, v0

    .line 30
    const/high16 v1, 0x40400000    # 3.0f

    .line 31
    .line 32
    div-float/2addr p1, v1

    .line 33
    const/16 v1, 0xa0

    .line 34
    .line 35
    int-to-float v1, v1

    .line 36
    iget-object v2, p0, Lkn/n;->h:Lt4/c;

    .line 37
    .line 38
    invoke-interface {v2, v1}, Lt4/c;->w0(F)F

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-static {p1, v1}, Ljava/lang/Math;->min(FF)F

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    iget-object v1, v3, Lkn/c0;->h:Ll2/f1;

    .line 47
    .line 48
    invoke-virtual {v1, p1}, Ll2/f1;->p(F)V

    .line 49
    .line 50
    .line 51
    iget-object p1, v3, Lkn/c0;->f:Lc1/c;

    .line 52
    .line 53
    invoke-virtual {p1}, Lc1/c;->e()Z

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    const/4 v1, 0x1

    .line 58
    const/4 v2, 0x0

    .line 59
    if-nez p1, :cond_2

    .line 60
    .line 61
    iget-boolean p1, v3, Lkn/c0;->n:Z

    .line 62
    .line 63
    if-eqz p1, :cond_1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    move v5, v2

    .line 67
    goto :goto_2

    .line 68
    :cond_2
    :goto_1
    move v5, v1

    .line 69
    :goto_2
    iget-object p1, v3, Lkn/c0;->c:Ll2/g1;

    .line 70
    .line 71
    invoke-virtual {p1, v0}, Ll2/g1;->p(I)V

    .line 72
    .line 73
    .line 74
    iget-object p1, v3, Lkn/c0;->s:Ll2/j1;

    .line 75
    .line 76
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Lkn/v;

    .line 81
    .line 82
    sget-object v4, Lkn/v;->g:Lkn/v;

    .line 83
    .line 84
    if-ne p1, v4, :cond_3

    .line 85
    .line 86
    invoke-virtual {v3}, Lkn/c0;->g()F

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    goto :goto_0

    .line 91
    :cond_3
    invoke-virtual {v3}, Lkn/c0;->i()Lkn/f0;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    const/4 v10, 0x3

    .line 100
    const/4 v11, 0x0

    .line 101
    iget-object v6, p0, Lkn/n;->g:Lvy0/b0;

    .line 102
    .line 103
    iget-object v7, p0, Lkn/n;->j:Lc1/c;

    .line 104
    .line 105
    if-eqz p1, :cond_7

    .line 106
    .line 107
    if-eq p1, v1, :cond_5

    .line 108
    .line 109
    const/4 p0, 0x2

    .line 110
    if-ne p1, p0, :cond_4

    .line 111
    .line 112
    new-instance p0, Lg90/b;

    .line 113
    .line 114
    const/4 p1, 0x2

    .line 115
    invoke-direct {p0, v3, v0, v11, p1}, Lg90/b;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 116
    .line 117
    .line 118
    invoke-static {v6, v11, v11, p0, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 119
    .line 120
    .line 121
    goto :goto_6

    .line 122
    :cond_4
    new-instance p0, La8/r0;

    .line 123
    .line 124
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_5
    if-eqz v5, :cond_6

    .line 129
    .line 130
    :goto_3
    move v4, v0

    .line 131
    goto :goto_4

    .line 132
    :cond_6
    invoke-virtual {v3}, Lkn/c0;->h()F

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    float-to-int p0, p0

    .line 137
    sub-int/2addr v0, p0

    .line 138
    goto :goto_3

    .line 139
    :goto_4
    new-instance v2, Lkn/t;

    .line 140
    .line 141
    const/4 v8, 0x0

    .line 142
    const/4 v9, 0x1

    .line 143
    invoke-direct/range {v2 .. v9}, Lkn/t;-><init>(Lkn/c0;IZLvy0/b0;Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 144
    .line 145
    .line 146
    invoke-static {v6, v11, v11, v2, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 147
    .line 148
    .line 149
    :goto_5
    move v0, v4

    .line 150
    goto :goto_6

    .line 151
    :cond_7
    if-eqz v5, :cond_8

    .line 152
    .line 153
    iget p0, p0, Lkn/n;->i:F

    .line 154
    .line 155
    float-to-int p0, p0

    .line 156
    invoke-static {v0, p0}, Ljava/lang/Math;->min(II)I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    :cond_8
    move v4, v2

    .line 161
    new-instance v2, Lkn/t;

    .line 162
    .line 163
    const/4 v8, 0x0

    .line 164
    const/4 v9, 0x0

    .line 165
    invoke-direct/range {v2 .. v9}, Lkn/t;-><init>(Lkn/c0;IZLvy0/b0;Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 166
    .line 167
    .line 168
    invoke-static {v6, v11, v11, v2, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 169
    .line 170
    .line 171
    goto :goto_5

    .line 172
    :goto_6
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0
.end method
