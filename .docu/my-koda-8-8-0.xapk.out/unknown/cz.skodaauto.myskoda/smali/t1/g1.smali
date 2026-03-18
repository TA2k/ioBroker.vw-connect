.class public final Lt1/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lt1/h1;

.field public final synthetic e:Z

.field public final synthetic f:Li1/l;


# direct methods
.method public constructor <init>(Lt1/h1;ZLi1/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/g1;->d:Lt1/h1;

    .line 5
    .line 6
    iput-boolean p2, p0, Lt1/g1;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lt1/g1;->f:Li1/l;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Lx2/s;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lt1/g1;->d:Lt1/h1;

    .line 11
    .line 12
    iget-object p3, p1, Lt1/h1;->f:Ll2/j1;

    .line 13
    .line 14
    check-cast p2, Ll2/t;

    .line 15
    .line 16
    const v0, 0x3001dc2a

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lw3/h1;->n:Ll2/u2;

    .line 23
    .line 24
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    sget-object v1, Lt4/m;->e:Lt4/m;

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    const/4 v3, 0x0

    .line 32
    if-ne v0, v1, :cond_0

    .line 33
    .line 34
    move v0, v2

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move v0, v3

    .line 37
    :goto_0
    invoke-virtual {p3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Lg1/w1;

    .line 42
    .line 43
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 44
    .line 45
    if-eq v1, v4, :cond_2

    .line 46
    .line 47
    if-nez v0, :cond_1

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move v9, v3

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    :goto_1
    move v9, v2

    .line 53
    :goto_2
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 62
    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    if-ne v1, v4, :cond_4

    .line 66
    .line 67
    :cond_3
    new-instance v1, Lpg/m;

    .line 68
    .line 69
    const/16 v0, 0xe

    .line 70
    .line 71
    invoke-direct {v1, p1, v0}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :cond_4
    check-cast v1, Lay0/k;

    .line 78
    .line 79
    invoke-static {v1, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    if-ne v1, v4, :cond_5

    .line 88
    .line 89
    new-instance v1, La2/g;

    .line 90
    .line 91
    const/16 v5, 0xa

    .line 92
    .line 93
    invoke-direct {v1, v0, v5}, La2/g;-><init>(Ll2/b1;I)V

    .line 94
    .line 95
    .line 96
    new-instance v0, Lg1/f0;

    .line 97
    .line 98
    invoke-direct {v0, v1}, Lg1/f0;-><init>(Lay0/k;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    move-object v1, v0

    .line 105
    :cond_5
    check-cast v1, Lg1/q2;

    .line 106
    .line 107
    invoke-virtual {p2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    or-int/2addr v0, v5

    .line 116
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    if-nez v0, :cond_6

    .line 121
    .line 122
    if-ne v5, v4, :cond_7

    .line 123
    .line 124
    :cond_6
    new-instance v5, Lt1/f1;

    .line 125
    .line 126
    invoke-direct {v5, v1, p1}, Lt1/f1;-><init>(Lg1/q2;Lt1/h1;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_7
    move-object v6, v5

    .line 133
    check-cast v6, Lt1/f1;

    .line 134
    .line 135
    invoke-virtual {p3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p3

    .line 139
    move-object v7, p3

    .line 140
    check-cast v7, Lg1/w1;

    .line 141
    .line 142
    iget-boolean p3, p0, Lt1/g1;->e:Z

    .line 143
    .line 144
    if-eqz p3, :cond_9

    .line 145
    .line 146
    iget-object p1, p1, Lt1/h1;->b:Ll2/f1;

    .line 147
    .line 148
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 149
    .line 150
    .line 151
    move-result p1

    .line 152
    const/4 p3, 0x0

    .line 153
    cmpg-float p1, p1, p3

    .line 154
    .line 155
    if-nez p1, :cond_8

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_8
    move v8, v2

    .line 159
    goto :goto_4

    .line 160
    :cond_9
    :goto_3
    move v8, v3

    .line 161
    :goto_4
    iget-object v10, p0, Lt1/g1;->f:Li1/l;

    .line 162
    .line 163
    const/16 v11, 0x10

    .line 164
    .line 165
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 166
    .line 167
    invoke-static/range {v5 .. v11}, Landroidx/compose/foundation/gestures/b;->b(Lx2/s;Lg1/q2;Lg1/w1;ZZLi1/l;I)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 172
    .line 173
    .line 174
    return-object p0
.end method
