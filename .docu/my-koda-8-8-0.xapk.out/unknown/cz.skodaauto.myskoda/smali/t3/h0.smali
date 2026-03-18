.class public final Lt3/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/p1;


# instance fields
.field public d:Lt4/m;

.field public e:F

.field public f:F

.field public final synthetic g:Lt3/m0;


# direct methods
.method public constructor <init>(Lt3/m0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/h0;->g:Lt3/m0;

    .line 5
    .line 6
    sget-object p1, Lt4/m;->e:Lt4/m;

    .line 7
    .line 8
    iput-object p1, p0, Lt3/h0;->d:Lt4/m;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;
    .locals 9

    .line 1
    iget-object p0, p0, Lt3/h0;->g:Lt3/m0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lt3/m0;->d()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lt3/m0;->d:Lv3/h0;

    .line 7
    .line 8
    iget-object v1, v0, Lv3/h0;->I:Lv3/l0;

    .line 9
    .line 10
    iget-object v1, v1, Lv3/l0;->d:Lv3/d0;

    .line 11
    .line 12
    sget-object v2, Lv3/d0;->d:Lv3/d0;

    .line 13
    .line 14
    if-eq v1, v2, :cond_1

    .line 15
    .line 16
    sget-object v3, Lv3/d0;->f:Lv3/d0;

    .line 17
    .line 18
    if-eq v1, v3, :cond_1

    .line 19
    .line 20
    sget-object v3, Lv3/d0;->e:Lv3/d0;

    .line 21
    .line 22
    if-eq v1, v3, :cond_1

    .line 23
    .line 24
    sget-object v3, Lv3/d0;->g:Lv3/d0;

    .line 25
    .line 26
    if-ne v1, v3, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const-string v3, "subcompose can only be used inside the measure or layout blocks"

    .line 30
    .line 31
    invoke-static {v3}, Ls3/a;->b(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :cond_1
    :goto_0
    iget-object v3, p0, Lt3/m0;->j:Landroidx/collection/q0;

    .line 35
    .line 36
    invoke-virtual {v3, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    const/4 v5, 0x0

    .line 41
    const/4 v6, 0x1

    .line 42
    if-nez v4, :cond_5

    .line 43
    .line 44
    iget-object v4, p0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 45
    .line 46
    invoke-virtual {v4, p1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Lv3/h0;

    .line 51
    .line 52
    if-eqz v4, :cond_3

    .line 53
    .line 54
    iget v7, p0, Lt3/m0;->r:I

    .line 55
    .line 56
    if-lez v7, :cond_2

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    const-string v7, "Check failed."

    .line 60
    .line 61
    invoke-static {v7}, Ls3/a;->b(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    :goto_1
    iget v7, p0, Lt3/m0;->r:I

    .line 65
    .line 66
    add-int/lit8 v7, v7, -0x1

    .line 67
    .line 68
    iput v7, p0, Lt3/m0;->r:I

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    invoke-virtual {p0, p1}, Lt3/m0;->j(Ljava/lang/Object;)Lv3/h0;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    if-nez v4, :cond_4

    .line 76
    .line 77
    iget v4, p0, Lt3/m0;->g:I

    .line 78
    .line 79
    new-instance v7, Lv3/h0;

    .line 80
    .line 81
    const/4 v8, 0x2

    .line 82
    invoke-direct {v7, v8}, Lv3/h0;-><init>(I)V

    .line 83
    .line 84
    .line 85
    iput-boolean v6, v0, Lv3/h0;->s:Z

    .line 86
    .line 87
    invoke-virtual {v0, v4, v7}, Lv3/h0;->B(ILv3/h0;)V

    .line 88
    .line 89
    .line 90
    iput-boolean v5, v0, Lv3/h0;->s:Z

    .line 91
    .line 92
    move-object v4, v7

    .line 93
    :cond_4
    :goto_2
    invoke-virtual {v3, p1, v4}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_5
    check-cast v4, Lv3/h0;

    .line 97
    .line 98
    invoke-virtual {v0}, Lv3/h0;->p()Ljava/util/List;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    iget v7, p0, Lt3/m0;->g:I

    .line 103
    .line 104
    invoke-static {v7, v3}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    if-eq v3, v4, :cond_7

    .line 109
    .line 110
    invoke-virtual {v0}, Lv3/h0;->p()Ljava/util/List;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    check-cast v3, Landroidx/collection/j0;

    .line 115
    .line 116
    iget-object v3, v3, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v3, Ln2/b;

    .line 119
    .line 120
    invoke-virtual {v3, v4}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    iget v7, p0, Lt3/m0;->g:I

    .line 125
    .line 126
    if-lt v3, v7, :cond_6

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_6
    new-instance v7, Ljava/lang/StringBuilder;

    .line 130
    .line 131
    const-string v8, "Key \""

    .line 132
    .line 133
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    const-string v8, "\" was already used. If you are using LazyColumn/Row please make sure you provide a unique key for each item."

    .line 140
    .line 141
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    invoke-static {v7}, Ls3/a;->a(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    :goto_3
    iget v7, p0, Lt3/m0;->g:I

    .line 152
    .line 153
    if-eq v7, v3, :cond_7

    .line 154
    .line 155
    iput-boolean v6, v0, Lv3/h0;->s:Z

    .line 156
    .line 157
    invoke-virtual {v0, v3, v7, v6}, Lv3/h0;->M(III)V

    .line 158
    .line 159
    .line 160
    iput-boolean v5, v0, Lv3/h0;->s:Z

    .line 161
    .line 162
    :cond_7
    iget v0, p0, Lt3/m0;->g:I

    .line 163
    .line 164
    add-int/2addr v0, v6

    .line 165
    iput v0, p0, Lt3/m0;->g:I

    .line 166
    .line 167
    invoke-virtual {p0, v4, p1, v5, p2}, Lt3/m0;->i(Lv3/h0;Ljava/lang/Object;ZLay0/n;)V

    .line 168
    .line 169
    .line 170
    if-eq v1, v2, :cond_9

    .line 171
    .line 172
    sget-object p0, Lv3/d0;->f:Lv3/d0;

    .line 173
    .line 174
    if-ne v1, p0, :cond_8

    .line 175
    .line 176
    goto :goto_4

    .line 177
    :cond_8
    invoke-virtual {v4}, Lv3/h0;->m()Ljava/util/List;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    return-object p0

    .line 182
    :cond_9
    :goto_4
    invoke-virtual {v4}, Lv3/h0;->n()Ljava/util/List;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    return-object p0
.end method

.method public final I()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lt3/h0;->g:Lt3/m0;

    .line 2
    .line 3
    iget-object p0, p0, Lt3/m0;->d:Lv3/h0;

    .line 4
    .line 5
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 6
    .line 7
    iget-object p0, p0, Lv3/l0;->d:Lv3/d0;

    .line 8
    .line 9
    sget-object v0, Lv3/d0;->g:Lv3/d0;

    .line 10
    .line 11
    if-eq p0, v0, :cond_1

    .line 12
    .line 13
    sget-object v0, Lv3/d0;->e:Lv3/d0;

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public final N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;
    .locals 9

    .line 1
    const/high16 v0, -0x1000000

    .line 2
    .line 3
    and-int v1, p1, v0

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    and-int/2addr v0, p2

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "Size("

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v1, " x "

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, ") is out of range. Each dimension must be between 0 and 16777215."

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :goto_0
    new-instance v1, Lt3/g0;

    .line 42
    .line 43
    iget-object v7, p0, Lt3/h0;->g:Lt3/m0;

    .line 44
    .line 45
    move-object v6, p0

    .line 46
    move v2, p1

    .line 47
    move v3, p2

    .line 48
    move-object v4, p3

    .line 49
    move-object v5, p4

    .line 50
    move-object v8, p5

    .line 51
    invoke-direct/range {v1 .. v8}, Lt3/g0;-><init>(IILjava/util/Map;Lay0/k;Lt3/h0;Lt3/m0;Lay0/k;)V

    .line 52
    .line 53
    .line 54
    return-object v1
.end method

.method public final a()F
    .locals 0

    .line 1
    iget p0, p0, Lt3/h0;->e:F

    .line 2
    .line 3
    return p0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/h0;->d:Lt4/m;

    .line 2
    .line 3
    return-object p0
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget p0, p0, Lt3/h0;->f:F

    .line 2
    .line 3
    return p0
.end method
