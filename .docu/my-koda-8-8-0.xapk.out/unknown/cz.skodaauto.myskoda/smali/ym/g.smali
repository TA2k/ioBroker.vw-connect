.class public final Lym/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/t2;


# instance fields
.field public final d:Ll2/j1;

.field public final e:Ll2/j1;

.field public final f:Ll2/j1;

.field public final g:Ll2/j1;

.field public final h:Ll2/j1;

.field public final i:Ll2/j1;

.field public final j:Ll2/j1;

.field public final k:Ll2/h0;

.field public final l:Ll2/j1;

.field public final m:Ll2/j1;

.field public final n:Ll2/j1;

.field public final o:Ll2/j1;

.field public final p:Ll2/h0;

.field public final q:Le1/b1;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 5
    .line 6
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iput-object v1, p0, Lym/g;->d:Ll2/j1;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    iput-object v2, p0, Lym/g;->e:Ll2/j1;

    .line 22
    .line 23
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    iput-object v1, p0, Lym/g;->f:Ll2/j1;

    .line 28
    .line 29
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    iput-object v1, p0, Lym/g;->g:Ll2/j1;

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    iput-object v2, p0, Lym/g;->h:Ll2/j1;

    .line 41
    .line 42
    const/high16 v2, 0x3f800000    # 1.0f

    .line 43
    .line 44
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    iput-object v2, p0, Lym/g;->i:Ll2/j1;

    .line 53
    .line 54
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iput-object v0, p0, Lym/g;->j:Ll2/j1;

    .line 59
    .line 60
    new-instance v0, Lym/e;

    .line 61
    .line 62
    const/4 v2, 0x1

    .line 63
    invoke-direct {v0, p0, v2}, Lym/e;-><init>(Lym/g;I)V

    .line 64
    .line 65
    .line 66
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iput-object v0, p0, Lym/g;->k:Ll2/h0;

    .line 71
    .line 72
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    iput-object v0, p0, Lym/g;->l:Ll2/j1;

    .line 77
    .line 78
    const/4 v0, 0x0

    .line 79
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    iput-object v1, p0, Lym/g;->m:Ll2/j1;

    .line 88
    .line 89
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    iput-object v0, p0, Lym/g;->n:Ll2/j1;

    .line 94
    .line 95
    const-wide/high16 v0, -0x8000000000000000L

    .line 96
    .line 97
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    iput-object v0, p0, Lym/g;->o:Ll2/j1;

    .line 106
    .line 107
    new-instance v0, Lym/e;

    .line 108
    .line 109
    const/4 v1, 0x0

    .line 110
    invoke-direct {v0, p0, v1}, Lym/e;-><init>(Lym/g;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    iput-object v0, p0, Lym/g;->p:Ll2/h0;

    .line 118
    .line 119
    new-instance v0, Lym/e;

    .line 120
    .line 121
    const/4 v1, 0x2

    .line 122
    invoke-direct {v0, p0, v1}, Lym/e;-><init>(Lym/g;I)V

    .line 123
    .line 124
    .line 125
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 126
    .line 127
    .line 128
    new-instance v0, Le1/b1;

    .line 129
    .line 130
    invoke-direct {v0}, Le1/b1;-><init>()V

    .line 131
    .line 132
    .line 133
    iput-object v0, p0, Lym/g;->q:Le1/b1;

    .line 134
    .line 135
    return-void
.end method

.method public static final a(Lym/g;IJ)Z
    .locals 10

    .line 1
    iget-object v0, p0, Lym/g;->l:Ll2/j1;

    .line 2
    .line 3
    iget-object v1, p0, Lym/g;->h:Ll2/j1;

    .line 4
    .line 5
    iget-object v2, p0, Lym/g;->m:Ll2/j1;

    .line 6
    .line 7
    iget-object v3, p0, Lym/g;->k:Ll2/h0;

    .line 8
    .line 9
    iget-object v4, p0, Lym/g;->o:Ll2/j1;

    .line 10
    .line 11
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lum/a;

    .line 16
    .line 17
    const/4 v5, 0x1

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    return v5

    .line 21
    :cond_0
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    check-cast v6, Ljava/lang/Number;

    .line 26
    .line 27
    invoke-virtual {v6}, Ljava/lang/Number;->longValue()J

    .line 28
    .line 29
    .line 30
    move-result-wide v6

    .line 31
    const-wide/high16 v8, -0x8000000000000000L

    .line 32
    .line 33
    cmp-long v6, v6, v8

    .line 34
    .line 35
    if-nez v6, :cond_1

    .line 36
    .line 37
    const-wide/16 v6, 0x0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    check-cast v6, Ljava/lang/Number;

    .line 45
    .line 46
    invoke-virtual {v6}, Ljava/lang/Number;->longValue()J

    .line 47
    .line 48
    .line 49
    move-result-wide v6

    .line 50
    sub-long v6, p2, v6

    .line 51
    .line 52
    :goto_0
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-virtual {v4, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-nez p2, :cond_7

    .line 64
    .line 65
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-nez p2, :cond_6

    .line 70
    .line 71
    const p2, 0xf4240

    .line 72
    .line 73
    .line 74
    int-to-long p2, p2

    .line 75
    div-long/2addr v6, p2

    .line 76
    long-to-float p2, v6

    .line 77
    invoke-virtual {v0}, Lum/a;->b()F

    .line 78
    .line 79
    .line 80
    move-result p3

    .line 81
    div-float/2addr p2, p3

    .line 82
    invoke-virtual {v3}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p3

    .line 86
    check-cast p3, Ljava/lang/Number;

    .line 87
    .line 88
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 89
    .line 90
    .line 91
    move-result p3

    .line 92
    mul-float/2addr p3, p2

    .line 93
    invoke-virtual {v3}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    check-cast p2, Ljava/lang/Number;

    .line 98
    .line 99
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 100
    .line 101
    .line 102
    move-result p2

    .line 103
    const/4 v0, 0x0

    .line 104
    cmpg-float p2, p2, v0

    .line 105
    .line 106
    const/high16 v1, 0x3f800000    # 1.0f

    .line 107
    .line 108
    if-gez p2, :cond_2

    .line 109
    .line 110
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    check-cast p2, Ljava/lang/Number;

    .line 115
    .line 116
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    add-float/2addr p2, p3

    .line 121
    sub-float p2, v0, p2

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_2
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    check-cast p2, Ljava/lang/Number;

    .line 129
    .line 130
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 131
    .line 132
    .line 133
    move-result p2

    .line 134
    add-float/2addr p2, p3

    .line 135
    sub-float/2addr p2, v1

    .line 136
    :goto_1
    cmpg-float v4, p2, v0

    .line 137
    .line 138
    if-gez v4, :cond_3

    .line 139
    .line 140
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    check-cast p1, Ljava/lang/Number;

    .line 145
    .line 146
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 147
    .line 148
    .line 149
    move-result p1

    .line 150
    invoke-static {p1, v0, v1}, Lkp/r9;->d(FFF)F

    .line 151
    .line 152
    .line 153
    move-result p1

    .line 154
    add-float/2addr p1, p3

    .line 155
    invoke-virtual {p0, p1}, Lym/g;->f(F)V

    .line 156
    .line 157
    .line 158
    return v5

    .line 159
    :cond_3
    div-float p3, p2, v1

    .line 160
    .line 161
    float-to-int p3, p3

    .line 162
    add-int/lit8 v2, p3, 0x1

    .line 163
    .line 164
    invoke-virtual {p0}, Lym/g;->d()I

    .line 165
    .line 166
    .line 167
    move-result v4

    .line 168
    add-int/2addr v4, v2

    .line 169
    if-le v4, p1, :cond_4

    .line 170
    .line 171
    invoke-virtual {p0}, Lym/g;->c()F

    .line 172
    .line 173
    .line 174
    move-result p2

    .line 175
    invoke-virtual {p0, p2}, Lym/g;->f(F)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p0, p1}, Lym/g;->e(I)V

    .line 179
    .line 180
    .line 181
    const/4 p0, 0x0

    .line 182
    return p0

    .line 183
    :cond_4
    invoke-virtual {p0}, Lym/g;->d()I

    .line 184
    .line 185
    .line 186
    move-result p1

    .line 187
    add-int/2addr p1, v2

    .line 188
    invoke-virtual {p0, p1}, Lym/g;->e(I)V

    .line 189
    .line 190
    .line 191
    int-to-float p1, p3

    .line 192
    mul-float/2addr p1, v1

    .line 193
    sub-float/2addr p2, p1

    .line 194
    invoke-virtual {v3}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    check-cast p1, Ljava/lang/Number;

    .line 199
    .line 200
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 201
    .line 202
    .line 203
    move-result p1

    .line 204
    cmpg-float p1, p1, v0

    .line 205
    .line 206
    if-gez p1, :cond_5

    .line 207
    .line 208
    sub-float/2addr v1, p2

    .line 209
    goto :goto_2

    .line 210
    :cond_5
    add-float v1, v0, p2

    .line 211
    .line 212
    :goto_2
    invoke-virtual {p0, v1}, Lym/g;->f(F)V

    .line 213
    .line 214
    .line 215
    return v5

    .line 216
    :cond_6
    new-instance p0, Ljava/lang/ClassCastException;

    .line 217
    .line 218
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 219
    .line 220
    .line 221
    throw p0

    .line 222
    :cond_7
    new-instance p0, Ljava/lang/ClassCastException;

    .line 223
    .line 224
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 225
    .line 226
    .line 227
    throw p0
.end method

.method public static final b(Lym/g;Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lym/g;->d:Ll2/j1;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final c()F
    .locals 0

    .line 1
    iget-object p0, p0, Lym/g;->p:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget-object p0, p0, Lym/g;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lym/g;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final f(F)V
    .locals 2

    .line 1
    iget-object v0, p0, Lym/g;->m:Ll2/j1;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lym/g;->j:Ll2/j1;

    .line 11
    .line 12
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    iget-object v0, p0, Lym/g;->l:Ll2/j1;

    .line 25
    .line 26
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lum/a;

    .line 31
    .line 32
    if-nez v0, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    iget v0, v0, Lum/a;->n:F

    .line 36
    .line 37
    const/4 v1, 0x1

    .line 38
    int-to-float v1, v1

    .line 39
    div-float/2addr v1, v0

    .line 40
    rem-float v0, p1, v1

    .line 41
    .line 42
    sub-float/2addr p1, v0

    .line 43
    :cond_1
    :goto_0
    iget-object p0, p0, Lym/g;->n:Ll2/j1;

    .line 44
    .line 45
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lym/g;->n:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
