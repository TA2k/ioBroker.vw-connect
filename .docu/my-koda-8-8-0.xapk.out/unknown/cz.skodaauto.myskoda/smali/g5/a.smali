.class public final Lg5/a;
.super Lh5/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public E0:Lh5/e;

.field public F0:[Lh5/d;

.field public G0:Z

.field public H0:I

.field public I0:I

.field public J0:I

.field public K0:I

.field public L0:F

.field public M0:F

.field public N0:Ljava/lang/String;

.field public O0:Ljava/lang/String;

.field public P0:Ljava/lang/String;

.field public Q0:Ljava/lang/String;

.field public R0:I

.field public S0:I

.field public T0:[[Z

.field public U0:Ljava/util/HashSet;

.field public V0:[[I

.field public W0:I

.field public X0:[[I

.field public Y0:I


# direct methods
.method public static a0(Lh5/d;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh5/d;->l0:[F

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/high16 v2, -0x40800000    # -1.0f

    .line 5
    .line 6
    aput v2, v0, v1

    .line 7
    .line 8
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 9
    .line 10
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lh5/d;->M:Lh5/c;

    .line 14
    .line 15
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lh5/d;->N:Lh5/c;

    .line 19
    .line 20
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public static j0(ILjava/lang/String;)[F
    .locals 7

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_2

    .line 14
    :cond_0
    const-string v0, ","

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-array v0, p0, [F

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    :goto_0
    if-ge v1, p0, :cond_2

    .line 24
    .line 25
    array-length v2, p1

    .line 26
    const/high16 v3, 0x3f800000    # 1.0f

    .line 27
    .line 28
    if-ge v1, v2, :cond_1

    .line 29
    .line 30
    :try_start_0
    aget-object v2, p1, v1

    .line 31
    .line 32
    invoke-static {v2}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    aput v2, v0, v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :catch_0
    move-exception v2

    .line 40
    sget-object v4, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 41
    .line 42
    new-instance v5, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v6, "Error parsing `"

    .line 45
    .line 46
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    aget-object v6, p1, v1

    .line 50
    .line 51
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v6, "`: "

    .line 55
    .line 56
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {v4, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    aput v3, v0, v1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    aput v3, v0, v1

    .line 77
    .line 78
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_2
    return-object v0

    .line 82
    :cond_3
    :goto_2
    const/4 p0, 0x0

    .line 83
    return-object p0
.end method


# virtual methods
.method public final Y(IIII)V
    .locals 4

    .line 1
    iget-object p1, p0, Lh5/d;->U:Lh5/e;

    .line 2
    .line 3
    iput-object p1, p0, Lg5/a;->E0:Lh5/e;

    .line 4
    .line 5
    iget p1, p0, Lg5/a;->H0:I

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    const/4 p3, 0x1

    .line 9
    if-lt p1, p3, :cond_8

    .line 10
    .line 11
    iget p1, p0, Lg5/a;->J0:I

    .line 12
    .line 13
    if-ge p1, p3, :cond_0

    .line 14
    .line 15
    goto/16 :goto_4

    .line 16
    .line 17
    :cond_0
    iput p2, p0, Lg5/a;->S0:I

    .line 18
    .line 19
    iget-object p1, p0, Lg5/a;->Q0:Ljava/lang/String;

    .line 20
    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-nez p1, :cond_1

    .line 32
    .line 33
    iget-object p1, p0, Lg5/a;->Q0:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {p0, p1, p2}, Lg5/a;->i0(Ljava/lang/String;Z)[[I

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lg5/a;->e0([[I)V

    .line 42
    .line 43
    .line 44
    :cond_1
    iget-object p1, p0, Lg5/a;->P0:Ljava/lang/String;

    .line 45
    .line 46
    if-eqz p1, :cond_2

    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    if-nez p1, :cond_2

    .line 57
    .line 58
    iget-object p1, p0, Lg5/a;->P0:Ljava/lang/String;

    .line 59
    .line 60
    invoke-virtual {p0, p1, p3}, Lg5/a;->i0(Ljava/lang/String;Z)[[I

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iput-object p1, p0, Lg5/a;->X0:[[I

    .line 65
    .line 66
    :cond_2
    iget p1, p0, Lg5/a;->H0:I

    .line 67
    .line 68
    iget p4, p0, Lg5/a;->J0:I

    .line 69
    .line 70
    invoke-static {p1, p4}, Ljava/lang/Math;->max(II)I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    iget-object p4, p0, Lg5/a;->F0:[Lh5/d;

    .line 75
    .line 76
    const/4 v0, 0x3

    .line 77
    if-nez p4, :cond_3

    .line 78
    .line 79
    new-array p1, p1, [Lh5/d;

    .line 80
    .line 81
    iput-object p1, p0, Lg5/a;->F0:[Lh5/d;

    .line 82
    .line 83
    move p1, p2

    .line 84
    :goto_0
    iget-object p4, p0, Lg5/a;->F0:[Lh5/d;

    .line 85
    .line 86
    array-length v1, p4

    .line 87
    if-ge p1, v1, :cond_7

    .line 88
    .line 89
    new-instance v1, Lh5/d;

    .line 90
    .line 91
    invoke-direct {v1}, Lh5/d;-><init>()V

    .line 92
    .line 93
    .line 94
    iget-object v2, v1, Lh5/d;->q0:[I

    .line 95
    .line 96
    aput v0, v2, p2

    .line 97
    .line 98
    aput v0, v2, p3

    .line 99
    .line 100
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    iput-object v2, v1, Lh5/d;->k:Ljava/lang/String;

    .line 109
    .line 110
    aput-object v1, p4, p1

    .line 111
    .line 112
    add-int/lit8 p1, p1, 0x1

    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_3
    array-length p4, p4

    .line 116
    if-eq p1, p4, :cond_7

    .line 117
    .line 118
    new-array p4, p1, [Lh5/d;

    .line 119
    .line 120
    move v1, p2

    .line 121
    :goto_1
    if-ge v1, p1, :cond_5

    .line 122
    .line 123
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 124
    .line 125
    array-length v3, v2

    .line 126
    if-ge v1, v3, :cond_4

    .line 127
    .line 128
    aget-object v2, v2, v1

    .line 129
    .line 130
    aput-object v2, p4, v1

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_4
    new-instance v2, Lh5/d;

    .line 134
    .line 135
    invoke-direct {v2}, Lh5/d;-><init>()V

    .line 136
    .line 137
    .line 138
    iget-object v3, v2, Lh5/d;->q0:[I

    .line 139
    .line 140
    aput v0, v3, p2

    .line 141
    .line 142
    aput v0, v3, p3

    .line 143
    .line 144
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 145
    .line 146
    .line 147
    move-result v3

    .line 148
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    iput-object v3, v2, Lh5/d;->k:Ljava/lang/String;

    .line 153
    .line 154
    aput-object v2, p4, v1

    .line 155
    .line 156
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_5
    :goto_3
    iget-object p3, p0, Lg5/a;->F0:[Lh5/d;

    .line 160
    .line 161
    array-length v0, p3

    .line 162
    if-ge p1, v0, :cond_6

    .line 163
    .line 164
    aget-object p3, p3, p1

    .line 165
    .line 166
    iget-object v0, p0, Lg5/a;->E0:Lh5/e;

    .line 167
    .line 168
    iget-object v0, v0, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 169
    .line 170
    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    invoke-virtual {p3}, Lh5/d;->D()V

    .line 174
    .line 175
    .line 176
    add-int/lit8 p1, p1, 0x1

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_6
    iput-object p4, p0, Lg5/a;->F0:[Lh5/d;

    .line 180
    .line 181
    :cond_7
    iget-object p1, p0, Lg5/a;->X0:[[I

    .line 182
    .line 183
    if-eqz p1, :cond_8

    .line 184
    .line 185
    invoke-virtual {p0, p1}, Lg5/a;->f0([[I)V

    .line 186
    .line 187
    .line 188
    :cond_8
    :goto_4
    iget-object p1, p0, Lg5/a;->E0:Lh5/e;

    .line 189
    .line 190
    iget-object p0, p0, Lg5/a;->F0:[Lh5/d;

    .line 191
    .line 192
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 193
    .line 194
    .line 195
    array-length p3, p0

    .line 196
    :goto_5
    if-ge p2, p3, :cond_9

    .line 197
    .line 198
    aget-object p4, p0, p2

    .line 199
    .line 200
    invoke-virtual {p1, p4}, Lh5/e;->V(Lh5/d;)V

    .line 201
    .line 202
    .line 203
    add-int/lit8 p2, p2, 0x1

    .line 204
    .line 205
    goto :goto_5

    .line 206
    :cond_9
    return-void
.end method

.method public final b0(IIIILh5/d;)V
    .locals 3

    .line 1
    iget-object v0, p5, Lh5/d;->J:Lh5/c;

    .line 2
    .line 3
    iget-object v1, p0, Lg5/a;->F0:[Lh5/d;

    .line 4
    .line 5
    aget-object v1, v1, p2

    .line 6
    .line 7
    iget-object v1, v1, Lh5/d;->J:Lh5/c;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-virtual {v0, v1, v2}, Lh5/c;->a(Lh5/c;I)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p5, Lh5/d;->K:Lh5/c;

    .line 14
    .line 15
    iget-object v1, p0, Lg5/a;->F0:[Lh5/d;

    .line 16
    .line 17
    aget-object v1, v1, p1

    .line 18
    .line 19
    iget-object v1, v1, Lh5/d;->K:Lh5/c;

    .line 20
    .line 21
    invoke-virtual {v0, v1, v2}, Lh5/c;->a(Lh5/c;I)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p5, Lh5/d;->L:Lh5/c;

    .line 25
    .line 26
    iget-object v1, p0, Lg5/a;->F0:[Lh5/d;

    .line 27
    .line 28
    add-int/2addr p2, p4

    .line 29
    add-int/lit8 p2, p2, -0x1

    .line 30
    .line 31
    aget-object p2, v1, p2

    .line 32
    .line 33
    iget-object p2, p2, Lh5/d;->L:Lh5/c;

    .line 34
    .line 35
    invoke-virtual {v0, p2, v2}, Lh5/c;->a(Lh5/c;I)V

    .line 36
    .line 37
    .line 38
    iget-object p2, p5, Lh5/d;->M:Lh5/c;

    .line 39
    .line 40
    iget-object p0, p0, Lg5/a;->F0:[Lh5/d;

    .line 41
    .line 42
    add-int/2addr p1, p3

    .line 43
    add-int/lit8 p1, p1, -0x1

    .line 44
    .line 45
    aget-object p0, p0, p1

    .line 46
    .line 47
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 48
    .line 49
    invoke-virtual {p2, p0, v2}, Lh5/c;->a(Lh5/c;I)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public final c(La5/c;Z)V
    .locals 12

    .line 1
    invoke-super {p0, p1, p2}, Lh5/d;->c(La5/c;Z)V

    .line 2
    .line 3
    .line 4
    iget p1, p0, Lg5/a;->H0:I

    .line 5
    .line 6
    iget p2, p0, Lg5/a;->J0:I

    .line 7
    .line 8
    invoke-static {p1, p2}, Ljava/lang/Math;->max(II)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object p2, p0, Lg5/a;->F0:[Lh5/d;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    aget-object p2, p2, v0

    .line 16
    .line 17
    iget v1, p0, Lg5/a;->H0:I

    .line 18
    .line 19
    iget-object v2, p0, Lg5/a;->N0:Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {v1, v2}, Lg5/a;->j0(ILjava/lang/String;)[F

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget v2, p0, Lg5/a;->H0:I

    .line 26
    .line 27
    iget-object v3, p0, Lh5/d;->M:Lh5/c;

    .line 28
    .line 29
    iget-object v4, p0, Lh5/d;->K:Lh5/c;

    .line 30
    .line 31
    const/4 v5, 0x1

    .line 32
    if-ne v2, v5, :cond_0

    .line 33
    .line 34
    invoke-static {p2}, Lg5/a;->a0(Lh5/d;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p2, Lh5/d;->K:Lh5/c;

    .line 38
    .line 39
    invoke-virtual {p1, v4, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 40
    .line 41
    .line 42
    iget-object p1, p2, Lh5/d;->M:Lh5/c;

    .line 43
    .line 44
    invoke-virtual {p1, v3, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 45
    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_0
    move p2, v0

    .line 49
    :goto_0
    iget v2, p0, Lg5/a;->H0:I

    .line 50
    .line 51
    if-ge p2, v2, :cond_5

    .line 52
    .line 53
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 54
    .line 55
    aget-object v2, v2, p2

    .line 56
    .line 57
    invoke-static {v2}, Lg5/a;->a0(Lh5/d;)V

    .line 58
    .line 59
    .line 60
    iget-object v6, v2, Lh5/d;->M:Lh5/c;

    .line 61
    .line 62
    iget-object v7, v2, Lh5/d;->K:Lh5/c;

    .line 63
    .line 64
    if-eqz v1, :cond_1

    .line 65
    .line 66
    aget v8, v1, p2

    .line 67
    .line 68
    iget-object v2, v2, Lh5/d;->l0:[F

    .line 69
    .line 70
    aput v8, v2, v5

    .line 71
    .line 72
    :cond_1
    if-lez p2, :cond_2

    .line 73
    .line 74
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 75
    .line 76
    add-int/lit8 v8, p2, -0x1

    .line 77
    .line 78
    aget-object v2, v2, v8

    .line 79
    .line 80
    iget-object v2, v2, Lh5/d;->M:Lh5/c;

    .line 81
    .line 82
    invoke-virtual {v7, v2, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_2
    invoke-virtual {v7, v4, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 87
    .line 88
    .line 89
    :goto_1
    iget v2, p0, Lg5/a;->H0:I

    .line 90
    .line 91
    sub-int/2addr v2, v5

    .line 92
    if-ge p2, v2, :cond_3

    .line 93
    .line 94
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 95
    .line 96
    add-int/lit8 v8, p2, 0x1

    .line 97
    .line 98
    aget-object v2, v2, v8

    .line 99
    .line 100
    iget-object v2, v2, Lh5/d;->K:Lh5/c;

    .line 101
    .line 102
    invoke-virtual {v6, v2, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 103
    .line 104
    .line 105
    goto :goto_2

    .line 106
    :cond_3
    invoke-virtual {v6, v3, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 107
    .line 108
    .line 109
    :goto_2
    if-lez p2, :cond_4

    .line 110
    .line 111
    iget v2, p0, Lg5/a;->M0:F

    .line 112
    .line 113
    float-to-int v2, v2

    .line 114
    iput v2, v7, Lh5/c;->g:I

    .line 115
    .line 116
    :cond_4
    add-int/lit8 p2, p2, 0x1

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_5
    :goto_3
    if-ge v2, p1, :cond_6

    .line 120
    .line 121
    iget-object p2, p0, Lg5/a;->F0:[Lh5/d;

    .line 122
    .line 123
    aget-object p2, p2, v2

    .line 124
    .line 125
    invoke-static {p2}, Lg5/a;->a0(Lh5/d;)V

    .line 126
    .line 127
    .line 128
    iget-object v1, p2, Lh5/d;->K:Lh5/c;

    .line 129
    .line 130
    invoke-virtual {v1, v4, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 131
    .line 132
    .line 133
    iget-object p2, p2, Lh5/d;->M:Lh5/c;

    .line 134
    .line 135
    invoke-virtual {p2, v3, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 136
    .line 137
    .line 138
    add-int/lit8 v2, v2, 0x1

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_6
    :goto_4
    iget p1, p0, Lg5/a;->H0:I

    .line 142
    .line 143
    iget p2, p0, Lg5/a;->J0:I

    .line 144
    .line 145
    invoke-static {p1, p2}, Ljava/lang/Math;->max(II)I

    .line 146
    .line 147
    .line 148
    move-result p1

    .line 149
    iget-object p2, p0, Lg5/a;->F0:[Lh5/d;

    .line 150
    .line 151
    aget-object p2, p2, v0

    .line 152
    .line 153
    iget v1, p0, Lg5/a;->J0:I

    .line 154
    .line 155
    iget-object v2, p0, Lg5/a;->O0:Ljava/lang/String;

    .line 156
    .line 157
    invoke-static {v1, v2}, Lg5/a;->j0(ILjava/lang/String;)[F

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    iget v2, p0, Lg5/a;->J0:I

    .line 162
    .line 163
    const/high16 v3, -0x40800000    # -1.0f

    .line 164
    .line 165
    iget-object v4, p0, Lh5/d;->L:Lh5/c;

    .line 166
    .line 167
    iget-object v6, p0, Lh5/d;->J:Lh5/c;

    .line 168
    .line 169
    if-ne v2, v5, :cond_7

    .line 170
    .line 171
    iget-object p1, p2, Lh5/d;->l0:[F

    .line 172
    .line 173
    iget-object v1, p2, Lh5/d;->L:Lh5/c;

    .line 174
    .line 175
    iget-object p2, p2, Lh5/d;->J:Lh5/c;

    .line 176
    .line 177
    aput v3, p1, v0

    .line 178
    .line 179
    invoke-virtual {p2}, Lh5/c;->j()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1}, Lh5/c;->j()V

    .line 183
    .line 184
    .line 185
    invoke-virtual {p2, v6, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v1, v4, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 189
    .line 190
    .line 191
    goto :goto_9

    .line 192
    :cond_7
    move p2, v0

    .line 193
    :goto_5
    iget v2, p0, Lg5/a;->J0:I

    .line 194
    .line 195
    if-ge p2, v2, :cond_c

    .line 196
    .line 197
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 198
    .line 199
    aget-object v2, v2, p2

    .line 200
    .line 201
    iget-object v7, v2, Lh5/d;->l0:[F

    .line 202
    .line 203
    iget-object v8, v2, Lh5/d;->L:Lh5/c;

    .line 204
    .line 205
    iget-object v9, v2, Lh5/d;->J:Lh5/c;

    .line 206
    .line 207
    aput v3, v7, v0

    .line 208
    .line 209
    invoke-virtual {v9}, Lh5/c;->j()V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v8}, Lh5/c;->j()V

    .line 213
    .line 214
    .line 215
    if-eqz v1, :cond_8

    .line 216
    .line 217
    aget v7, v1, p2

    .line 218
    .line 219
    iget-object v2, v2, Lh5/d;->l0:[F

    .line 220
    .line 221
    aput v7, v2, v0

    .line 222
    .line 223
    :cond_8
    if-lez p2, :cond_9

    .line 224
    .line 225
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 226
    .line 227
    add-int/lit8 v7, p2, -0x1

    .line 228
    .line 229
    aget-object v2, v2, v7

    .line 230
    .line 231
    iget-object v2, v2, Lh5/d;->L:Lh5/c;

    .line 232
    .line 233
    invoke-virtual {v9, v2, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 234
    .line 235
    .line 236
    goto :goto_6

    .line 237
    :cond_9
    invoke-virtual {v9, v6, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 238
    .line 239
    .line 240
    :goto_6
    iget v2, p0, Lg5/a;->J0:I

    .line 241
    .line 242
    sub-int/2addr v2, v5

    .line 243
    if-ge p2, v2, :cond_a

    .line 244
    .line 245
    iget-object v2, p0, Lg5/a;->F0:[Lh5/d;

    .line 246
    .line 247
    add-int/lit8 v7, p2, 0x1

    .line 248
    .line 249
    aget-object v2, v2, v7

    .line 250
    .line 251
    iget-object v2, v2, Lh5/d;->J:Lh5/c;

    .line 252
    .line 253
    invoke-virtual {v8, v2, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 254
    .line 255
    .line 256
    goto :goto_7

    .line 257
    :cond_a
    invoke-virtual {v8, v4, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 258
    .line 259
    .line 260
    :goto_7
    if-lez p2, :cond_b

    .line 261
    .line 262
    iget v2, p0, Lg5/a;->L0:F

    .line 263
    .line 264
    float-to-int v2, v2

    .line 265
    iput v2, v9, Lh5/c;->g:I

    .line 266
    .line 267
    :cond_b
    add-int/lit8 p2, p2, 0x1

    .line 268
    .line 269
    goto :goto_5

    .line 270
    :cond_c
    :goto_8
    if-ge v2, p1, :cond_d

    .line 271
    .line 272
    iget-object p2, p0, Lg5/a;->F0:[Lh5/d;

    .line 273
    .line 274
    aget-object p2, p2, v2

    .line 275
    .line 276
    iget-object v1, p2, Lh5/d;->l0:[F

    .line 277
    .line 278
    iget-object v7, p2, Lh5/d;->L:Lh5/c;

    .line 279
    .line 280
    iget-object p2, p2, Lh5/d;->J:Lh5/c;

    .line 281
    .line 282
    aput v3, v1, v0

    .line 283
    .line 284
    invoke-virtual {p2}, Lh5/c;->j()V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v7}, Lh5/c;->j()V

    .line 288
    .line 289
    .line 290
    invoke-virtual {p2, v6, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v7, v4, v0}, Lh5/c;->a(Lh5/c;I)V

    .line 294
    .line 295
    .line 296
    add-int/lit8 v2, v2, 0x1

    .line 297
    .line 298
    goto :goto_8

    .line 299
    :cond_d
    :goto_9
    move p1, v0

    .line 300
    :goto_a
    iget p2, p0, Lh5/i;->s0:I

    .line 301
    .line 302
    if-ge p1, p2, :cond_15

    .line 303
    .line 304
    iget-object p2, p0, Lg5/a;->U0:Ljava/util/HashSet;

    .line 305
    .line 306
    iget-object v1, p0, Lh5/i;->r0:[Lh5/d;

    .line 307
    .line 308
    aget-object v1, v1, p1

    .line 309
    .line 310
    iget-object v1, v1, Lh5/d;->k:Ljava/lang/String;

    .line 311
    .line 312
    invoke-virtual {p2, v1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    move-result p2

    .line 316
    if-eqz p2, :cond_e

    .line 317
    .line 318
    :goto_b
    move-object v6, p0

    .line 319
    goto/16 :goto_e

    .line 320
    .line 321
    :cond_e
    move p2, v0

    .line 322
    move v1, p2

    .line 323
    :goto_c
    const/4 v2, -0x1

    .line 324
    if-nez p2, :cond_11

    .line 325
    .line 326
    iget v1, p0, Lg5/a;->S0:I

    .line 327
    .line 328
    iget v3, p0, Lg5/a;->H0:I

    .line 329
    .line 330
    iget v4, p0, Lg5/a;->J0:I

    .line 331
    .line 332
    mul-int/2addr v3, v4

    .line 333
    if-lt v1, v3, :cond_f

    .line 334
    .line 335
    move v1, v2

    .line 336
    goto :goto_d

    .line 337
    :cond_f
    invoke-virtual {p0, v1}, Lg5/a;->d0(I)I

    .line 338
    .line 339
    .line 340
    move-result v2

    .line 341
    iget v3, p0, Lg5/a;->S0:I

    .line 342
    .line 343
    invoke-virtual {p0, v3}, Lg5/a;->c0(I)I

    .line 344
    .line 345
    .line 346
    move-result v3

    .line 347
    iget-object v4, p0, Lg5/a;->T0:[[Z

    .line 348
    .line 349
    aget-object v2, v4, v2

    .line 350
    .line 351
    aget-boolean v4, v2, v3

    .line 352
    .line 353
    if-eqz v4, :cond_10

    .line 354
    .line 355
    aput-boolean v0, v2, v3

    .line 356
    .line 357
    move p2, v5

    .line 358
    :cond_10
    iget v2, p0, Lg5/a;->S0:I

    .line 359
    .line 360
    add-int/2addr v2, v5

    .line 361
    iput v2, p0, Lg5/a;->S0:I

    .line 362
    .line 363
    goto :goto_c

    .line 364
    :cond_11
    :goto_d
    invoke-virtual {p0, v1}, Lg5/a;->d0(I)I

    .line 365
    .line 366
    .line 367
    move-result v7

    .line 368
    invoke-virtual {p0, v1}, Lg5/a;->c0(I)I

    .line 369
    .line 370
    .line 371
    move-result v8

    .line 372
    if-ne v1, v2, :cond_12

    .line 373
    .line 374
    goto :goto_f

    .line 375
    :cond_12
    iget p2, p0, Lg5/a;->W0:I

    .line 376
    .line 377
    const/4 v2, 0x2

    .line 378
    and-int/2addr p2, v2

    .line 379
    if-lez p2, :cond_14

    .line 380
    .line 381
    iget-object p2, p0, Lg5/a;->X0:[[I

    .line 382
    .line 383
    if-eqz p2, :cond_14

    .line 384
    .line 385
    iget v3, p0, Lg5/a;->Y0:I

    .line 386
    .line 387
    array-length v4, p2

    .line 388
    if-ge v3, v4, :cond_14

    .line 389
    .line 390
    aget-object p2, p2, v3

    .line 391
    .line 392
    aget v3, p2, v0

    .line 393
    .line 394
    if-ne v3, v1, :cond_14

    .line 395
    .line 396
    iget-object v1, p0, Lg5/a;->T0:[[Z

    .line 397
    .line 398
    aget-object v1, v1, v7

    .line 399
    .line 400
    aput-boolean v5, v1, v8

    .line 401
    .line 402
    aget v1, p2, v5

    .line 403
    .line 404
    aget p2, p2, v2

    .line 405
    .line 406
    invoke-virtual {p0, v7, v8, v1, p2}, Lg5/a;->h0(IIII)Z

    .line 407
    .line 408
    .line 409
    move-result p2

    .line 410
    if-nez p2, :cond_13

    .line 411
    .line 412
    goto :goto_b

    .line 413
    :cond_13
    iget-object p2, p0, Lh5/i;->r0:[Lh5/d;

    .line 414
    .line 415
    aget-object v11, p2, p1

    .line 416
    .line 417
    iget-object p2, p0, Lg5/a;->X0:[[I

    .line 418
    .line 419
    iget v1, p0, Lg5/a;->Y0:I

    .line 420
    .line 421
    aget-object p2, p2, v1

    .line 422
    .line 423
    aget v9, p2, v5

    .line 424
    .line 425
    aget v10, p2, v2

    .line 426
    .line 427
    move-object v6, p0

    .line 428
    invoke-virtual/range {v6 .. v11}, Lg5/a;->b0(IIIILh5/d;)V

    .line 429
    .line 430
    .line 431
    iget p0, v6, Lg5/a;->Y0:I

    .line 432
    .line 433
    add-int/2addr p0, v5

    .line 434
    iput p0, v6, Lg5/a;->Y0:I

    .line 435
    .line 436
    goto :goto_e

    .line 437
    :cond_14
    move-object v6, p0

    .line 438
    iget-object p0, v6, Lh5/i;->r0:[Lh5/d;

    .line 439
    .line 440
    aget-object v11, p0, p1

    .line 441
    .line 442
    const/4 v9, 0x1

    .line 443
    const/4 v10, 0x1

    .line 444
    invoke-virtual/range {v6 .. v11}, Lg5/a;->b0(IIIILh5/d;)V

    .line 445
    .line 446
    .line 447
    :goto_e
    add-int/lit8 p1, p1, 0x1

    .line 448
    .line 449
    move-object p0, v6

    .line 450
    goto/16 :goto_a

    .line 451
    .line 452
    :cond_15
    :goto_f
    return-void
.end method

.method public final c0(I)I
    .locals 2

    .line 1
    iget v0, p0, Lg5/a;->R0:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    iget p0, p0, Lg5/a;->H0:I

    .line 7
    .line 8
    div-int/2addr p1, p0

    .line 9
    return p1

    .line 10
    :cond_0
    iget p0, p0, Lg5/a;->J0:I

    .line 11
    .line 12
    rem-int/2addr p1, p0

    .line 13
    return p1
.end method

.method public final d0(I)I
    .locals 2

    .line 1
    iget v0, p0, Lg5/a;->R0:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    iget p0, p0, Lg5/a;->H0:I

    .line 7
    .line 8
    rem-int/2addr p1, p0

    .line 9
    return p1

    .line 10
    :cond_0
    iget p0, p0, Lg5/a;->J0:I

    .line 11
    .line 12
    div-int/2addr p1, p0

    .line 13
    return p1
.end method

.method public final e0([[I)V
    .locals 8

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    :goto_0
    if-ge v2, v0, :cond_1

    .line 5
    .line 6
    aget-object v3, p1, v2

    .line 7
    .line 8
    aget v4, v3, v1

    .line 9
    .line 10
    invoke-virtual {p0, v4}, Lg5/a;->d0(I)I

    .line 11
    .line 12
    .line 13
    move-result v4

    .line 14
    aget v5, v3, v1

    .line 15
    .line 16
    invoke-virtual {p0, v5}, Lg5/a;->c0(I)I

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    const/4 v6, 0x1

    .line 21
    aget v6, v3, v6

    .line 22
    .line 23
    const/4 v7, 0x2

    .line 24
    aget v3, v3, v7

    .line 25
    .line 26
    invoke-virtual {p0, v4, v5, v6, v3}, Lg5/a;->h0(IIII)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    :goto_1
    return-void
.end method

.method public final f0([[I)V
    .locals 10

    .line 1
    iget v0, p0, Lg5/a;->W0:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    and-int/2addr v0, v1

    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    move v2, v0

    .line 10
    :goto_0
    array-length v3, p1

    .line 11
    if-ge v2, v3, :cond_2

    .line 12
    .line 13
    aget-object v3, p1, v2

    .line 14
    .line 15
    aget v3, v3, v0

    .line 16
    .line 17
    invoke-virtual {p0, v3}, Lg5/a;->d0(I)I

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    aget-object v3, p1, v2

    .line 22
    .line 23
    aget v3, v3, v0

    .line 24
    .line 25
    invoke-virtual {p0, v3}, Lg5/a;->c0(I)I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    aget-object v3, p1, v2

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    aget v7, v3, v4

    .line 33
    .line 34
    aget v3, v3, v1

    .line 35
    .line 36
    invoke-virtual {p0, v5, v6, v7, v3}, Lg5/a;->h0(IIII)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-nez v3, :cond_1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    iget-object v3, p0, Lh5/i;->r0:[Lh5/d;

    .line 44
    .line 45
    aget-object v9, v3, v2

    .line 46
    .line 47
    aget-object v3, p1, v2

    .line 48
    .line 49
    aget v7, v3, v4

    .line 50
    .line 51
    aget v8, v3, v1

    .line 52
    .line 53
    move-object v4, p0

    .line 54
    invoke-virtual/range {v4 .. v9}, Lg5/a;->b0(IIIILh5/d;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, v4, Lg5/a;->U0:Ljava/util/HashSet;

    .line 58
    .line 59
    iget-object v3, v4, Lh5/i;->r0:[Lh5/d;

    .line 60
    .line 61
    aget-object v3, v3, v2

    .line 62
    .line 63
    iget-object v3, v3, Lh5/d;->k:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {p0, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    add-int/lit8 v2, v2, 0x1

    .line 69
    .line 70
    move-object p0, v4

    .line 71
    goto :goto_0

    .line 72
    :cond_2
    :goto_1
    return-void
.end method

.method public final g0()V
    .locals 7

    .line 1
    iget v0, p0, Lg5/a;->H0:I

    .line 2
    .line 3
    iget v1, p0, Lg5/a;->J0:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    new-array v3, v2, [I

    .line 7
    .line 8
    const/4 v4, 0x1

    .line 9
    aput v1, v3, v4

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    aput v0, v3, v1

    .line 13
    .line 14
    sget-object v0, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 15
    .line 16
    invoke-static {v0, v3}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, [[Z

    .line 21
    .line 22
    iput-object v0, p0, Lg5/a;->T0:[[Z

    .line 23
    .line 24
    array-length v3, v0

    .line 25
    move v5, v1

    .line 26
    :goto_0
    if-ge v5, v3, :cond_0

    .line 27
    .line 28
    aget-object v6, v0, v5

    .line 29
    .line 30
    invoke-static {v6, v4}, Ljava/util/Arrays;->fill([ZZ)V

    .line 31
    .line 32
    .line 33
    add-int/lit8 v5, v5, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget v0, p0, Lh5/i;->s0:I

    .line 37
    .line 38
    if-lez v0, :cond_1

    .line 39
    .line 40
    new-array v2, v2, [I

    .line 41
    .line 42
    const/4 v3, 0x4

    .line 43
    aput v3, v2, v4

    .line 44
    .line 45
    aput v0, v2, v1

    .line 46
    .line 47
    sget-object v0, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 48
    .line 49
    invoke-static {v0, v2}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, [[I

    .line 54
    .line 55
    iput-object v0, p0, Lg5/a;->V0:[[I

    .line 56
    .line 57
    array-length p0, v0

    .line 58
    :goto_1
    if-ge v1, p0, :cond_1

    .line 59
    .line 60
    aget-object v2, v0, v1

    .line 61
    .line 62
    const/4 v3, -0x1

    .line 63
    invoke-static {v2, v3}, Ljava/util/Arrays;->fill([II)V

    .line 64
    .line 65
    .line 66
    add-int/lit8 v1, v1, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_1
    return-void
.end method

.method public final h0(IIII)Z
    .locals 5

    .line 1
    move v0, p1

    .line 2
    :goto_0
    add-int v1, p1, p3

    .line 3
    .line 4
    if-ge v0, v1, :cond_3

    .line 5
    .line 6
    move v1, p2

    .line 7
    :goto_1
    add-int v2, p2, p4

    .line 8
    .line 9
    if-ge v1, v2, :cond_2

    .line 10
    .line 11
    iget-object v2, p0, Lg5/a;->T0:[[Z

    .line 12
    .line 13
    array-length v3, v2

    .line 14
    const/4 v4, 0x0

    .line 15
    if-ge v0, v3, :cond_1

    .line 16
    .line 17
    aget-object v3, v2, v4

    .line 18
    .line 19
    array-length v3, v3

    .line 20
    if-ge v1, v3, :cond_1

    .line 21
    .line 22
    aget-object v2, v2, v0

    .line 23
    .line 24
    aget-boolean v3, v2, v1

    .line 25
    .line 26
    if-nez v3, :cond_0

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_0
    aput-boolean v4, v2, v1

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    :goto_2
    return v4

    .line 35
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_3
    const/4 p0, 0x1

    .line 39
    return p0
.end method

.method public final i0(Ljava/lang/String;Z)[[I
    .locals 11

    .line 1
    :try_start_0
    const-string v0, ","

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1, v0}, Ljava/util/Arrays;->sort([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 14
    .line 15
    .line 16
    array-length v0, p1

    .line 17
    const/4 v1, 0x2

    .line 18
    new-array v2, v1, [I

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    const/4 v4, 0x3

    .line 22
    aput v4, v2, v3

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    aput v0, v2, v4

    .line 26
    .line 27
    sget-object v0, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 28
    .line 29
    invoke-static {v0, v2}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, [[I

    .line 34
    .line 35
    iget v2, p0, Lg5/a;->H0:I
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 36
    .line 37
    const-string v5, ":"

    .line 38
    .line 39
    if-eq v2, v3, :cond_3

    .line 40
    .line 41
    :try_start_1
    iget v2, p0, Lg5/a;->J0:I

    .line 42
    .line 43
    if-ne v2, v3, :cond_0

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_0
    move p2, v4

    .line 47
    :goto_0
    array-length v2, p1

    .line 48
    if-ge p2, v2, :cond_2

    .line 49
    .line 50
    aget-object v2, p1, p2

    .line 51
    .line 52
    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-virtual {v2, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    aget-object v6, v2, v3

    .line 61
    .line 62
    const-string v7, "x"

    .line 63
    .line 64
    invoke-virtual {v6, v7}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    aget-object v7, v0, p2

    .line 69
    .line 70
    aget-object v2, v2, v4

    .line 71
    .line 72
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    aput v2, v7, v4

    .line 77
    .line 78
    iget v2, p0, Lg5/a;->W0:I

    .line 79
    .line 80
    and-int/2addr v2, v3

    .line 81
    if-lez v2, :cond_1

    .line 82
    .line 83
    aget-object v2, v0, p2

    .line 84
    .line 85
    aget-object v7, v6, v3

    .line 86
    .line 87
    invoke-static {v7}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result v7

    .line 91
    aput v7, v2, v3

    .line 92
    .line 93
    aget-object v2, v0, p2

    .line 94
    .line 95
    aget-object v6, v6, v4

    .line 96
    .line 97
    invoke-static {v6}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 98
    .line 99
    .line 100
    move-result v6

    .line 101
    aput v6, v2, v1

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_1
    aget-object v2, v0, p2

    .line 105
    .line 106
    aget-object v7, v6, v4

    .line 107
    .line 108
    invoke-static {v7}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    move-result v7

    .line 112
    aput v7, v2, v3

    .line 113
    .line 114
    aget-object v2, v0, p2

    .line 115
    .line 116
    aget-object v6, v6, v3

    .line 117
    .line 118
    invoke-static {v6}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    move-result v6

    .line 122
    aput v6, v2, v1

    .line 123
    .line 124
    :goto_1
    add-int/lit8 p2, p2, 0x1

    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_2
    return-object v0

    .line 128
    :cond_3
    :goto_2
    move v2, v4

    .line 129
    move v6, v2

    .line 130
    move v7, v6

    .line 131
    :goto_3
    array-length v8, p1

    .line 132
    if-ge v2, v8, :cond_6

    .line 133
    .line 134
    aget-object v8, p1, v2

    .line 135
    .line 136
    invoke-virtual {v8}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v8

    .line 140
    invoke-virtual {v8, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v8

    .line 144
    aget-object v9, v0, v2

    .line 145
    .line 146
    aget-object v10, v8, v4

    .line 147
    .line 148
    invoke-static {v10}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 149
    .line 150
    .line 151
    move-result v10

    .line 152
    aput v10, v9, v4

    .line 153
    .line 154
    aget-object v9, v0, v2

    .line 155
    .line 156
    aput v3, v9, v3

    .line 157
    .line 158
    aput v3, v9, v1

    .line 159
    .line 160
    iget v10, p0, Lg5/a;->J0:I

    .line 161
    .line 162
    if-ne v10, v3, :cond_4

    .line 163
    .line 164
    aget-object v10, v8, v3

    .line 165
    .line 166
    invoke-static {v10}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 167
    .line 168
    .line 169
    move-result v10

    .line 170
    aput v10, v9, v3

    .line 171
    .line 172
    aget-object v9, v0, v2

    .line 173
    .line 174
    aget v9, v9, v3

    .line 175
    .line 176
    add-int/2addr v6, v9

    .line 177
    if-eqz p2, :cond_4

    .line 178
    .line 179
    add-int/lit8 v6, v6, -0x1

    .line 180
    .line 181
    :cond_4
    iget v9, p0, Lg5/a;->H0:I

    .line 182
    .line 183
    if-ne v9, v3, :cond_5

    .line 184
    .line 185
    aget-object v9, v0, v2

    .line 186
    .line 187
    aget-object v8, v8, v3

    .line 188
    .line 189
    invoke-static {v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 190
    .line 191
    .line 192
    move-result v8

    .line 193
    aput v8, v9, v1

    .line 194
    .line 195
    aget-object v8, v0, v2

    .line 196
    .line 197
    aget v8, v8, v1

    .line 198
    .line 199
    add-int/2addr v7, v8

    .line 200
    if-eqz p2, :cond_5

    .line 201
    .line 202
    add-int/lit8 v7, v7, -0x1

    .line 203
    .line 204
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 205
    .line 206
    goto :goto_3

    .line 207
    :cond_6
    const/16 p1, 0x32

    .line 208
    .line 209
    if-eqz v6, :cond_9

    .line 210
    .line 211
    iget-boolean p2, p0, Lg5/a;->G0:Z

    .line 212
    .line 213
    if-nez p2, :cond_9

    .line 214
    .line 215
    iget p2, p0, Lg5/a;->H0:I

    .line 216
    .line 217
    add-int/2addr p2, v6

    .line 218
    if-le p2, p1, :cond_7

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_7
    iget v1, p0, Lg5/a;->I0:I

    .line 222
    .line 223
    if-ne v1, p2, :cond_8

    .line 224
    .line 225
    goto :goto_4

    .line 226
    :cond_8
    iput p2, p0, Lg5/a;->I0:I

    .line 227
    .line 228
    invoke-virtual {p0}, Lg5/a;->k0()V

    .line 229
    .line 230
    .line 231
    invoke-virtual {p0}, Lg5/a;->g0()V

    .line 232
    .line 233
    .line 234
    :cond_9
    :goto_4
    if-eqz v7, :cond_c

    .line 235
    .line 236
    iget-boolean p2, p0, Lg5/a;->G0:Z

    .line 237
    .line 238
    if-nez p2, :cond_c

    .line 239
    .line 240
    iget p2, p0, Lg5/a;->J0:I

    .line 241
    .line 242
    add-int/2addr p2, v7

    .line 243
    if-le p2, p1, :cond_a

    .line 244
    .line 245
    goto :goto_5

    .line 246
    :cond_a
    iget p1, p0, Lg5/a;->K0:I

    .line 247
    .line 248
    if-ne p1, p2, :cond_b

    .line 249
    .line 250
    goto :goto_5

    .line 251
    :cond_b
    iput p2, p0, Lg5/a;->K0:I

    .line 252
    .line 253
    invoke-virtual {p0}, Lg5/a;->k0()V

    .line 254
    .line 255
    .line 256
    invoke-virtual {p0}, Lg5/a;->g0()V

    .line 257
    .line 258
    .line 259
    :cond_c
    :goto_5
    iput-boolean v3, p0, Lg5/a;->G0:Z
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 260
    .line 261
    return-object v0

    .line 262
    :catch_0
    const/4 p0, 0x0

    .line 263
    return-object p0
.end method

.method public final k0()V
    .locals 4

    .line 1
    iget v0, p0, Lg5/a;->I0:I

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget v1, p0, Lg5/a;->K0:I

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iput v0, p0, Lg5/a;->H0:I

    .line 11
    .line 12
    iput v1, p0, Lg5/a;->J0:I

    .line 13
    .line 14
    return-void

    .line 15
    :cond_1
    :goto_0
    iget v1, p0, Lg5/a;->K0:I

    .line 16
    .line 17
    if-lez v1, :cond_2

    .line 18
    .line 19
    iput v1, p0, Lg5/a;->J0:I

    .line 20
    .line 21
    iget v0, p0, Lh5/i;->s0:I

    .line 22
    .line 23
    add-int/2addr v0, v1

    .line 24
    add-int/lit8 v0, v0, -0x1

    .line 25
    .line 26
    div-int/2addr v0, v1

    .line 27
    iput v0, p0, Lg5/a;->H0:I

    .line 28
    .line 29
    return-void

    .line 30
    :cond_2
    if-lez v0, :cond_3

    .line 31
    .line 32
    iput v0, p0, Lg5/a;->H0:I

    .line 33
    .line 34
    iget v1, p0, Lh5/i;->s0:I

    .line 35
    .line 36
    add-int/2addr v1, v0

    .line 37
    add-int/lit8 v1, v1, -0x1

    .line 38
    .line 39
    div-int/2addr v1, v0

    .line 40
    iput v1, p0, Lg5/a;->J0:I

    .line 41
    .line 42
    return-void

    .line 43
    :cond_3
    iget v0, p0, Lh5/i;->s0:I

    .line 44
    .line 45
    int-to-double v0, v0

    .line 46
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    const-wide/high16 v2, 0x3ff8000000000000L    # 1.5

    .line 51
    .line 52
    add-double/2addr v0, v2

    .line 53
    double-to-int v0, v0

    .line 54
    iput v0, p0, Lg5/a;->H0:I

    .line 55
    .line 56
    iget v1, p0, Lh5/i;->s0:I

    .line 57
    .line 58
    add-int/2addr v1, v0

    .line 59
    add-int/lit8 v1, v1, -0x1

    .line 60
    .line 61
    div-int/2addr v1, v0

    .line 62
    iput v1, p0, Lg5/a;->J0:I

    .line 63
    .line 64
    return-void
.end method
