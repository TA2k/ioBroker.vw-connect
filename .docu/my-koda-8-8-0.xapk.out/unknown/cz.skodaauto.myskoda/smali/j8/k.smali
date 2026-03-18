.class public final Lj8/k;
.super Lj8/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final h:I

.field public final i:Z

.field public final j:Z

.field public final k:Z

.field public final l:I

.field public final m:I

.field public final n:I

.field public final o:I

.field public final p:Z


# direct methods
.method public constructor <init>(ILt7/q0;ILj8/i;ILjava/lang/String;Ljava/lang/String;)V
    .locals 5

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lj8/m;-><init>(ILt7/q0;I)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    invoke-static {p5, p1}, La8/f;->n(IZ)Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    iput-boolean p2, p0, Lj8/k;->i:Z

    .line 10
    .line 11
    iget-object p2, p0, Lj8/m;->g:Lt7/o;

    .line 12
    .line 13
    iget p2, p2, Lt7/o;->e:I

    .line 14
    .line 15
    iget p3, p4, Lt7/u0;->r:I

    .line 16
    .line 17
    iget-object v0, p4, Lt7/u0;->p:Lhr/h0;

    .line 18
    .line 19
    not-int p3, p3

    .line 20
    and-int/2addr p2, p3

    .line 21
    and-int/lit8 p3, p2, 0x1

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    if-eqz p3, :cond_0

    .line 25
    .line 26
    move p3, v1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move p3, p1

    .line 29
    :goto_0
    iput-boolean p3, p0, Lj8/k;->j:Z

    .line 30
    .line 31
    and-int/lit8 p2, p2, 0x2

    .line 32
    .line 33
    if-eqz p2, :cond_1

    .line 34
    .line 35
    move p2, v1

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move p2, p1

    .line 38
    :goto_1
    iput-boolean p2, p0, Lj8/k;->k:Z

    .line 39
    .line 40
    if-eqz p7, :cond_2

    .line 41
    .line 42
    invoke-static {p7}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_3

    .line 52
    .line 53
    const-string p2, ""

    .line 54
    .line 55
    invoke-static {p2}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    goto :goto_2

    .line 60
    :cond_3
    move-object p2, v0

    .line 61
    :goto_2
    move p3, p1

    .line 62
    :goto_3
    invoke-virtual {p2}, Ljava/util/AbstractCollection;->size()I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    const v3, 0x7fffffff

    .line 67
    .line 68
    .line 69
    if-ge p3, v2, :cond_5

    .line 70
    .line 71
    iget-object v2, p0, Lj8/m;->g:Lt7/o;

    .line 72
    .line 73
    invoke-interface {p2, p3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v2, v4, p1}, Lj8/o;->r(Lt7/o;Ljava/lang/String;Z)I

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    if-lez v2, :cond_4

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_4
    add-int/lit8 p3, p3, 0x1

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_5
    move v2, p1

    .line 90
    move p3, v3

    .line 91
    :goto_4
    iput p3, p0, Lj8/k;->l:I

    .line 92
    .line 93
    iput v2, p0, Lj8/k;->m:I

    .line 94
    .line 95
    const/16 p2, 0x440

    .line 96
    .line 97
    if-eqz p7, :cond_6

    .line 98
    .line 99
    move p3, p2

    .line 100
    goto :goto_5

    .line 101
    :cond_6
    move p3, p1

    .line 102
    :goto_5
    iget-object p7, p0, Lj8/m;->g:Lt7/o;

    .line 103
    .line 104
    iget p7, p7, Lt7/o;->f:I

    .line 105
    .line 106
    sget-object v4, Lj8/o;->l:Lhr/w0;

    .line 107
    .line 108
    if-eqz p7, :cond_7

    .line 109
    .line 110
    if-ne p7, p3, :cond_7

    .line 111
    .line 112
    goto :goto_6

    .line 113
    :cond_7
    and-int/2addr p3, p7

    .line 114
    invoke-static {p3}, Ljava/lang/Integer;->bitCount(I)I

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    :goto_6
    iput v3, p0, Lj8/k;->n:I

    .line 119
    .line 120
    iget-object p3, p0, Lj8/m;->g:Lt7/o;

    .line 121
    .line 122
    iget p3, p3, Lt7/o;->f:I

    .line 123
    .line 124
    and-int/2addr p2, p3

    .line 125
    if-eqz p2, :cond_8

    .line 126
    .line 127
    move p2, v1

    .line 128
    goto :goto_7

    .line 129
    :cond_8
    move p2, p1

    .line 130
    :goto_7
    iput-boolean p2, p0, Lj8/k;->p:Z

    .line 131
    .line 132
    invoke-static {p6}, Lj8/o;->u(Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    if-nez p2, :cond_9

    .line 137
    .line 138
    move p2, v1

    .line 139
    goto :goto_8

    .line 140
    :cond_9
    move p2, p1

    .line 141
    :goto_8
    iget-object p3, p0, Lj8/m;->g:Lt7/o;

    .line 142
    .line 143
    invoke-static {p3, p6, p2}, Lj8/o;->r(Lt7/o;Ljava/lang/String;Z)I

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    iput p2, p0, Lj8/k;->o:I

    .line 148
    .line 149
    if-gtz v2, :cond_c

    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 152
    .line 153
    .line 154
    move-result p3

    .line 155
    if-eqz p3, :cond_a

    .line 156
    .line 157
    if-gtz v3, :cond_c

    .line 158
    .line 159
    :cond_a
    iget-boolean p3, p0, Lj8/k;->j:Z

    .line 160
    .line 161
    if-nez p3, :cond_c

    .line 162
    .line 163
    iget-boolean p3, p0, Lj8/k;->k:Z

    .line 164
    .line 165
    if-eqz p3, :cond_b

    .line 166
    .line 167
    if-lez p2, :cond_b

    .line 168
    .line 169
    goto :goto_9

    .line 170
    :cond_b
    move p2, p1

    .line 171
    goto :goto_a

    .line 172
    :cond_c
    :goto_9
    move p2, v1

    .line 173
    :goto_a
    iget-boolean p3, p4, Lj8/i;->z:Z

    .line 174
    .line 175
    invoke-static {p5, p3}, La8/f;->n(IZ)Z

    .line 176
    .line 177
    .line 178
    move-result p3

    .line 179
    if-eqz p3, :cond_d

    .line 180
    .line 181
    if-eqz p2, :cond_d

    .line 182
    .line 183
    move p1, v1

    .line 184
    :cond_d
    iput p1, p0, Lj8/k;->h:I

    .line 185
    .line 186
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lj8/k;->h:I

    .line 2
    .line 3
    return p0
.end method

.method public final bridge synthetic b(Lj8/m;)Z
    .locals 0

    .line 1
    check-cast p1, Lj8/k;

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0
.end method

.method public final c(Lj8/k;)I
    .locals 7

    .line 1
    iget-boolean v0, p0, Lj8/k;->i:Z

    .line 2
    .line 3
    iget-boolean v1, p1, Lj8/k;->i:Z

    .line 4
    .line 5
    sget-object v2, Lhr/z;->a:Lhr/x;

    .line 6
    .line 7
    invoke-virtual {v2, v0, v1}, Lhr/x;->c(ZZ)Lhr/z;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget v1, p0, Lj8/k;->l:I

    .line 12
    .line 13
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget v2, p1, Lj8/k;->l:I

    .line 18
    .line 19
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    sget-object v3, Lhr/v0;->e:Lhr/v0;

    .line 24
    .line 25
    sget-object v4, Lhr/v0;->f:Lhr/v0;

    .line 26
    .line 27
    invoke-virtual {v0, v1, v2, v4}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iget v1, p1, Lj8/k;->m:I

    .line 32
    .line 33
    iget v2, p0, Lj8/k;->m:I

    .line 34
    .line 35
    invoke-virtual {v0, v2, v1}, Lhr/z;->a(II)Lhr/z;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iget v1, p1, Lj8/k;->n:I

    .line 40
    .line 41
    iget v5, p0, Lj8/k;->n:I

    .line 42
    .line 43
    invoke-virtual {v0, v5, v1}, Lhr/z;->a(II)Lhr/z;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-boolean v1, p0, Lj8/k;->j:Z

    .line 48
    .line 49
    iget-boolean v6, p1, Lj8/k;->j:Z

    .line 50
    .line 51
    invoke-virtual {v0, v1, v6}, Lhr/z;->c(ZZ)Lhr/z;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iget-boolean v1, p0, Lj8/k;->k:Z

    .line 56
    .line 57
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    iget-boolean v6, p1, Lj8/k;->k:Z

    .line 62
    .line 63
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    if-nez v2, :cond_0

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    move-object v3, v4

    .line 71
    :goto_0
    invoke-virtual {v0, v1, v6, v3}, Lhr/z;->b(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/Comparator;)Lhr/z;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget v1, p0, Lj8/k;->o:I

    .line 76
    .line 77
    iget v2, p1, Lj8/k;->o:I

    .line 78
    .line 79
    invoke-virtual {v0, v1, v2}, Lhr/z;->a(II)Lhr/z;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-nez v5, :cond_1

    .line 84
    .line 85
    iget-boolean p0, p0, Lj8/k;->p:Z

    .line 86
    .line 87
    iget-boolean p1, p1, Lj8/k;->p:Z

    .line 88
    .line 89
    invoke-virtual {v0, p0, p1}, Lhr/z;->d(ZZ)Lhr/z;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    :cond_1
    invoke-virtual {v0}, Lhr/z;->e()I

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    return p0
.end method

.method public final bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lj8/k;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lj8/k;->c(Lj8/k;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
