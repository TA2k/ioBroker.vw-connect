.class public final Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;",
        "Lv3/z0;",
        "Ld2/l;",
        "foundation_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Ljava/lang/String;

.field public final c:Lg4/p0;

.field public final d:Lk4/m;

.field public final e:I

.field public final f:Z

.field public final g:I

.field public final h:I

.field public final i:Le3/t;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lg4/p0;Lk4/m;IZIILe3/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->b:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->c:Lg4/p0;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->d:Lk4/m;

    .line 9
    .line 10
    iput p4, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->e:I

    .line 11
    .line 12
    iput-boolean p5, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->f:Z

    .line 13
    .line 14
    iput p6, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->g:I

    .line 15
    .line 16
    iput p7, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->h:I

    .line 17
    .line 18
    iput-object p8, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->i:Le3/t;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;

    .line 12
    .line 13
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->i:Le3/t;

    .line 14
    .line 15
    iget-object v3, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->i:Le3/t;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->b:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->c:Lg4/p0;

    .line 36
    .line 37
    iget-object v3, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->c:Lg4/p0;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->d:Lk4/m;

    .line 47
    .line 48
    iget-object v3, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->d:Lk4/m;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->e:I

    .line 58
    .line 59
    iget v3, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->e:I

    .line 60
    .line 61
    if-ne v1, v3, :cond_9

    .line 62
    .line 63
    iget-boolean v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->f:Z

    .line 64
    .line 65
    iget-boolean v3, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->f:Z

    .line 66
    .line 67
    if-eq v1, v3, :cond_6

    .line 68
    .line 69
    return v2

    .line 70
    :cond_6
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->g:I

    .line 71
    .line 72
    iget v3, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->g:I

    .line 73
    .line 74
    if-eq v1, v3, :cond_7

    .line 75
    .line 76
    return v2

    .line 77
    :cond_7
    iget p0, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->h:I

    .line 78
    .line 79
    iget p1, p1, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->h:I

    .line 80
    .line 81
    if-eq p0, p1, :cond_8

    .line 82
    .line 83
    return v2

    .line 84
    :cond_8
    return v0

    .line 85
    :cond_9
    return v2
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Ld2/l;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object v1, v0, Ld2/l;->r:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->c:Lg4/p0;

    .line 11
    .line 12
    iput-object v1, v0, Ld2/l;->s:Lg4/p0;

    .line 13
    .line 14
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->d:Lk4/m;

    .line 15
    .line 16
    iput-object v1, v0, Ld2/l;->t:Lk4/m;

    .line 17
    .line 18
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->e:I

    .line 19
    .line 20
    iput v1, v0, Ld2/l;->u:I

    .line 21
    .line 22
    iget-boolean v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->f:Z

    .line 23
    .line 24
    iput-boolean v1, v0, Ld2/l;->v:Z

    .line 25
    .line 26
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->g:I

    .line 27
    .line 28
    iput v1, v0, Ld2/l;->w:I

    .line 29
    .line 30
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->h:I

    .line 31
    .line 32
    iput v1, v0, Ld2/l;->x:I

    .line 33
    .line 34
    iget-object p0, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->i:Le3/t;

    .line 35
    .line 36
    iput-object p0, v0, Ld2/l;->y:Le3/t;

    .line 37
    .line 38
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->b:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->c:Lg4/p0;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->c(IILg4/p0;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->d:Lk4/m;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget v0, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->e:I

    .line 25
    .line 26
    invoke-static {v0, v2, v1}, Lc1/j0;->g(III)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-boolean v2, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->f:Z

    .line 31
    .line 32
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget v2, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->g:I

    .line 37
    .line 38
    add-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget v2, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->h:I

    .line 41
    .line 42
    add-int/2addr v0, v2

    .line 43
    mul-int/2addr v0, v1

    .line 44
    iget-object p0, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->i:Le3/t;

    .line 45
    .line 46
    if-eqz p0, :cond_0

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 p0, 0x0

    .line 54
    :goto_0
    add-int/2addr v0, p0

    .line 55
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 10

    .line 1
    check-cast p1, Ld2/l;

    .line 2
    .line 3
    iget-object v0, p1, Ld2/l;->y:Le3/t;

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->i:Le3/t;

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput-object v1, p1, Ld2/l;->y:Le3/t;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x1

    .line 15
    iget-object v3, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->c:Lg4/p0;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p1, Ld2/l;->s:Lg4/p0;

    .line 20
    .line 21
    if-eq v3, v0, :cond_0

    .line 22
    .line 23
    iget-object v4, v3, Lg4/p0;->a:Lg4/g0;

    .line 24
    .line 25
    iget-object v0, v0, Lg4/p0;->a:Lg4/g0;

    .line 26
    .line 27
    invoke-virtual {v4, v0}, Lg4/g0;->c(Lg4/g0;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    :goto_0
    move v0, v1

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v0, v2

    .line 40
    :goto_1
    iget-object v4, p1, Ld2/l;->r:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v5, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->b:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_2

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    iput-object v5, p1, Ld2/l;->r:Ljava/lang/String;

    .line 52
    .line 53
    const/4 v1, 0x0

    .line 54
    iput-object v1, p1, Ld2/l;->C:Ld2/k;

    .line 55
    .line 56
    move v1, v2

    .line 57
    :goto_2
    iget-object v4, p1, Ld2/l;->s:Lg4/p0;

    .line 58
    .line 59
    invoke-virtual {v4, v3}, Lg4/p0;->c(Lg4/p0;)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    xor-int/2addr v4, v2

    .line 64
    iput-object v3, p1, Ld2/l;->s:Lg4/p0;

    .line 65
    .line 66
    iget v3, p1, Ld2/l;->x:I

    .line 67
    .line 68
    iget v5, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->h:I

    .line 69
    .line 70
    if-eq v3, v5, :cond_3

    .line 71
    .line 72
    iput v5, p1, Ld2/l;->x:I

    .line 73
    .line 74
    move v4, v2

    .line 75
    :cond_3
    iget v3, p1, Ld2/l;->w:I

    .line 76
    .line 77
    iget v5, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->g:I

    .line 78
    .line 79
    if-eq v3, v5, :cond_4

    .line 80
    .line 81
    iput v5, p1, Ld2/l;->w:I

    .line 82
    .line 83
    move v4, v2

    .line 84
    :cond_4
    iget-boolean v3, p1, Ld2/l;->v:Z

    .line 85
    .line 86
    iget-boolean v5, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->f:Z

    .line 87
    .line 88
    if-eq v3, v5, :cond_5

    .line 89
    .line 90
    iput-boolean v5, p1, Ld2/l;->v:Z

    .line 91
    .line 92
    move v4, v2

    .line 93
    :cond_5
    iget-object v3, p1, Ld2/l;->t:Lk4/m;

    .line 94
    .line 95
    iget-object v5, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->d:Lk4/m;

    .line 96
    .line 97
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    if-nez v3, :cond_6

    .line 102
    .line 103
    iput-object v5, p1, Ld2/l;->t:Lk4/m;

    .line 104
    .line 105
    move v4, v2

    .line 106
    :cond_6
    iget v3, p1, Ld2/l;->u:I

    .line 107
    .line 108
    iget p0, p0, Landroidx/compose/foundation/text/modifiers/TextStringSimpleElement;->e:I

    .line 109
    .line 110
    if-ne v3, p0, :cond_7

    .line 111
    .line 112
    move v2, v4

    .line 113
    goto :goto_3

    .line 114
    :cond_7
    iput p0, p1, Ld2/l;->u:I

    .line 115
    .line 116
    :goto_3
    if-nez v1, :cond_8

    .line 117
    .line 118
    if-eqz v2, :cond_9

    .line 119
    .line 120
    :cond_8
    invoke-virtual {p1}, Ld2/l;->X0()Ld2/e;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    iget-object v3, p1, Ld2/l;->r:Ljava/lang/String;

    .line 125
    .line 126
    iget-object v4, p1, Ld2/l;->s:Lg4/p0;

    .line 127
    .line 128
    iget-object v5, p1, Ld2/l;->t:Lk4/m;

    .line 129
    .line 130
    iget v6, p1, Ld2/l;->u:I

    .line 131
    .line 132
    iget-boolean v7, p1, Ld2/l;->v:Z

    .line 133
    .line 134
    iget v8, p1, Ld2/l;->w:I

    .line 135
    .line 136
    iget v9, p1, Ld2/l;->x:I

    .line 137
    .line 138
    iput-object v3, p0, Ld2/e;->a:Ljava/lang/String;

    .line 139
    .line 140
    iput-object v4, p0, Ld2/e;->b:Lg4/p0;

    .line 141
    .line 142
    iput-object v5, p0, Ld2/e;->c:Lk4/m;

    .line 143
    .line 144
    iput v6, p0, Ld2/e;->d:I

    .line 145
    .line 146
    iput-boolean v7, p0, Ld2/e;->e:Z

    .line 147
    .line 148
    iput v8, p0, Ld2/e;->f:I

    .line 149
    .line 150
    iput v9, p0, Ld2/e;->g:I

    .line 151
    .line 152
    iget-wide v3, p0, Ld2/e;->s:J

    .line 153
    .line 154
    const/4 v5, 0x2

    .line 155
    shl-long/2addr v3, v5

    .line 156
    const-wide/16 v5, 0x2

    .line 157
    .line 158
    or-long/2addr v3, v5

    .line 159
    iput-wide v3, p0, Ld2/e;->s:J

    .line 160
    .line 161
    invoke-virtual {p0}, Ld2/e;->c()V

    .line 162
    .line 163
    .line 164
    :cond_9
    iget-boolean p0, p1, Lx2/r;->q:Z

    .line 165
    .line 166
    if-nez p0, :cond_a

    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_a
    if-nez v1, :cond_b

    .line 170
    .line 171
    if-eqz v0, :cond_c

    .line 172
    .line 173
    iget-object p0, p1, Ld2/l;->B:Ld2/j;

    .line 174
    .line 175
    if-eqz p0, :cond_c

    .line 176
    .line 177
    :cond_b
    invoke-static {p1}, Lv3/f;->o(Lv3/x1;)V

    .line 178
    .line 179
    .line 180
    :cond_c
    if-nez v1, :cond_d

    .line 181
    .line 182
    if-eqz v2, :cond_e

    .line 183
    .line 184
    :cond_d
    invoke-static {p1}, Lv3/f;->n(Lv3/y;)V

    .line 185
    .line 186
    .line 187
    invoke-static {p1}, Lv3/f;->m(Lv3/p;)V

    .line 188
    .line 189
    .line 190
    :cond_e
    if-eqz v0, :cond_f

    .line 191
    .line 192
    invoke-static {p1}, Lv3/f;->m(Lv3/p;)V

    .line 193
    .line 194
    .line 195
    :cond_f
    :goto_4
    return-void
.end method
