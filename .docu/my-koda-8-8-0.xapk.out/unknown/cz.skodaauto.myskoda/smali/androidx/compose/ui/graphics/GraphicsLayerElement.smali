.class final Landroidx/compose/ui/graphics/GraphicsLayerElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0082\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/ui/graphics/GraphicsLayerElement;",
        "Lv3/z0;",
        "Le3/o0;",
        "ui_release"
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
.field public final b:F

.field public final c:F

.field public final d:F

.field public final e:F

.field public final f:F

.field public final g:F

.field public final h:F

.field public final i:J

.field public final j:Le3/n0;

.field public final k:Z

.field public final l:J

.field public final m:J


# direct methods
.method public constructor <init>(FFFFFFFJLe3/n0;ZJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 5
    .line 6
    iput p2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 7
    .line 8
    iput p3, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 9
    .line 10
    iput p4, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 11
    .line 12
    iput p5, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 13
    .line 14
    iput p6, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 15
    .line 16
    iput p7, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 17
    .line 18
    iput-wide p8, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 19
    .line 20
    iput-object p10, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 21
    .line 22
    iput-boolean p11, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 23
    .line 24
    iput-wide p12, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 25
    .line 26
    iput-wide p14, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;

    .line 12
    .line 13
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 14
    .line 15
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 16
    .line 17
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_2
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 26
    .line 27
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 28
    .line 29
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_3

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_3
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 38
    .line 39
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 40
    .line 41
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eqz v0, :cond_4

    .line 46
    .line 47
    goto/16 :goto_0

    .line 48
    .line 49
    :cond_4
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 50
    .line 51
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 52
    .line 53
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_5

    .line 58
    .line 59
    goto/16 :goto_0

    .line 60
    .line 61
    :cond_5
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 62
    .line 63
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 64
    .line 65
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_6

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_6
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 73
    .line 74
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 75
    .line 76
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_7

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_7
    const/4 v0, 0x0

    .line 84
    invoke-static {v0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_8

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_8
    invoke-static {v0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_9

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_9
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 99
    .line 100
    iget v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 101
    .line 102
    invoke-static {v0, v1}, Ljava/lang/Float;->compare(FF)I

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    if-eqz v0, :cond_a

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_a
    const/high16 v0, 0x41000000    # 8.0f

    .line 110
    .line 111
    invoke-static {v0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-eqz v0, :cond_b

    .line 116
    .line 117
    goto :goto_0

    .line 118
    :cond_b
    iget-wide v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 119
    .line 120
    iget-wide v2, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 121
    .line 122
    invoke-static {v0, v1, v2, v3}, Le3/q0;->a(JJ)Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-nez v0, :cond_c

    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_c
    iget-object v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 130
    .line 131
    iget-object v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 132
    .line 133
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    if-nez v0, :cond_d

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_d
    iget-boolean v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 141
    .line 142
    iget-boolean v1, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 143
    .line 144
    if-eq v0, v1, :cond_e

    .line 145
    .line 146
    goto :goto_0

    .line 147
    :cond_e
    iget-wide v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 148
    .line 149
    iget-wide v2, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 150
    .line 151
    invoke-static {v0, v1, v2, v3}, Le3/s;->c(JJ)Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    if-nez v0, :cond_f

    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_f
    iget-wide v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 159
    .line 160
    iget-wide p0, p1, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 161
    .line 162
    invoke-static {v0, v1, p0, p1}, Le3/s;->c(JJ)Z

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    if-nez p0, :cond_10

    .line 167
    .line 168
    :goto_0
    const/4 p0, 0x0

    .line 169
    return p0

    .line 170
    :cond_10
    :goto_1
    const/4 p0, 0x1

    .line 171
    return p0
.end method

.method public final h()Lx2/r;
    .locals 3

    .line 1
    new-instance v0, Le3/o0;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 7
    .line 8
    iput v1, v0, Le3/o0;->r:F

    .line 9
    .line 10
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 11
    .line 12
    iput v1, v0, Le3/o0;->s:F

    .line 13
    .line 14
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 15
    .line 16
    iput v1, v0, Le3/o0;->t:F

    .line 17
    .line 18
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 19
    .line 20
    iput v1, v0, Le3/o0;->u:F

    .line 21
    .line 22
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 23
    .line 24
    iput v1, v0, Le3/o0;->v:F

    .line 25
    .line 26
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 27
    .line 28
    iput v1, v0, Le3/o0;->w:F

    .line 29
    .line 30
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 31
    .line 32
    iput v1, v0, Le3/o0;->x:F

    .line 33
    .line 34
    const/high16 v1, 0x41000000    # 8.0f

    .line 35
    .line 36
    iput v1, v0, Le3/o0;->y:F

    .line 37
    .line 38
    iget-wide v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 39
    .line 40
    iput-wide v1, v0, Le3/o0;->z:J

    .line 41
    .line 42
    iget-object v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 43
    .line 44
    iput-object v1, v0, Le3/o0;->A:Le3/n0;

    .line 45
    .line 46
    iget-boolean v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 47
    .line 48
    iput-boolean v1, v0, Le3/o0;->B:Z

    .line 49
    .line 50
    iget-wide v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 51
    .line 52
    iput-wide v1, v0, Le3/o0;->C:J

    .line 53
    .line 54
    iget-wide v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 55
    .line 56
    iput-wide v1, v0, Le3/o0;->D:J

    .line 57
    .line 58
    const/4 p0, 0x3

    .line 59
    iput p0, v0, Le3/o0;->E:I

    .line 60
    .line 61
    new-instance p0, La3/f;

    .line 62
    .line 63
    const/16 v1, 0xe

    .line 64
    .line 65
    invoke-direct {p0, v0, v1}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    iput-object p0, v0, Le3/o0;->F:La3/f;

    .line 69
    .line 70
    return-object v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

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
    iget v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 29
    .line 30
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 35
    .line 36
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    iget v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 50
    .line 51
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    const/high16 v2, 0x41000000    # 8.0f

    .line 56
    .line 57
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    sget v2, Le3/q0;->c:I

    .line 62
    .line 63
    iget-wide v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 64
    .line 65
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    iget-object v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 70
    .line 71
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    add-int/2addr v2, v0

    .line 76
    mul-int/2addr v2, v1

    .line 77
    iget-boolean v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 78
    .line 79
    const/16 v3, 0x3c1

    .line 80
    .line 81
    invoke-static {v2, v3, v0}, La7/g0;->e(IIZ)I

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    sget v2, Le3/s;->j:I

    .line 86
    .line 87
    iget-wide v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 88
    .line 89
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    iget-wide v2, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 94
    .line 95
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    const/4 v0, 0x0

    .line 100
    invoke-static {v0, p0, v1}, Lc1/j0;->g(III)I

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    const/4 v0, 0x3

    .line 105
    invoke-static {v0, p0, v1}, Lc1/j0;->g(III)I

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 2

    .line 1
    check-cast p1, Le3/o0;

    .line 2
    .line 3
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 4
    .line 5
    iput v0, p1, Le3/o0;->r:F

    .line 6
    .line 7
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 8
    .line 9
    iput v0, p1, Le3/o0;->s:F

    .line 10
    .line 11
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 12
    .line 13
    iput v0, p1, Le3/o0;->t:F

    .line 14
    .line 15
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 16
    .line 17
    iput v0, p1, Le3/o0;->u:F

    .line 18
    .line 19
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 20
    .line 21
    iput v0, p1, Le3/o0;->v:F

    .line 22
    .line 23
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 24
    .line 25
    iput v0, p1, Le3/o0;->w:F

    .line 26
    .line 27
    iget v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 28
    .line 29
    iput v0, p1, Le3/o0;->x:F

    .line 30
    .line 31
    const/high16 v0, 0x41000000    # 8.0f

    .line 32
    .line 33
    iput v0, p1, Le3/o0;->y:F

    .line 34
    .line 35
    iget-wide v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 36
    .line 37
    iput-wide v0, p1, Le3/o0;->z:J

    .line 38
    .line 39
    iget-object v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 40
    .line 41
    iput-object v0, p1, Le3/o0;->A:Le3/n0;

    .line 42
    .line 43
    iget-boolean v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 44
    .line 45
    iput-boolean v0, p1, Le3/o0;->B:Z

    .line 46
    .line 47
    iget-wide v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 48
    .line 49
    iput-wide v0, p1, Le3/o0;->C:J

    .line 50
    .line 51
    iget-wide v0, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 52
    .line 53
    iput-wide v0, p1, Le3/o0;->D:J

    .line 54
    .line 55
    const/4 p0, 0x3

    .line 56
    iput p0, p1, Le3/o0;->E:I

    .line 57
    .line 58
    const/4 p0, 0x2

    .line 59
    invoke-static {p1, p0}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    iget-object p0, p0, Lv3/f1;->s:Lv3/f1;

    .line 64
    .line 65
    if-eqz p0, :cond_0

    .line 66
    .line 67
    iget-object p1, p1, Le3/o0;->F:La3/f;

    .line 68
    .line 69
    const/4 v0, 0x1

    .line 70
    invoke-virtual {p0, p1, v0}, Lv3/f1;->E1(Lay0/k;Z)V

    .line 71
    .line 72
    .line 73
    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "GraphicsLayerElement(scaleX="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->b:F

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", scaleY="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->c:F

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", alpha="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->d:F

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", translationX="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->e:F

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", translationY="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->f:F

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", shadowElevation="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->g:F

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", rotationX=0.0, rotationY=0.0, rotationZ="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->h:F

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", cameraDistance=8.0, transformOrigin="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-wide v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->i:J

    .line 79
    .line 80
    invoke-static {v1, v2}, Le3/q0;->d(J)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v1, ", shape="

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    iget-object v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->j:Le3/n0;

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", clip="

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    iget-boolean v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->k:Z

    .line 103
    .line 104
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    const-string v1, ", renderEffect=null, ambientShadowColor="

    .line 108
    .line 109
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    iget-wide v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->l:J

    .line 113
    .line 114
    const-string v3, ", spotShadowColor="

    .line 115
    .line 116
    invoke-static {v1, v2, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->x(JLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 117
    .line 118
    .line 119
    iget-wide v1, p0, Landroidx/compose/ui/graphics/GraphicsLayerElement;->m:J

    .line 120
    .line 121
    invoke-static {v1, v2}, Le3/s;->i(J)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string p0, ", compositingStrategy=CompositingStrategy(value=0), blendMode="

    .line 129
    .line 130
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const/4 p0, 0x3

    .line 134
    invoke-static {p0}, Le3/j0;->D(I)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    const-string p0, ", colorFilter=null)"

    .line 142
    .line 143
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0
.end method
