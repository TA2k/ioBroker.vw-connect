.class public final Lj3/h;
.super Lj3/c0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public b:Le3/p;

.field public c:F

.field public d:Ljava/util/List;

.field public e:F

.field public f:F

.field public g:Le3/p;

.field public h:I

.field public i:I

.field public j:F

.field public k:F

.field public l:F

.field public m:F

.field public n:Z

.field public o:Z

.field public p:Z

.field public q:Lg3/h;

.field public final r:Le3/i;

.field public s:Le3/i;

.field public final t:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f800000    # 1.0f

    .line 5
    .line 6
    iput v0, p0, Lj3/h;->c:F

    .line 7
    .line 8
    sget v1, Lj3/h0;->a:I

    .line 9
    .line 10
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 11
    .line 12
    iput-object v1, p0, Lj3/h;->d:Ljava/util/List;

    .line 13
    .line 14
    iput v0, p0, Lj3/h;->e:F

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    iput v1, p0, Lj3/h;->h:I

    .line 18
    .line 19
    iput v1, p0, Lj3/h;->i:I

    .line 20
    .line 21
    const/high16 v1, 0x40800000    # 4.0f

    .line 22
    .line 23
    iput v1, p0, Lj3/h;->j:F

    .line 24
    .line 25
    iput v0, p0, Lj3/h;->l:F

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    iput-boolean v0, p0, Lj3/h;->n:Z

    .line 29
    .line 30
    iput-boolean v0, p0, Lj3/h;->o:Z

    .line 31
    .line 32
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iput-object v0, p0, Lj3/h;->r:Le3/i;

    .line 37
    .line 38
    iput-object v0, p0, Lj3/h;->s:Le3/i;

    .line 39
    .line 40
    sget-object v0, Llx0/j;->f:Llx0/j;

    .line 41
    .line 42
    sget-object v1, Lj3/g;->g:Lj3/g;

    .line 43
    .line 44
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iput-object v0, p0, Lj3/h;->t:Ljava/lang/Object;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final a(Lg3/d;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lj3/h;->n:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v0, Lj3/h;->d:Ljava/util/List;

    .line 8
    .line 9
    iget-object v2, v0, Lj3/h;->r:Le3/i;

    .line 10
    .line 11
    invoke-static {v1, v2}, Lj3/b;->d(Ljava/util/List;Le3/i;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Lj3/h;->e()V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-boolean v1, v0, Lj3/h;->p:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0}, Lj3/h;->e()V

    .line 23
    .line 24
    .line 25
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 26
    iput-boolean v1, v0, Lj3/h;->n:Z

    .line 27
    .line 28
    iput-boolean v1, v0, Lj3/h;->p:Z

    .line 29
    .line 30
    iget-object v4, v0, Lj3/h;->b:Le3/p;

    .line 31
    .line 32
    if-eqz v4, :cond_2

    .line 33
    .line 34
    iget-object v3, v0, Lj3/h;->s:Le3/i;

    .line 35
    .line 36
    iget v5, v0, Lj3/h;->c:F

    .line 37
    .line 38
    const/4 v6, 0x0

    .line 39
    const/16 v7, 0x38

    .line 40
    .line 41
    move-object/from16 v2, p1

    .line 42
    .line 43
    invoke-static/range {v2 .. v7}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 44
    .line 45
    .line 46
    :cond_2
    iget-object v10, v0, Lj3/h;->g:Le3/p;

    .line 47
    .line 48
    if-eqz v10, :cond_5

    .line 49
    .line 50
    iget-object v2, v0, Lj3/h;->q:Lg3/h;

    .line 51
    .line 52
    iget-boolean v3, v0, Lj3/h;->o:Z

    .line 53
    .line 54
    if-nez v3, :cond_4

    .line 55
    .line 56
    if-nez v2, :cond_3

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    move-object v12, v2

    .line 60
    goto :goto_2

    .line 61
    :cond_4
    :goto_1
    new-instance v11, Lg3/h;

    .line 62
    .line 63
    iget v12, v0, Lj3/h;->f:F

    .line 64
    .line 65
    iget v13, v0, Lj3/h;->j:F

    .line 66
    .line 67
    iget v14, v0, Lj3/h;->h:I

    .line 68
    .line 69
    iget v15, v0, Lj3/h;->i:I

    .line 70
    .line 71
    const/16 v16, 0x0

    .line 72
    .line 73
    const/16 v17, 0x10

    .line 74
    .line 75
    invoke-direct/range {v11 .. v17}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 76
    .line 77
    .line 78
    iput-object v11, v0, Lj3/h;->q:Lg3/h;

    .line 79
    .line 80
    iput-boolean v1, v0, Lj3/h;->o:Z

    .line 81
    .line 82
    move-object v12, v11

    .line 83
    :goto_2
    iget-object v9, v0, Lj3/h;->s:Le3/i;

    .line 84
    .line 85
    iget v11, v0, Lj3/h;->e:F

    .line 86
    .line 87
    const/16 v13, 0x30

    .line 88
    .line 89
    move-object/from16 v8, p1

    .line 90
    .line 91
    invoke-static/range {v8 .. v13}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 92
    .line 93
    .line 94
    :cond_5
    return-void
.end method

.method public final e()V
    .locals 7

    .line 1
    iget v0, p0, Lj3/h;->k:F

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    cmpg-float v0, v0, v1

    .line 5
    .line 6
    iget-object v2, p0, Lj3/h;->r:Le3/i;

    .line 7
    .line 8
    const/high16 v3, 0x3f800000    # 1.0f

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget v0, p0, Lj3/h;->l:F

    .line 13
    .line 14
    cmpg-float v0, v0, v3

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    iput-object v2, p0, Lj3/h;->s:Le3/i;

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object v0, p0, Lj3/h;->s:Le3/i;

    .line 22
    .line 23
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v4, 0x0

    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    iput-object v0, p0, Lj3/h;->s:Le3/i;

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    iget-object v0, p0, Lj3/h;->s:Le3/i;

    .line 38
    .line 39
    iget-object v0, v0, Le3/i;->a:Landroid/graphics/Path;

    .line 40
    .line 41
    invoke-virtual {v0}, Landroid/graphics/Path;->getFillType()Landroid/graphics/Path$FillType;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sget-object v5, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 46
    .line 47
    if-ne v0, v5, :cond_2

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    goto :goto_0

    .line 51
    :cond_2
    move v0, v4

    .line 52
    :goto_0
    iget-object v5, p0, Lj3/h;->s:Le3/i;

    .line 53
    .line 54
    invoke-virtual {v5}, Le3/i;->k()V

    .line 55
    .line 56
    .line 57
    iget-object v5, p0, Lj3/h;->s:Le3/i;

    .line 58
    .line 59
    invoke-virtual {v5, v0}, Le3/i;->l(I)V

    .line 60
    .line 61
    .line 62
    :goto_1
    iget-object v0, p0, Lj3/h;->t:Ljava/lang/Object;

    .line 63
    .line 64
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    check-cast v5, Le3/k;

    .line 69
    .line 70
    iget-object v5, v5, Le3/k;->a:Landroid/graphics/PathMeasure;

    .line 71
    .line 72
    if-eqz v2, :cond_3

    .line 73
    .line 74
    iget-object v2, v2, Le3/i;->a:Landroid/graphics/Path;

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_3
    const/4 v2, 0x0

    .line 78
    :goto_2
    invoke-virtual {v5, v2, v4}, Landroid/graphics/PathMeasure;->setPath(Landroid/graphics/Path;Z)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    check-cast v2, Le3/k;

    .line 86
    .line 87
    iget-object v2, v2, Le3/k;->a:Landroid/graphics/PathMeasure;

    .line 88
    .line 89
    invoke-virtual {v2}, Landroid/graphics/PathMeasure;->getLength()F

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    iget v4, p0, Lj3/h;->k:F

    .line 94
    .line 95
    iget v5, p0, Lj3/h;->m:F

    .line 96
    .line 97
    add-float/2addr v4, v5

    .line 98
    rem-float/2addr v4, v3

    .line 99
    mul-float/2addr v4, v2

    .line 100
    iget v6, p0, Lj3/h;->l:F

    .line 101
    .line 102
    add-float/2addr v6, v5

    .line 103
    rem-float/2addr v6, v3

    .line 104
    mul-float/2addr v6, v2

    .line 105
    cmpl-float v3, v4, v6

    .line 106
    .line 107
    if-lez v3, :cond_4

    .line 108
    .line 109
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    check-cast v3, Le3/k;

    .line 114
    .line 115
    iget-object v5, p0, Lj3/h;->s:Le3/i;

    .line 116
    .line 117
    invoke-virtual {v3, v4, v2, v5}, Le3/k;->a(FFLe3/i;)V

    .line 118
    .line 119
    .line 120
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Le3/k;

    .line 125
    .line 126
    iget-object p0, p0, Lj3/h;->s:Le3/i;

    .line 127
    .line 128
    invoke-virtual {v0, v1, v6, p0}, Le3/k;->a(FFLe3/i;)V

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :cond_4
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    check-cast v0, Le3/k;

    .line 137
    .line 138
    iget-object p0, p0, Lj3/h;->s:Le3/i;

    .line 139
    .line 140
    invoke-virtual {v0, v4, v6, p0}, Le3/k;->a(FFLe3/i;)V

    .line 141
    .line 142
    .line 143
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lj3/h;->r:Le3/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
