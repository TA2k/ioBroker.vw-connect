.class public final Lwm/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwm/e;
.implements Lwm/l;
.implements Lxm/a;


# instance fields
.field public final a:Lb11/a;

.field public final b:Landroid/graphics/RectF;

.field public final c:Lgn/g;

.field public final d:Landroid/graphics/Matrix;

.field public final e:Landroid/graphics/Path;

.field public final f:Landroid/graphics/RectF;

.field public final g:Z

.field public final h:Ljava/util/ArrayList;

.field public final i:Lum/j;

.field public j:Ljava/util/ArrayList;

.field public final k:Lxm/n;


# direct methods
.method public constructor <init>(Lum/j;Ldn/b;Lcn/m;Lum/a;)V
    .locals 7

    .line 1
    iget-object v0, p3, Lcn/m;->a:Ljava/lang/String;

    .line 2
    iget-boolean v4, p3, Lcn/m;->c:Z

    .line 3
    iget-object p3, p3, Lcn/m;->b:Ljava/util/List;

    .line 4
    new-instance v5, Ljava/util/ArrayList;

    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v0

    invoke-direct {v5, v0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v0, 0x0

    move v1, v0

    .line 5
    :goto_0
    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v2

    if-ge v1, v2, :cond_1

    .line 6
    invoke-interface {p3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcn/b;

    invoke-interface {v2, p1, p4, p2}, Lcn/b;->a(Lum/j;Lum/a;Ldn/b;)Lwm/c;

    move-result-object v2

    if-eqz v2, :cond_0

    .line 7
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    .line 8
    :cond_1
    :goto_1
    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result p4

    if-ge v0, p4, :cond_3

    .line 9
    invoke-interface {p3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Lcn/b;

    .line 10
    instance-of v1, p4, Lbn/e;

    if-eqz v1, :cond_2

    .line 11
    check-cast p4, Lbn/e;

    :goto_2
    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v6, p4

    goto :goto_3

    :cond_2
    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_3
    const/4 p4, 0x0

    goto :goto_2

    .line 12
    :goto_3
    invoke-direct/range {v1 .. v6}, Lwm/d;-><init>(Lum/j;Ldn/b;ZLjava/util/ArrayList;Lbn/e;)V

    return-void
.end method

.method public constructor <init>(Lum/j;Ldn/b;ZLjava/util/ArrayList;Lbn/e;)V
    .locals 3

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    new-instance v0, Lb11/a;

    const/4 v1, 0x4

    const/4 v2, 0x0

    invoke-direct {v0, v2, v1}, Lb11/a;-><init>(BI)V

    iput-object v0, p0, Lwm/d;->a:Lb11/a;

    .line 15
    new-instance v0, Landroid/graphics/RectF;

    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    iput-object v0, p0, Lwm/d;->b:Landroid/graphics/RectF;

    .line 16
    new-instance v0, Lgn/g;

    invoke-direct {v0}, Lgn/g;-><init>()V

    iput-object v0, p0, Lwm/d;->c:Lgn/g;

    .line 17
    new-instance v0, Landroid/graphics/Matrix;

    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    iput-object v0, p0, Lwm/d;->d:Landroid/graphics/Matrix;

    .line 18
    new-instance v0, Landroid/graphics/Path;

    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    iput-object v0, p0, Lwm/d;->e:Landroid/graphics/Path;

    .line 19
    new-instance v0, Landroid/graphics/RectF;

    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    iput-object v0, p0, Lwm/d;->f:Landroid/graphics/RectF;

    .line 20
    iput-object p1, p0, Lwm/d;->i:Lum/j;

    .line 21
    iput-boolean p3, p0, Lwm/d;->g:Z

    .line 22
    iput-object p4, p0, Lwm/d;->h:Ljava/util/ArrayList;

    if-eqz p5, :cond_0

    .line 23
    new-instance p1, Lxm/n;

    invoke-direct {p1, p5}, Lxm/n;-><init>(Lbn/e;)V

    .line 24
    iput-object p1, p0, Lwm/d;->k:Lxm/n;

    .line 25
    invoke-virtual {p1, p2}, Lxm/n;->a(Ldn/b;)V

    .line 26
    invoke-virtual {p1, p0}, Lxm/n;->b(Lxm/a;)V

    .line 27
    :cond_0
    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 28
    invoke-virtual {p4}, Ljava/util/ArrayList;->size()I

    move-result p1

    add-int/lit8 p1, p1, -0x1

    :goto_0
    if-ltz p1, :cond_2

    .line 29
    invoke-virtual {p4, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lwm/c;

    .line 30
    instance-of p3, p2, Lwm/j;

    if-eqz p3, :cond_1

    .line 31
    check-cast p2, Lwm/j;

    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_1
    add-int/lit8 p1, p1, -0x1

    goto :goto_0

    .line 32
    :cond_2
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result p1

    add-int/lit8 p1, p1, -0x1

    :goto_1
    if-ltz p1, :cond_3

    .line 33
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lwm/j;

    invoke-virtual {p4}, Ljava/util/ArrayList;->size()I

    move-result p3

    invoke-virtual {p4, p3}, Ljava/util/ArrayList;->listIterator(I)Ljava/util/ListIterator;

    move-result-object p3

    invoke-interface {p2, p3}, Lwm/j;->f(Ljava/util/ListIterator;)V

    add-int/lit8 p1, p1, -0x1

    goto :goto_1

    :cond_3
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lwm/d;->i:Lum/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lum/j;->invalidateSelf()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(Ljava/util/List;Ljava/util/List;)V
    .locals 2

    .line 1
    new-instance p2, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object p0, p0, Lwm/d;->h:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, v0

    .line 14
    invoke-direct {p2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    add-int/lit8 p1, p1, -0x1

    .line 25
    .line 26
    :goto_0
    if-ltz p1, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, Lwm/c;

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-virtual {p0, v1, p1}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-interface {v0, p2, v1}, Lwm/c;->b(Ljava/util/List;Ljava/util/List;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    add-int/lit8 p1, p1, -0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    return-void
.end method

.method public final c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lwm/d;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_9

    .line 6
    .line 7
    :cond_0
    iget-object v0, p0, Lwm/d;->d:Landroid/graphics/Matrix;

    .line 8
    .line 9
    invoke-virtual {v0, p2}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lwm/d;->k:Lxm/n;

    .line 13
    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    invoke-virtual {v1}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {v0, v2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 21
    .line 22
    .line 23
    iget-object v1, v1, Lxm/n;->j:Lxm/f;

    .line 24
    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    const/16 v1, 0x64

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Ljava/lang/Integer;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    :goto_0
    int-to-float v1, v1

    .line 41
    const/high16 v2, 0x42c80000    # 100.0f

    .line 42
    .line 43
    div-float/2addr v1, v2

    .line 44
    int-to-float p3, p3

    .line 45
    mul-float/2addr v1, p3

    .line 46
    const/high16 p3, 0x437f0000    # 255.0f

    .line 47
    .line 48
    div-float/2addr v1, p3

    .line 49
    mul-float/2addr v1, p3

    .line 50
    float-to-int p3, v1

    .line 51
    :cond_2
    iget-object v1, p0, Lwm/d;->i:Lum/j;

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    if-eqz p4, :cond_5

    .line 58
    .line 59
    iget-boolean v1, v1, Lum/j;->n:Z

    .line 60
    .line 61
    if-eqz v1, :cond_5

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    move v3, v1

    .line 65
    move v4, v3

    .line 66
    :goto_1
    iget-object v5, p0, Lwm/d;->h:Ljava/util/ArrayList;

    .line 67
    .line 68
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-ge v3, v6, :cond_4

    .line 73
    .line 74
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    instance-of v5, v5, Lwm/e;

    .line 79
    .line 80
    if-eqz v5, :cond_3

    .line 81
    .line 82
    add-int/lit8 v4, v4, 0x1

    .line 83
    .line 84
    const/4 v5, 0x2

    .line 85
    if-lt v4, v5, :cond_3

    .line 86
    .line 87
    const/4 v1, 0x1

    .line 88
    goto :goto_2

    .line 89
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_4
    :goto_2
    if-eqz v1, :cond_5

    .line 93
    .line 94
    move v1, v2

    .line 95
    goto :goto_3

    .line 96
    :cond_5
    const/4 v1, 0x0

    .line 97
    :goto_3
    if-eqz v1, :cond_6

    .line 98
    .line 99
    const/16 v3, 0xff

    .line 100
    .line 101
    goto :goto_4

    .line 102
    :cond_6
    move v3, p3

    .line 103
    :goto_4
    iget-object v4, p0, Lwm/d;->c:Lgn/g;

    .line 104
    .line 105
    if-eqz v1, :cond_9

    .line 106
    .line 107
    iget-object v5, p0, Lwm/d;->b:Landroid/graphics/RectF;

    .line 108
    .line 109
    const/4 v6, 0x0

    .line 110
    invoke-virtual {v5, v6, v6, v6, v6}, Landroid/graphics/RectF;->set(FFFF)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0, v5, p2, v2}, Lwm/d;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 114
    .line 115
    .line 116
    iget-object p2, p0, Lwm/d;->a:Lb11/a;

    .line 117
    .line 118
    iput p3, p2, Lb11/a;->e:I

    .line 119
    .line 120
    const/4 p3, 0x0

    .line 121
    if-eqz p4, :cond_8

    .line 122
    .line 123
    iget v6, p4, Lgn/a;->d:I

    .line 124
    .line 125
    invoke-static {v6}, Landroid/graphics/Color;->alpha(I)I

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    if-lez v6, :cond_7

    .line 130
    .line 131
    iput-object p4, p2, Lb11/a;->f:Ljava/lang/Object;

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_7
    iput-object p3, p2, Lb11/a;->f:Ljava/lang/Object;

    .line 135
    .line 136
    :goto_5
    move-object p4, p3

    .line 137
    goto :goto_6

    .line 138
    :cond_8
    iput-object p3, p2, Lb11/a;->f:Ljava/lang/Object;

    .line 139
    .line 140
    :goto_6
    invoke-virtual {v4, p1, v5, p2}, Lgn/g;->e(Landroid/graphics/Canvas;Landroid/graphics/RectF;Lb11/a;)Landroid/graphics/Canvas;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    goto :goto_7

    .line 145
    :cond_9
    if-eqz p4, :cond_a

    .line 146
    .line 147
    new-instance p2, Lgn/a;

    .line 148
    .line 149
    invoke-direct {p2, p4}, Lgn/a;-><init>(Lgn/a;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p2, v3}, Lgn/a;->b(I)V

    .line 153
    .line 154
    .line 155
    move-object p4, p2

    .line 156
    :cond_a
    :goto_7
    iget-object p0, p0, Lwm/d;->h:Ljava/util/ArrayList;

    .line 157
    .line 158
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 159
    .line 160
    .line 161
    move-result p2

    .line 162
    sub-int/2addr p2, v2

    .line 163
    :goto_8
    if-ltz p2, :cond_c

    .line 164
    .line 165
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p3

    .line 169
    instance-of v2, p3, Lwm/e;

    .line 170
    .line 171
    if-eqz v2, :cond_b

    .line 172
    .line 173
    check-cast p3, Lwm/e;

    .line 174
    .line 175
    invoke-interface {p3, p1, v0, v3, p4}, Lwm/e;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 176
    .line 177
    .line 178
    :cond_b
    add-int/lit8 p2, p2, -0x1

    .line 179
    .line 180
    goto :goto_8

    .line 181
    :cond_c
    if-eqz v1, :cond_d

    .line 182
    .line 183
    invoke-virtual {v4}, Lgn/g;->c()V

    .line 184
    .line 185
    .line 186
    :cond_d
    :goto_9
    return-void
.end method

.method public final d()Landroid/graphics/Path;
    .locals 5

    .line 1
    iget-object v0, p0, Lwm/d;->d:Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/graphics/Matrix;->reset()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lwm/d;->k:Lxm/n;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    invoke-virtual {v1}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v1, p0, Lwm/d;->e:Landroid/graphics/Path;

    .line 18
    .line 19
    invoke-virtual {v1}, Landroid/graphics/Path;->reset()V

    .line 20
    .line 21
    .line 22
    iget-boolean v2, p0, Lwm/d;->g:Z

    .line 23
    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    iget-object p0, p0, Lwm/d;->h:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    add-int/lit8 v2, v2, -0x1

    .line 34
    .line 35
    :goto_0
    if-ltz v2, :cond_3

    .line 36
    .line 37
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Lwm/c;

    .line 42
    .line 43
    instance-of v4, v3, Lwm/l;

    .line 44
    .line 45
    if-eqz v4, :cond_2

    .line 46
    .line 47
    check-cast v3, Lwm/l;

    .line 48
    .line 49
    invoke-interface {v3}, Lwm/l;->d()Landroid/graphics/Path;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-virtual {v1, v3, v0}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;Landroid/graphics/Matrix;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    add-int/lit8 v2, v2, -0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    :goto_1
    return-object v1
.end method

.method public final e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lwm/d;->d:Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-virtual {v0, p2}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lwm/d;->k:Lxm/n;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    invoke-virtual {p2}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-virtual {v0, p2}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object p2, p0, Lwm/d;->f:Landroid/graphics/RectF;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-virtual {p2, v1, v1, v1, v1}, Landroid/graphics/RectF;->set(FFFF)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lwm/d;->h:Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    add-int/lit8 v1, v1, -0x1

    .line 30
    .line 31
    :goto_0
    if-ltz v1, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Lwm/c;

    .line 38
    .line 39
    instance-of v3, v2, Lwm/e;

    .line 40
    .line 41
    if-eqz v3, :cond_1

    .line 42
    .line 43
    check-cast v2, Lwm/e;

    .line 44
    .line 45
    invoke-interface {v2, p2, v0, p3}, Lwm/e;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p2}, Landroid/graphics/RectF;->union(Landroid/graphics/RectF;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    add-int/lit8 v1, v1, -0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    return-void
.end method

.method public final f()Ljava/util/List;
    .locals 3

    .line 1
    iget-object v0, p0, Lwm/d;->j:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lwm/d;->j:Ljava/util/ArrayList;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    :goto_0
    iget-object v1, p0, Lwm/d;->h:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-ge v0, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Lwm/c;

    .line 26
    .line 27
    instance-of v2, v1, Lwm/l;

    .line 28
    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    iget-object v2, p0, Lwm/d;->j:Ljava/util/ArrayList;

    .line 32
    .line 33
    check-cast v1, Lwm/l;

    .line 34
    .line 35
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    iget-object p0, p0, Lwm/d;->j:Ljava/util/ArrayList;

    .line 42
    .line 43
    return-object p0
.end method
