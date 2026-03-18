.class public final Lxm/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxm/a;


# instance fields
.field public final a:Ldn/b;

.field public final b:Ldn/b;

.field public final c:Lxm/f;

.field public final d:Lxm/f;

.field public final e:Lxm/f;

.field public final f:Lxm/f;

.field public final g:Lxm/f;

.field public h:Landroid/graphics/Matrix;


# direct methods
.method public constructor <init>(Ldn/b;Ldn/b;Landroidx/lifecycle/c1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxm/g;->b:Ldn/b;

    .line 5
    .line 6
    iput-object p2, p0, Lxm/g;->a:Ldn/b;

    .line 7
    .line 8
    iget-object p1, p3, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Lbn/a;

    .line 11
    .line 12
    invoke-virtual {p1}, Lbn/a;->p()Lxm/e;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    move-object v0, p1

    .line 17
    check-cast v0, Lxm/f;

    .line 18
    .line 19
    iput-object v0, p0, Lxm/g;->c:Lxm/f;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2, p1}, Ldn/b;->f(Lxm/e;)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p3, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Lbn/b;

    .line 30
    .line 31
    invoke-virtual {p1}, Lbn/b;->b0()Lxm/f;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lxm/g;->d:Lxm/f;

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p2, p1}, Ldn/b;->f(Lxm/e;)V

    .line 41
    .line 42
    .line 43
    iget-object p1, p3, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Lbn/b;

    .line 46
    .line 47
    invoke-virtual {p1}, Lbn/b;->b0()Lxm/f;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    iput-object p1, p0, Lxm/g;->e:Lxm/f;

    .line 52
    .line 53
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p2, p1}, Ldn/b;->f(Lxm/e;)V

    .line 57
    .line 58
    .line 59
    iget-object p1, p3, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p1, Lbn/b;

    .line 62
    .line 63
    invoke-virtual {p1}, Lbn/b;->b0()Lxm/f;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    iput-object p1, p0, Lxm/g;->f:Lxm/f;

    .line 68
    .line 69
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p2, p1}, Ldn/b;->f(Lxm/e;)V

    .line 73
    .line 74
    .line 75
    iget-object p1, p3, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p1, Lbn/b;

    .line 78
    .line 79
    invoke-virtual {p1}, Lbn/b;->b0()Lxm/f;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    iput-object p1, p0, Lxm/g;->g:Lxm/f;

    .line 84
    .line 85
    invoke-virtual {p1, p0}, Lxm/e;->a(Lxm/a;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p2, p1}, Ldn/b;->f(Lxm/e;)V

    .line 89
    .line 90
    .line 91
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lxm/g;->b:Ldn/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Ldn/b;->a()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final b(Landroid/graphics/Matrix;I)Lgn/a;
    .locals 6

    .line 1
    iget-object v0, p0, Lxm/g;->e:Lxm/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Lxm/f;->i()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0x3c8efa35

    .line 8
    .line 9
    .line 10
    mul-float/2addr v0, v1

    .line 11
    iget-object v1, p0, Lxm/g;->f:Lxm/f;

    .line 12
    .line 13
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ljava/lang/Float;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    float-to-double v2, v0

    .line 24
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 25
    .line 26
    .line 27
    move-result-wide v4

    .line 28
    double-to-float v0, v4

    .line 29
    mul-float/2addr v0, v1

    .line 30
    const-wide v4, 0x400921fb54442d18L    # Math.PI

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    add-double/2addr v2, v4

    .line 36
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    double-to-float v2, v2

    .line 41
    mul-float/2addr v2, v1

    .line 42
    iget-object v1, p0, Lxm/g;->g:Lxm/f;

    .line 43
    .line 44
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/lang/Float;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    iget-object v3, p0, Lxm/g;->c:Lxm/f;

    .line 55
    .line 56
    invoke-virtual {v3}, Lxm/e;->d()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    check-cast v3, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    iget-object v4, p0, Lxm/g;->d:Lxm/f;

    .line 67
    .line 68
    invoke-virtual {v4}, Lxm/e;->d()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    check-cast v4, Ljava/lang/Float;

    .line 73
    .line 74
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    int-to-float p2, p2

    .line 79
    mul-float/2addr v4, p2

    .line 80
    const/high16 p2, 0x437f0000    # 255.0f

    .line 81
    .line 82
    div-float/2addr v4, p2

    .line 83
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    invoke-static {v3}, Landroid/graphics/Color;->red(I)I

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    invoke-static {v3}, Landroid/graphics/Color;->green(I)I

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    invoke-static {v3}, Landroid/graphics/Color;->blue(I)I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    invoke-static {p2, v4, v5, v3}, Landroid/graphics/Color;->argb(IIII)I

    .line 100
    .line 101
    .line 102
    move-result p2

    .line 103
    new-instance v3, Lgn/a;

    .line 104
    .line 105
    const v4, 0x3ea8f5c3    # 0.33f

    .line 106
    .line 107
    .line 108
    mul-float/2addr v1, v4

    .line 109
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 110
    .line 111
    .line 112
    iput v1, v3, Lgn/a;->a:F

    .line 113
    .line 114
    iput v0, v3, Lgn/a;->b:F

    .line 115
    .line 116
    iput v2, v3, Lgn/a;->c:F

    .line 117
    .line 118
    iput p2, v3, Lgn/a;->d:I

    .line 119
    .line 120
    const/4 p2, 0x0

    .line 121
    iput-object p2, v3, Lgn/a;->e:[F

    .line 122
    .line 123
    invoke-virtual {v3, p1}, Lgn/a;->c(Landroid/graphics/Matrix;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, p0, Lxm/g;->h:Landroid/graphics/Matrix;

    .line 127
    .line 128
    if-nez p1, :cond_0

    .line 129
    .line 130
    new-instance p1, Landroid/graphics/Matrix;

    .line 131
    .line 132
    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    .line 133
    .line 134
    .line 135
    iput-object p1, p0, Lxm/g;->h:Landroid/graphics/Matrix;

    .line 136
    .line 137
    :cond_0
    iget-object p1, p0, Lxm/g;->a:Ldn/b;

    .line 138
    .line 139
    iget-object p1, p1, Ldn/b;->w:Lxm/n;

    .line 140
    .line 141
    invoke-virtual {p1}, Lxm/n;->d()Landroid/graphics/Matrix;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    iget-object p2, p0, Lxm/g;->h:Landroid/graphics/Matrix;

    .line 146
    .line 147
    invoke-virtual {p1, p2}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 148
    .line 149
    .line 150
    iget-object p0, p0, Lxm/g;->h:Landroid/graphics/Matrix;

    .line 151
    .line 152
    invoke-virtual {v3, p0}, Lgn/a;->c(Landroid/graphics/Matrix;)V

    .line 153
    .line 154
    .line 155
    return-object v3
.end method
