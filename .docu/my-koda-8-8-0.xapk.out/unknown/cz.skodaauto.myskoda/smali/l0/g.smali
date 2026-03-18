.class public final Ll0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/k;


# instance fields
.field public final d:Lh0/d;

.field public final e:Lh0/d;

.field public final f:Lh0/r2;

.field public final g:Lb0/q;

.field public final h:Ljava/util/ArrayList;

.field public final i:Ljava/util/ArrayList;

.field public final j:Lz/a;

.field public k:Ljava/util/List;

.field public l:Landroid/util/Range;

.field public final m:Lh0/t;

.field public final n:Ljava/lang/Object;

.field public o:Z

.field public p:Lh0/q0;

.field public q:Lb0/z1;

.field public r:Lt0/e;

.field public final s:Lb0/x;

.field public final t:Lb0/x;

.field public final u:Lvp/y1;

.field public final v:Lc2/k;


# direct methods
.method public constructor <init>(Lh0/b0;Lh0/b0;Lh0/c;Lh0/c;Lb0/x;Lb0/x;Lz/a;Lc2/k;Lh0/r2;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ll0/g;->h:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 17
    .line 18
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 19
    .line 20
    iput-object v0, p0, Ll0/g;->k:Ljava/util/List;

    .line 21
    .line 22
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 23
    .line 24
    iput-object v0, p0, Ll0/g;->l:Landroid/util/Range;

    .line 25
    .line 26
    new-instance v0, Ljava/lang/Object;

    .line 27
    .line 28
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 32
    .line 33
    const/4 v0, 0x1

    .line 34
    iput-boolean v0, p0, Ll0/g;->o:Z

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    iput-object v0, p0, Ll0/g;->p:Lh0/q0;

    .line 38
    .line 39
    new-instance v1, Lvp/y1;

    .line 40
    .line 41
    const/16 v2, 0x12

    .line 42
    .line 43
    invoke-direct {v1, v2}, Lvp/y1;-><init>(I)V

    .line 44
    .line 45
    .line 46
    iput-object v1, p0, Ll0/g;->u:Lvp/y1;

    .line 47
    .line 48
    iget-object v1, p3, Lh0/c;->c:Lh0/t;

    .line 49
    .line 50
    iput-object v1, p0, Ll0/g;->m:Lh0/t;

    .line 51
    .line 52
    new-instance v2, Lh0/d;

    .line 53
    .line 54
    invoke-direct {v2, p1, p3}, Lh0/d;-><init>(Lh0/b0;Lh0/c;)V

    .line 55
    .line 56
    .line 57
    iput-object v2, p0, Ll0/g;->d:Lh0/d;

    .line 58
    .line 59
    if-eqz p2, :cond_0

    .line 60
    .line 61
    if-eqz p4, :cond_0

    .line 62
    .line 63
    new-instance p1, Lh0/d;

    .line 64
    .line 65
    invoke-direct {p1, p2, p4}, Lh0/d;-><init>(Lh0/b0;Lh0/c;)V

    .line 66
    .line 67
    .line 68
    iput-object p1, p0, Ll0/g;->e:Lh0/d;

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    iput-object v0, p0, Ll0/g;->e:Lh0/d;

    .line 72
    .line 73
    :goto_0
    iput-object p5, p0, Ll0/g;->s:Lb0/x;

    .line 74
    .line 75
    iput-object p6, p0, Ll0/g;->t:Lb0/x;

    .line 76
    .line 77
    iput-object p7, p0, Ll0/g;->j:Lz/a;

    .line 78
    .line 79
    iput-object p9, p0, Ll0/g;->f:Lh0/r2;

    .line 80
    .line 81
    if-eqz p4, :cond_1

    .line 82
    .line 83
    iget-object p1, p4, Lh0/w0;->a:Lh0/z;

    .line 84
    .line 85
    invoke-interface {p1}, Lh0/z;->f()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    :cond_1
    check-cast v1, Lh0/v;

    .line 90
    .line 91
    iget-object p1, v1, Lh0/v;->d:Lh0/h;

    .line 92
    .line 93
    const-string p2, "getCompatibilityId(...)"

    .line 94
    .line 95
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    iget-object p2, p3, Lh0/w0;->a:Lh0/z;

    .line 99
    .line 100
    invoke-interface {p2}, Lh0/z;->f()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    const-string p3, "getCameraId(...)"

    .line 105
    .line 106
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    filled-new-array {p2}, [Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p2

    .line 113
    invoke-static {p2}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    if-eqz v0, :cond_2

    .line 118
    .line 119
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    :cond_2
    new-instance p3, Lb0/q;

    .line 123
    .line 124
    invoke-direct {p3, p2, p1}, Lb0/q;-><init>(Ljava/util/ArrayList;Lh0/h;)V

    .line 125
    .line 126
    .line 127
    iput-object p3, p0, Ll0/g;->g:Lb0/q;

    .line 128
    .line 129
    iput-object p8, p0, Ll0/g;->v:Lc2/k;

    .line 130
    .line 131
    return-void
.end method

.method public static B(Lb0/z1;)Z
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_2

    .line 3
    .line 4
    iget-object v1, p0, Lb0/z1;->g:Lh0/o2;

    .line 5
    .line 6
    sget-object v2, Lh0/o2;->Z0:Lh0/g;

    .line 7
    .line 8
    invoke-interface {v1, v2}, Lh0/t1;->j(Lh0/g;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 15
    .line 16
    invoke-interface {p0}, Lh0/o2;->J()Lh0/q2;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object v1, Lh0/q2;->g:Lh0/q2;

    .line 21
    .line 22
    if-ne p0, v1, :cond_0

    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    :cond_0
    return v0

    .line 27
    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string p0, " UseCase does not have capture type."

    .line 36
    .line 37
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-string v1, "CameraUseCaseAdapter"

    .line 45
    .line 46
    invoke-static {v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    :cond_2
    return v0
.end method

.method public static D(Ljava/util/HashMap;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Ljava/util/Map$Entry;

    .line 20
    .line 21
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Lb0/z1;

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Ljava/util/Set;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    new-instance v2, Ljava/util/HashSet;

    .line 39
    .line 40
    invoke-direct {v2, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    const/4 v2, 0x0

    .line 45
    :goto_1
    iput-object v2, v1, Lb0/z1;->f:Ljava/util/HashSet;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    return-void
.end method

.method public static E(Ljava/util/ArrayList;Ljava/util/List;)Ljava/util/ArrayList;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lb0/z1;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-nez v2, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-static {v1}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    throw p0

    .line 41
    :cond_1
    return-object v0
.end method

.method public static m(Ljava/util/LinkedHashSet;Ld0/c;)Ljava/util/HashMap;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lb0/z1;

    .line 21
    .line 22
    iget-object v2, v1, Lb0/z1;->f:Ljava/util/HashSet;

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    iget-object v3, p1, Ld0/c;->a:Ljava/util/LinkedHashSet;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    move-object v3, v2

    .line 34
    :goto_1
    if-eqz v3, :cond_1

    .line 35
    .line 36
    new-instance v2, Ljava/util/HashSet;

    .line 37
    .line 38
    invoke-direct {v2, v3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    iput-object v2, v1, Lb0/z1;->f:Ljava/util/HashSet;

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    return-object v0
.end method

.method public static t(Landroid/graphics/Rect;Landroid/util/Size;)Landroid/graphics/Matrix;
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-lez v0, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    :goto_0
    const-string v1, "Cannot compute viewport crop rects zero sized sensor rect."

    .line 17
    .line 18
    invoke-static {v0, v1}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Landroid/graphics/RectF;

    .line 22
    .line 23
    invoke-direct {v0, p0}, Landroid/graphics/RectF;-><init>(Landroid/graphics/Rect;)V

    .line 24
    .line 25
    .line 26
    new-instance p0, Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-direct {p0}, Landroid/graphics/Matrix;-><init>()V

    .line 29
    .line 30
    .line 31
    new-instance v1, Landroid/graphics/RectF;

    .line 32
    .line 33
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    int-to-float v2, v2

    .line 38
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    int-to-float p1, p1

    .line 43
    const/4 v3, 0x0

    .line 44
    invoke-direct {v1, v3, v3, v2, p1}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 45
    .line 46
    .line 47
    sget-object p1, Landroid/graphics/Matrix$ScaleToFit;->CENTER:Landroid/graphics/Matrix$ScaleToFit;

    .line 48
    .line 49
    invoke-virtual {p0, v1, v0, p1}, Landroid/graphics/Matrix;->setRectToRect(Landroid/graphics/RectF;Landroid/graphics/RectF;Landroid/graphics/Matrix$ScaleToFit;)Z

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p0}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 53
    .line 54
    .line 55
    return-object p0
.end method

.method public static u()Lb0/u0;
    .locals 10

    .line 1
    new-instance v0, Lb0/f0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lb0/f0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sget-object v2, Ll0/k;->g1:Lh0/g;

    .line 8
    .line 9
    iget-object v0, v0, Lb0/f0;->b:Lh0/j1;

    .line 10
    .line 11
    const-string v3, "ImageCapture-Extra"

    .line 12
    .line 13
    invoke-virtual {v0, v2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    const/16 v2, 0x100

    .line 17
    .line 18
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const/16 v3, 0x20

    .line 23
    .line 24
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    sget-object v4, Lh0/y0;->g:Lh0/g;

    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    invoke-virtual {v0, v4, v5}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    check-cast v4, Ljava/lang/Integer;

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x3

    .line 39
    if-eqz v4, :cond_0

    .line 40
    .line 41
    sget-object v2, Lh0/z0;->C0:Lh0/g;

    .line 42
    .line 43
    invoke-virtual {v0, v2, v4}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    sget-object v4, Lb0/u0;->y:Lb0/r0;

    .line 48
    .line 49
    sget-object v4, Lh0/y0;->h:Lh0/g;

    .line 50
    .line 51
    invoke-virtual {v0, v4, v5}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v9

    .line 59
    invoke-static {v8, v9}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    if-eqz v8, :cond_1

    .line 64
    .line 65
    sget-object v2, Lh0/z0;->C0:Lh0/g;

    .line 66
    .line 67
    invoke-virtual {v0, v2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    invoke-virtual {v0, v4, v5}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v8

    .line 75
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 76
    .line 77
    .line 78
    move-result-object v9

    .line 79
    invoke-static {v8, v9}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v8

    .line 83
    if-eqz v8, :cond_2

    .line 84
    .line 85
    sget-object v4, Lh0/z0;->C0:Lh0/g;

    .line 86
    .line 87
    invoke-virtual {v0, v4, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    sget-object v3, Lh0/z0;->D0:Lh0/g;

    .line 91
    .line 92
    invoke-virtual {v0, v3, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_2
    invoke-virtual {v0, v4, v5}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    invoke-static {v3, v4}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-eqz v3, :cond_3

    .line 109
    .line 110
    sget-object v2, Lh0/z0;->C0:Lh0/g;

    .line 111
    .line 112
    const/16 v3, 0x1005

    .line 113
    .line 114
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-virtual {v0, v2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    sget-object v2, Lh0/z0;->E0:Lh0/g;

    .line 122
    .line 123
    sget-object v3, Lb0/y;->c:Lb0/y;

    .line 124
    .line 125
    invoke-virtual {v0, v2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    goto :goto_0

    .line 129
    :cond_3
    sget-object v3, Lh0/z0;->C0:Lh0/g;

    .line 130
    .line 131
    invoke-virtual {v0, v3, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    :goto_0
    new-instance v2, Lh0/y0;

    .line 135
    .line 136
    invoke-static {v0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    invoke-direct {v2, v3}, Lh0/y0;-><init>(Lh0/n1;)V

    .line 141
    .line 142
    .line 143
    invoke-static {v2}, Lh0/a1;->L(Lh0/a1;)V

    .line 144
    .line 145
    .line 146
    new-instance v3, Lb0/u0;

    .line 147
    .line 148
    invoke-direct {v3, v2}, Lb0/u0;-><init>(Lh0/y0;)V

    .line 149
    .line 150
    .line 151
    sget-object v2, Lh0/a1;->J0:Lh0/g;

    .line 152
    .line 153
    invoke-virtual {v0, v2, v5}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    check-cast v2, Landroid/util/Size;

    .line 158
    .line 159
    if-eqz v2, :cond_4

    .line 160
    .line 161
    new-instance v4, Landroid/util/Rational;

    .line 162
    .line 163
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 164
    .line 165
    .line 166
    move-result v8

    .line 167
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    invoke-direct {v4, v8, v2}, Landroid/util/Rational;-><init>(II)V

    .line 172
    .line 173
    .line 174
    :cond_4
    sget-object v2, Ll0/h;->f1:Lh0/g;

    .line 175
    .line 176
    invoke-static {}, Llp/hb;->c()Lj0/f;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    invoke-virtual {v0, v2, v4}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 185
    .line 186
    const-string v4, "The IO executor can\'t be null"

    .line 187
    .line 188
    invoke-static {v2, v4}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    sget-object v2, Lh0/y0;->f:Lh0/g;

    .line 192
    .line 193
    iget-object v4, v0, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 194
    .line 195
    invoke-virtual {v4, v2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v4

    .line 199
    if-eqz v4, :cond_8

    .line 200
    .line 201
    invoke-virtual {v0, v2}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    check-cast v2, Ljava/lang/Integer;

    .line 206
    .line 207
    if-eqz v2, :cond_7

    .line 208
    .line 209
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 210
    .line 211
    .line 212
    move-result v4

    .line 213
    if-eqz v4, :cond_5

    .line 214
    .line 215
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    if-eq v4, v1, :cond_5

    .line 220
    .line 221
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 222
    .line 223
    .line 224
    move-result v1

    .line 225
    if-eq v1, v7, :cond_5

    .line 226
    .line 227
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 228
    .line 229
    .line 230
    move-result v1

    .line 231
    if-ne v1, v6, :cond_7

    .line 232
    .line 233
    :cond_5
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    if-ne v1, v7, :cond_8

    .line 238
    .line 239
    sget-object v1, Lh0/y0;->l:Lh0/g;

    .line 240
    .line 241
    invoke-virtual {v0, v1, v5}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    if-eqz v0, :cond_6

    .line 246
    .line 247
    goto :goto_1

    .line 248
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 249
    .line 250
    const-string v1, "A ScreenFlash instance is required for FLASH_MODE_SCREEN but was not found. If value from PreviewView.getScreenFlash() is set to ImageCapture.setScreenFlash(), ensure PreviewView.setScreenFlashWindow() is invoked first."

    .line 251
    .line 252
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw v0

    .line 256
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 257
    .line 258
    new-instance v1, Ljava/lang/StringBuilder;

    .line 259
    .line 260
    const-string v3, "The flash mode is not allowed to set: "

    .line 261
    .line 262
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    throw v0

    .line 276
    :cond_8
    :goto_1
    return-object v3
.end method

.method public static x(Ljava/util/ArrayList;Lh0/r2;Lh0/r2;Landroid/util/Range;)Ljava/util/HashMap;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_4

    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lb0/z1;

    .line 21
    .line 22
    instance-of v2, v1, Lt0/e;

    .line 23
    .line 24
    const/4 v3, 0x0

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    move-object v2, v1

    .line 28
    check-cast v2, Lt0/e;

    .line 29
    .line 30
    new-instance v4, Lb0/h1;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-direct {v4, v5}, Lb0/h1;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v4}, Lb0/h1;->c()Lb0/k1;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-virtual {v4, v3, p1}, Lb0/k1;->f(ZLh0/r2;)Lh0/o2;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    if-nez v4, :cond_0

    .line 45
    .line 46
    const/4 v2, 0x0

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    invoke-static {v4}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    sget-object v5, Ll0/k;->h1:Lh0/g;

    .line 53
    .line 54
    iget-object v6, v4, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 55
    .line 56
    invoke-virtual {v6, v5}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2, v4}, Lt0/e;->l(Lh0/q0;)Lh0/n2;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    check-cast v2, La0/i;

    .line 64
    .line 65
    invoke-virtual {v2}, La0/i;->b()Lh0/o2;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-virtual {v1, v3, p1}, Lb0/z1;->f(ZLh0/r2;)Lh0/o2;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    :goto_1
    const/4 v4, 0x1

    .line 75
    invoke-virtual {v1, v4, p2}, Lb0/z1;->f(ZLh0/r2;)Lh0/o2;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    if-eqz v4, :cond_2

    .line 80
    .line 81
    invoke-static {v4}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    goto :goto_2

    .line 86
    :cond_2
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    :goto_2
    sget-object v5, Lh0/o2;->U0:Lh0/g;

    .line 91
    .line 92
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    invoke-virtual {v4, v5, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    sget-object v3, Lh0/k;->h:Landroid/util/Range;

    .line 100
    .line 101
    invoke-virtual {v3, p3}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    if-nez v3, :cond_3

    .line 106
    .line 107
    sget-object v3, Lh0/o2;->V0:Lh0/g;

    .line 108
    .line 109
    sget-object v5, Lh0/p0;->e:Lh0/p0;

    .line 110
    .line 111
    invoke-virtual {v4, v3, v5, p3}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    sget-object v3, Lh0/o2;->W0:Lh0/g;

    .line 115
    .line 116
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-virtual {v4, v3, v5}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_3
    invoke-virtual {v1, v4}, Lb0/z1;->l(Lh0/q0;)Lh0/n2;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    invoke-interface {v3}, Lh0/n2;->b()Lh0/o2;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    new-instance v4, Ll0/f;

    .line 130
    .line 131
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 132
    .line 133
    .line 134
    iput-object v2, v4, Ll0/f;->a:Lh0/o2;

    .line 135
    .line 136
    iput-object v3, v4, Ll0/f;->b:Lh0/o2;

    .line 137
    .line 138
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    goto/16 :goto_0

    .line 142
    .line 143
    :cond_4
    return-object v0
.end method


# virtual methods
.method public final A()V
    .locals 1

    .line 1
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Ll0/g;->m:Lh0/t;

    .line 5
    .line 6
    invoke-interface {p0}, Lh0/t;->r()V

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public final C(Ljava/util/ArrayList;)V
    .locals 4

    .line 1
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Lb0/z1;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    iput-object v3, v2, Lb0/z1;->f:Ljava/util/HashSet;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 25
    .line 26
    iget-object v2, p0, Ll0/g;->h:Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v1, v2}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {v1, p1}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Ll0/g;->e:Lh0/d;

    .line 35
    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    const/4 p1, 0x1

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/4 p1, 0x0

    .line 41
    :goto_1
    invoke-virtual {p0, v1, p1}, Ll0/g;->s(Ljava/util/LinkedHashSet;Z)Ll0/b;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-virtual {p0, p1}, Ll0/g;->f(Ll0/b;)V

    .line 46
    .line 47
    .line 48
    monitor-exit v0

    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    throw p0
.end method

.method public final a()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Ll0/g;->d:Lh0/d;

    .line 2
    .line 3
    iget-object p0, p0, Lh0/d;->e:Lh0/c;

    .line 4
    .line 5
    return-object p0
.end method

.method public final e(Ljava/util/Collection;Ld0/c;)V
    .locals 3

    .line 1
    const-string v0, "CameraUseCaseAdapter"

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "addUseCases: appUseCasesToAdd = "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v2, ", featureGroup = "

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-static {v0, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 29
    .line 30
    monitor-enter v0

    .line 31
    :try_start_0
    iget-object v1, p0, Ll0/g;->d:Lh0/d;

    .line 32
    .line 33
    iget-object v2, p0, Ll0/g;->m:Lh0/t;

    .line 34
    .line 35
    invoke-virtual {v1, v2}, Lh0/d;->i(Lh0/t;)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Ll0/g;->e:Lh0/d;

    .line 39
    .line 40
    if-eqz v1, :cond_0

    .line 41
    .line 42
    invoke-virtual {v1, v2}, Lh0/d;->i(Lh0/t;)V

    .line 43
    .line 44
    .line 45
    :cond_0
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 46
    .line 47
    iget-object v2, p0, Ll0/g;->h:Ljava/util/ArrayList;

    .line 48
    .line 49
    invoke-direct {v1, v2}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v1, p1}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 53
    .line 54
    .line 55
    invoke-static {v1, p2}, Ll0/g;->m(Ljava/util/LinkedHashSet;Ld0/c;)Ljava/util/HashMap;

    .line 56
    .line 57
    .line 58
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    :try_start_1
    iget-object p2, p0, Ll0/g;->e:Lh0/d;

    .line 60
    .line 61
    if-eqz p2, :cond_1

    .line 62
    .line 63
    const/4 p2, 0x1

    .line 64
    goto :goto_0

    .line 65
    :cond_1
    const/4 p2, 0x0

    .line 66
    :goto_0
    invoke-virtual {p0, v1, p2}, Ll0/g;->s(Ljava/util/LinkedHashSet;Z)Ll0/b;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    invoke-virtual {p0, p2}, Ll0/g;->f(Ll0/b;)V
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    .line 72
    .line 73
    :try_start_2
    monitor-exit v0

    .line 74
    return-void

    .line 75
    :catchall_0
    move-exception p0

    .line 76
    goto :goto_1

    .line 77
    :catch_0
    move-exception p0

    .line 78
    invoke-static {p1}, Ll0/g;->D(Ljava/util/HashMap;)V

    .line 79
    .line 80
    .line 81
    new-instance p1, Ll0/e;

    .line 82
    .line 83
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 84
    .line 85
    .line 86
    throw p1

    .line 87
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 88
    throw p0
.end method

.method public final f(Ll0/b;)V
    .locals 7

    .line 1
    iget-object v0, p1, Ll0/b;->i:Ll0/j;

    .line 2
    .line 3
    iget-object v0, v0, Ll0/j;->a:Ljava/util/Map;

    .line 4
    .line 5
    iget-object v1, p1, Ll0/b;->b:Ljava/util/ArrayList;

    .line 6
    .line 7
    iget-object v2, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v2

    .line 10
    :try_start_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Lb0/z1;

    .line 25
    .line 26
    iget-object v4, p0, Ll0/g;->d:Lh0/d;

    .line 27
    .line 28
    iget-object v4, v4, Lh0/d;->e:Lh0/c;

    .line 29
    .line 30
    iget-object v4, v4, Lh0/w0;->a:Lh0/z;

    .line 31
    .line 32
    invoke-interface {v4}, Lh0/z;->g()Landroid/graphics/Rect;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    invoke-interface {v0, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    check-cast v5, Lh0/k;

    .line 41
    .line 42
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    iget-object v5, v5, Lh0/k;->a:Landroid/util/Size;

    .line 46
    .line 47
    invoke-static {v4, v5}, Ll0/g;->t(Landroid/graphics/Rect;Landroid/util/Size;)Landroid/graphics/Matrix;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    invoke-virtual {v3, v4}, Lb0/z1;->z(Landroid/graphics/Matrix;)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto/16 :goto_7

    .line 57
    .line 58
    :cond_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    iget-object v0, p0, Ll0/g;->k:Ljava/util/List;

    .line 60
    .line 61
    iget-object v1, p1, Ll0/b;->b:Ljava/util/ArrayList;

    .line 62
    .line 63
    iget-object v2, p1, Ll0/b;->a:Ljava/util/LinkedHashSet;

    .line 64
    .line 65
    invoke-static {v1, v0}, Ll0/g;->E(Ljava/util/ArrayList;Ljava/util/List;)Ljava/util/ArrayList;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    new-instance v3, Ljava/util/ArrayList;

    .line 70
    .line 71
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 75
    .line 76
    .line 77
    invoke-static {v3, v0}, Ll0/g;->E(Ljava/util/ArrayList;Ljava/util/List;)Ljava/util/ArrayList;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-nez v1, :cond_1

    .line 86
    .line 87
    const-string v1, "CameraUseCaseAdapter"

    .line 88
    .line 89
    new-instance v2, Ljava/lang/StringBuilder;

    .line 90
    .line 91
    const-string v3, "Unused effects: "

    .line 92
    .line 93
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    invoke-static {v1, v0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    :cond_1
    iget-object v0, p1, Ll0/b;->e:Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-eqz v1, :cond_2

    .line 117
    .line 118
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    check-cast v1, Lb0/z1;

    .line 123
    .line 124
    iget-object v2, p0, Ll0/g;->d:Lh0/d;

    .line 125
    .line 126
    invoke-virtual {v1, v2}, Lb0/z1;->B(Lh0/b0;)V

    .line 127
    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_2
    iget-object v0, p0, Ll0/g;->d:Lh0/d;

    .line 131
    .line 132
    iget-object v1, p1, Ll0/b;->e:Ljava/util/ArrayList;

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Lh0/d;->o(Ljava/util/ArrayList;)V

    .line 135
    .line 136
    .line 137
    iget-object v0, p0, Ll0/g;->e:Lh0/d;

    .line 138
    .line 139
    if-eqz v0, :cond_4

    .line 140
    .line 141
    iget-object v0, p1, Ll0/b;->e:Ljava/util/ArrayList;

    .line 142
    .line 143
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-eqz v1, :cond_3

    .line 152
    .line 153
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    check-cast v1, Lb0/z1;

    .line 158
    .line 159
    iget-object v2, p0, Ll0/g;->e:Lh0/d;

    .line 160
    .line 161
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    invoke-virtual {v1, v2}, Lb0/z1;->B(Lh0/b0;)V

    .line 165
    .line 166
    .line 167
    goto :goto_2

    .line 168
    :cond_3
    iget-object v0, p0, Ll0/g;->e:Lh0/d;

    .line 169
    .line 170
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    iget-object v1, p1, Ll0/b;->e:Ljava/util/ArrayList;

    .line 174
    .line 175
    invoke-virtual {v0, v1}, Lh0/d;->o(Ljava/util/ArrayList;)V

    .line 176
    .line 177
    .line 178
    :cond_4
    iget-object v0, p1, Ll0/b;->e:Ljava/util/ArrayList;

    .line 179
    .line 180
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-eqz v0, :cond_9

    .line 185
    .line 186
    iget-object v0, p1, Ll0/b;->d:Ljava/util/ArrayList;

    .line 187
    .line 188
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    :cond_5
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 193
    .line 194
    .line 195
    move-result v1

    .line 196
    if-eqz v1, :cond_9

    .line 197
    .line 198
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    check-cast v1, Lb0/z1;

    .line 203
    .line 204
    iget-object v2, p1, Ll0/b;->i:Ll0/j;

    .line 205
    .line 206
    iget-object v2, v2, Ll0/j;->a:Ljava/util/Map;

    .line 207
    .line 208
    invoke-interface {v2, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v3

    .line 212
    if-eqz v3, :cond_5

    .line 213
    .line 214
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    check-cast v2, Lh0/k;

    .line 219
    .line 220
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    iget-object v2, v2, Lh0/k;->f:Lh0/q0;

    .line 224
    .line 225
    if-eqz v2, :cond_5

    .line 226
    .line 227
    iget-object v3, v1, Lb0/z1;->n:Lh0/z1;

    .line 228
    .line 229
    iget-object v4, v3, Lh0/z1;->g:Lh0/o0;

    .line 230
    .line 231
    iget-object v4, v4, Lh0/o0;->b:Lh0/n1;

    .line 232
    .line 233
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    invoke-interface {v2}, Lh0/q0;->d()Ljava/util/Set;

    .line 237
    .line 238
    .line 239
    move-result-object v5

    .line 240
    invoke-interface {v5}, Ljava/util/Set;->size()I

    .line 241
    .line 242
    .line 243
    move-result v5

    .line 244
    iget-object v3, v3, Lh0/z1;->g:Lh0/o0;

    .line 245
    .line 246
    iget-object v3, v3, Lh0/o0;->b:Lh0/n1;

    .line 247
    .line 248
    invoke-virtual {v3}, Lh0/n1;->d()Ljava/util/Set;

    .line 249
    .line 250
    .line 251
    move-result-object v3

    .line 252
    invoke-interface {v3}, Ljava/util/Set;->size()I

    .line 253
    .line 254
    .line 255
    move-result v3

    .line 256
    if-eq v5, v3, :cond_6

    .line 257
    .line 258
    goto :goto_4

    .line 259
    :cond_6
    invoke-interface {v2}, Lh0/q0;->d()Ljava/util/Set;

    .line 260
    .line 261
    .line 262
    move-result-object v3

    .line 263
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 264
    .line 265
    .line 266
    move-result-object v3

    .line 267
    :cond_7
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 268
    .line 269
    .line 270
    move-result v5

    .line 271
    if-eqz v5, :cond_5

    .line 272
    .line 273
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    check-cast v5, Lh0/g;

    .line 278
    .line 279
    iget-object v6, v4, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 280
    .line 281
    invoke-virtual {v6, v5}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v6

    .line 285
    if-eqz v6, :cond_8

    .line 286
    .line 287
    invoke-virtual {v4, v5}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    invoke-interface {v2, v5}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v5

    .line 295
    invoke-static {v6, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    move-result v5

    .line 299
    if-nez v5, :cond_7

    .line 300
    .line 301
    :cond_8
    :goto_4
    invoke-virtual {v1, v2}, Lb0/z1;->w(Lh0/q0;)Lh0/k;

    .line 302
    .line 303
    .line 304
    move-result-object v2

    .line 305
    iput-object v2, v1, Lb0/z1;->h:Lh0/k;

    .line 306
    .line 307
    iget-boolean v2, p0, Ll0/g;->o:Z

    .line 308
    .line 309
    if-eqz v2, :cond_5

    .line 310
    .line 311
    iget-object v2, p0, Ll0/g;->d:Lh0/d;

    .line 312
    .line 313
    invoke-virtual {v2, v1}, Lh0/d;->r(Lb0/z1;)V

    .line 314
    .line 315
    .line 316
    iget-object v2, p0, Ll0/g;->e:Lh0/d;

    .line 317
    .line 318
    if-eqz v2, :cond_5

    .line 319
    .line 320
    invoke-virtual {v2, v1}, Lh0/d;->r(Lb0/z1;)V

    .line 321
    .line 322
    .line 323
    goto/16 :goto_3

    .line 324
    .line 325
    :cond_9
    iget-object v0, p1, Ll0/b;->c:Ljava/util/ArrayList;

    .line 326
    .line 327
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 332
    .line 333
    .line 334
    move-result v1

    .line 335
    if-eqz v1, :cond_b

    .line 336
    .line 337
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    check-cast v1, Lb0/z1;

    .line 342
    .line 343
    iget-object v2, p1, Ll0/b;->h:Ljava/util/HashMap;

    .line 344
    .line 345
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v2

    .line 349
    check-cast v2, Ll0/f;

    .line 350
    .line 351
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    iget-object v3, p0, Ll0/g;->e:Lh0/d;

    .line 355
    .line 356
    if-eqz v3, :cond_a

    .line 357
    .line 358
    iget-object v4, p0, Ll0/g;->d:Lh0/d;

    .line 359
    .line 360
    iget-object v5, v2, Ll0/f;->a:Lh0/o2;

    .line 361
    .line 362
    iget-object v2, v2, Ll0/f;->b:Lh0/o2;

    .line 363
    .line 364
    invoke-virtual {v1, v4, v3, v5, v2}, Lb0/z1;->b(Lh0/b0;Lh0/b0;Lh0/o2;Lh0/o2;)V

    .line 365
    .line 366
    .line 367
    iget-object v2, p1, Ll0/b;->i:Ll0/j;

    .line 368
    .line 369
    iget-object v2, v2, Ll0/j;->a:Ljava/util/Map;

    .line 370
    .line 371
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v2

    .line 375
    check-cast v2, Lh0/k;

    .line 376
    .line 377
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 378
    .line 379
    .line 380
    iget-object v3, p1, Ll0/b;->j:Ll0/j;

    .line 381
    .line 382
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 383
    .line 384
    .line 385
    iget-object v3, v3, Ll0/j;->a:Ljava/util/Map;

    .line 386
    .line 387
    invoke-interface {v3, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v3

    .line 391
    check-cast v3, Lh0/k;

    .line 392
    .line 393
    invoke-virtual {v1, v2, v3}, Lb0/z1;->x(Lh0/k;Lh0/k;)Lh0/k;

    .line 394
    .line 395
    .line 396
    move-result-object v2

    .line 397
    iput-object v2, v1, Lb0/z1;->h:Lh0/k;

    .line 398
    .line 399
    goto :goto_5

    .line 400
    :cond_a
    iget-object v3, p0, Ll0/g;->d:Lh0/d;

    .line 401
    .line 402
    iget-object v4, v2, Ll0/f;->a:Lh0/o2;

    .line 403
    .line 404
    iget-object v2, v2, Ll0/f;->b:Lh0/o2;

    .line 405
    .line 406
    const/4 v5, 0x0

    .line 407
    invoke-virtual {v1, v3, v5, v4, v2}, Lb0/z1;->b(Lh0/b0;Lh0/b0;Lh0/o2;Lh0/o2;)V

    .line 408
    .line 409
    .line 410
    iget-object v2, p1, Ll0/b;->i:Ll0/j;

    .line 411
    .line 412
    iget-object v2, v2, Ll0/j;->a:Ljava/util/Map;

    .line 413
    .line 414
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v2

    .line 418
    check-cast v2, Lh0/k;

    .line 419
    .line 420
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 421
    .line 422
    .line 423
    invoke-virtual {v1, v2, v5}, Lb0/z1;->x(Lh0/k;Lh0/k;)Lh0/k;

    .line 424
    .line 425
    .line 426
    move-result-object v2

    .line 427
    iput-object v2, v1, Lb0/z1;->h:Lh0/k;

    .line 428
    .line 429
    goto :goto_5

    .line 430
    :cond_b
    iget-boolean v0, p0, Ll0/g;->o:Z

    .line 431
    .line 432
    if-eqz v0, :cond_c

    .line 433
    .line 434
    iget-object v0, p0, Ll0/g;->d:Lh0/d;

    .line 435
    .line 436
    iget-object v1, p1, Ll0/b;->c:Ljava/util/ArrayList;

    .line 437
    .line 438
    invoke-virtual {v0, v1}, Lh0/d;->k(Ljava/util/Collection;)V

    .line 439
    .line 440
    .line 441
    iget-object v0, p0, Ll0/g;->e:Lh0/d;

    .line 442
    .line 443
    if-eqz v0, :cond_c

    .line 444
    .line 445
    iget-object v1, p1, Ll0/b;->c:Ljava/util/ArrayList;

    .line 446
    .line 447
    invoke-virtual {v0, v1}, Lh0/d;->k(Ljava/util/Collection;)V

    .line 448
    .line 449
    .line 450
    :cond_c
    iget-object v0, p1, Ll0/b;->c:Ljava/util/ArrayList;

    .line 451
    .line 452
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 453
    .line 454
    .line 455
    move-result-object v0

    .line 456
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 457
    .line 458
    .line 459
    move-result v1

    .line 460
    if-eqz v1, :cond_d

    .line 461
    .line 462
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    check-cast v1, Lb0/z1;

    .line 467
    .line 468
    invoke-virtual {v1}, Lb0/z1;->q()V

    .line 469
    .line 470
    .line 471
    goto :goto_6

    .line 472
    :cond_d
    iget-object v0, p0, Ll0/g;->h:Ljava/util/ArrayList;

    .line 473
    .line 474
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 475
    .line 476
    .line 477
    iget-object v0, p0, Ll0/g;->h:Ljava/util/ArrayList;

    .line 478
    .line 479
    iget-object v1, p1, Ll0/b;->a:Ljava/util/LinkedHashSet;

    .line 480
    .line 481
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 482
    .line 483
    .line 484
    iget-object v0, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 485
    .line 486
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 487
    .line 488
    .line 489
    iget-object v0, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 490
    .line 491
    iget-object v1, p1, Ll0/b;->b:Ljava/util/ArrayList;

    .line 492
    .line 493
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 494
    .line 495
    .line 496
    iget-object v0, p1, Ll0/b;->g:Lb0/z1;

    .line 497
    .line 498
    iput-object v0, p0, Ll0/g;->q:Lb0/z1;

    .line 499
    .line 500
    iget-object p1, p1, Ll0/b;->f:Lt0/e;

    .line 501
    .line 502
    iput-object p1, p0, Ll0/g;->r:Lt0/e;

    .line 503
    .line 504
    return-void

    .line 505
    :goto_7
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 506
    throw p0
.end method

.method public final r()V
    .locals 4

    .line 1
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Ll0/g;->o:Z

    .line 5
    .line 6
    if-nez v1, :cond_4

    .line 7
    .line 8
    iget-object v1, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-object v1, p0, Ll0/g;->d:Lh0/d;

    .line 17
    .line 18
    iget-object v2, p0, Ll0/g;->m:Lh0/t;

    .line 19
    .line 20
    invoke-virtual {v1, v2}, Lh0/d;->i(Lh0/t;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Ll0/g;->e:Lh0/d;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    iget-object v2, p0, Ll0/g;->m:Lh0/t;

    .line 28
    .line 29
    invoke-virtual {v1, v2}, Lh0/d;->i(Lh0/t;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_5

    .line 35
    :cond_0
    :goto_0
    iget-object v1, p0, Ll0/g;->d:Lh0/d;

    .line 36
    .line 37
    iget-object v2, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v1, v2}, Lh0/d;->k(Ljava/util/Collection;)V

    .line 40
    .line 41
    .line 42
    iget-object v1, p0, Ll0/g;->e:Lh0/d;

    .line 43
    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    iget-object v2, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {v1, v2}, Lh0/d;->k(Ljava/util/Collection;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    iget-object v1, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 52
    .line 53
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    :try_start_1
    iget-object v2, p0, Ll0/g;->p:Lh0/q0;

    .line 55
    .line 56
    if-eqz v2, :cond_2

    .line 57
    .line 58
    iget-object v3, p0, Ll0/g;->d:Lh0/d;

    .line 59
    .line 60
    iget-object v3, v3, Lh0/d;->f:Lh0/b;

    .line 61
    .line 62
    invoke-virtual {v3, v2}, Lh0/b;->f(Lh0/q0;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :catchall_1
    move-exception p0

    .line 67
    goto :goto_3

    .line 68
    :cond_2
    :goto_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 69
    :try_start_2
    iget-object v1, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-eqz v2, :cond_3

    .line 80
    .line 81
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    check-cast v2, Lb0/z1;

    .line 86
    .line 87
    invoke-virtual {v2}, Lb0/z1;->q()V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_3
    const/4 v1, 0x1

    .line 92
    iput-boolean v1, p0, Ll0/g;->o:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 93
    .line 94
    goto :goto_4

    .line 95
    :goto_3
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 96
    :try_start_4
    throw p0

    .line 97
    :cond_4
    :goto_4
    monitor-exit v0

    .line 98
    return-void

    .line 99
    :goto_5
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 100
    throw p0
.end method

.method public final s(Ljava/util/LinkedHashSet;Z)Ll0/b;
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-virtual {v1}, Ll0/g;->A()V

    .line 6
    .line 7
    .line 8
    iget-object v3, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v3

    .line 11
    :try_start_0
    iget-object v0, v1, Ll0/g;->k:Ljava/util/List;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    if-nez v0, :cond_7

    .line 21
    .line 22
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    if-eqz v7, :cond_2

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v7

    .line 36
    check-cast v7, Lb0/z1;

    .line 37
    .line 38
    instance-of v8, v7, Lb0/u0;

    .line 39
    .line 40
    if-nez v8, :cond_1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    iget-object v7, v7, Lb0/z1;->g:Lh0/o2;

    .line 44
    .line 45
    sget-object v8, Lh0/y0;->h:Lh0/g;

    .line 46
    .line 47
    invoke-interface {v7, v8}, Lh0/t1;->j(Lh0/g;)Z

    .line 48
    .line 49
    .line 50
    move-result v9

    .line 51
    if-eqz v9, :cond_0

    .line 52
    .line 53
    invoke-interface {v7, v8}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    check-cast v7, Ljava/lang/Integer;

    .line 58
    .line 59
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    if-eq v7, v6, :cond_6

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    if-eqz v7, :cond_5

    .line 78
    .line 79
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    check-cast v7, Lb0/z1;

    .line 84
    .line 85
    instance-of v8, v7, Lb0/u0;

    .line 86
    .line 87
    if-nez v8, :cond_4

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_4
    iget-object v7, v7, Lb0/z1;->g:Lh0/o2;

    .line 91
    .line 92
    sget-object v8, Lh0/y0;->h:Lh0/g;

    .line 93
    .line 94
    invoke-interface {v7, v8}, Lh0/t1;->j(Lh0/g;)Z

    .line 95
    .line 96
    .line 97
    move-result v9

    .line 98
    if-eqz v9, :cond_3

    .line 99
    .line 100
    invoke-interface {v7, v8}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v7

    .line 104
    check-cast v7, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    if-ne v7, v4, :cond_3

    .line 114
    .line 115
    move v0, v6

    .line 116
    goto :goto_2

    .line 117
    :cond_5
    move v0, v5

    .line 118
    :goto_2
    if-nez v0, :cond_6

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 122
    .line 123
    const-string v1, "Ultra HDR image and Raw capture does not support for use with CameraEffect."

    .line 124
    .line 125
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw v0

    .line 129
    :catchall_0
    move-exception v0

    .line 130
    goto/16 :goto_1c

    .line 131
    .line 132
    :cond_7
    :goto_3
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 133
    if-nez p2, :cond_11

    .line 134
    .line 135
    invoke-virtual {v1}, Ll0/g;->A()V

    .line 136
    .line 137
    .line 138
    iget-object v0, v1, Ll0/g;->u:Lvp/y1;

    .line 139
    .line 140
    iget-object v3, v1, Ll0/g;->d:Lh0/d;

    .line 141
    .line 142
    iget-object v3, v3, Lh0/d;->e:Lh0/c;

    .line 143
    .line 144
    iget-object v3, v3, Lh0/w0;->a:Lh0/z;

    .line 145
    .line 146
    invoke-interface {v3}, Lh0/z;->f()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    iget-object v7, v0, Lvp/y1;->e:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v7, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;

    .line 153
    .line 154
    if-eqz v7, :cond_9

    .line 155
    .line 156
    const-string v0, "1"

    .line 157
    .line 158
    sget-object v7, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->a:Ljava/util/HashSet;

    .line 159
    .line 160
    const-string v7, "oneplus"

    .line 161
    .line 162
    sget-object v8, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 163
    .line 164
    invoke-virtual {v7, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 165
    .line 166
    .line 167
    move-result v7

    .line 168
    if-eqz v7, :cond_8

    .line 169
    .line 170
    const-string v7, "cph2583"

    .line 171
    .line 172
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 173
    .line 174
    invoke-virtual {v7, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 175
    .line 176
    .line 177
    move-result v7

    .line 178
    if-eqz v7, :cond_8

    .line 179
    .line 180
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-eqz v0, :cond_11

    .line 185
    .line 186
    invoke-static {v2}, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->b(Ljava/util/LinkedHashSet;)Z

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    if-eqz v0, :cond_11

    .line 191
    .line 192
    goto/16 :goto_6

    .line 193
    .line 194
    :cond_8
    const-string v7, "google"

    .line 195
    .line 196
    invoke-virtual {v7, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 197
    .line 198
    .line 199
    move-result v7

    .line 200
    if-eqz v7, :cond_11

    .line 201
    .line 202
    sget-object v7, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->a:Ljava/util/HashSet;

    .line 203
    .line 204
    sget-object v8, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 205
    .line 206
    invoke-virtual {v8}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v8

    .line 210
    invoke-virtual {v7, v8}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v7

    .line 214
    if-eqz v7, :cond_11

    .line 215
    .line 216
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v0

    .line 220
    if-eqz v0, :cond_11

    .line 221
    .line 222
    invoke-static {v2}, Landroidx/camera/core/internal/compat/quirk/ImageCaptureFailedForSpecificCombinationQuirk;->b(Ljava/util/LinkedHashSet;)Z

    .line 223
    .line 224
    .line 225
    move-result v0

    .line 226
    if-eqz v0, :cond_11

    .line 227
    .line 228
    goto/16 :goto_6

    .line 229
    .line 230
    :cond_9
    iget-object v0, v0, Lvp/y1;->f:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v0, Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;

    .line 233
    .line 234
    if-eqz v0, :cond_11

    .line 235
    .line 236
    sget-object v0, Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;->a:Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;

    .line 237
    .line 238
    const-string v0, "cameraId"

    .line 239
    .line 240
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    sget-object v0, Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;->a:Landroidx/camera/core/internal/compat/quirk/PreviewGreenTintQuirk;

    .line 244
    .line 245
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 246
    .line 247
    .line 248
    const-string v0, "motorola"

    .line 249
    .line 250
    sget-object v7, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 251
    .line 252
    invoke-virtual {v0, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    if-eqz v0, :cond_11

    .line 257
    .line 258
    const-string v0, "moto e20"

    .line 259
    .line 260
    sget-object v7, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 261
    .line 262
    invoke-virtual {v0, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 263
    .line 264
    .line 265
    move-result v0

    .line 266
    if-eqz v0, :cond_11

    .line 267
    .line 268
    const-string v0, "0"

    .line 269
    .line 270
    invoke-virtual {v3, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move-result v0

    .line 274
    if-eqz v0, :cond_11

    .line 275
    .line 276
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 277
    .line 278
    .line 279
    move-result v0

    .line 280
    if-eq v0, v4, :cond_a

    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_a
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 284
    .line 285
    .line 286
    move-result v0

    .line 287
    if-eqz v0, :cond_c

    .line 288
    .line 289
    :cond_b
    move v0, v5

    .line 290
    goto :goto_4

    .line 291
    :cond_c
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    :cond_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 296
    .line 297
    .line 298
    move-result v3

    .line 299
    if-eqz v3, :cond_b

    .line 300
    .line 301
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    check-cast v3, Lb0/z1;

    .line 306
    .line 307
    instance-of v3, v3, Lb0/k1;

    .line 308
    .line 309
    if-eqz v3, :cond_d

    .line 310
    .line 311
    move v0, v6

    .line 312
    :goto_4
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    if-eqz v3, :cond_f

    .line 317
    .line 318
    :cond_e
    move v3, v5

    .line 319
    goto :goto_5

    .line 320
    :cond_f
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 321
    .line 322
    .line 323
    move-result-object v3

    .line 324
    :cond_10
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 325
    .line 326
    .line 327
    move-result v7

    .line 328
    if-eqz v7, :cond_e

    .line 329
    .line 330
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v7

    .line 334
    check-cast v7, Lb0/z1;

    .line 335
    .line 336
    iget-object v8, v7, Lb0/z1;->g:Lh0/o2;

    .line 337
    .line 338
    sget-object v9, Lh0/o2;->Z0:Lh0/g;

    .line 339
    .line 340
    invoke-interface {v8, v9}, Lh0/t1;->j(Lh0/g;)Z

    .line 341
    .line 342
    .line 343
    move-result v8

    .line 344
    if-eqz v8, :cond_10

    .line 345
    .line 346
    iget-object v7, v7, Lb0/z1;->g:Lh0/o2;

    .line 347
    .line 348
    invoke-interface {v7}, Lh0/o2;->J()Lh0/q2;

    .line 349
    .line 350
    .line 351
    move-result-object v7

    .line 352
    sget-object v8, Lh0/q2;->g:Lh0/q2;

    .line 353
    .line 354
    if-ne v7, v8, :cond_10

    .line 355
    .line 356
    move v3, v6

    .line 357
    :goto_5
    if-eqz v0, :cond_11

    .line 358
    .line 359
    if-eqz v3, :cond_11

    .line 360
    .line 361
    :goto_6
    invoke-virtual {v1, v2, v6}, Ll0/g;->s(Ljava/util/LinkedHashSet;Z)Ll0/b;

    .line 362
    .line 363
    .line 364
    move-result-object v0

    .line 365
    return-object v0

    .line 366
    :cond_11
    :goto_7
    iget-object v7, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 367
    .line 368
    monitor-enter v7

    .line 369
    :try_start_1
    invoke-virtual/range {p0 .. p2}, Ll0/g;->y(Ljava/util/LinkedHashSet;Z)Ljava/util/HashSet;

    .line 370
    .line 371
    .line 372
    move-result-object v13

    .line 373
    invoke-virtual {v13}, Ljava/util/HashSet;->size()I

    .line 374
    .line 375
    .line 376
    move-result v0

    .line 377
    const/4 v3, 0x4

    .line 378
    if-ge v0, v4, :cond_12

    .line 379
    .line 380
    invoke-virtual {v1}, Ll0/g;->A()V

    .line 381
    .line 382
    .line 383
    monitor-exit v7

    .line 384
    :goto_8
    const/4 v0, 0x0

    .line 385
    goto/16 :goto_d

    .line 386
    .line 387
    :catchall_1
    move-exception v0

    .line 388
    goto/16 :goto_1b

    .line 389
    .line 390
    :cond_12
    iget-object v0, v1, Ll0/g;->r:Lt0/e;

    .line 391
    .line 392
    if-eqz v0, :cond_14

    .line 393
    .line 394
    iget-object v0, v0, Lt0/e;->q:Lt0/h;

    .line 395
    .line 396
    iget-object v0, v0, Lt0/h;->d:Ljava/util/HashSet;

    .line 397
    .line 398
    invoke-interface {v0, v13}, Ljava/util/Set;->equals(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    move-result v0

    .line 402
    if-eqz v0, :cond_14

    .line 403
    .line 404
    iget-object v0, v1, Ll0/g;->r:Lt0/e;

    .line 405
    .line 406
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 407
    .line 408
    .line 409
    invoke-virtual {v13}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 410
    .line 411
    .line 412
    move-result-object v8

    .line 413
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v8

    .line 417
    check-cast v8, Lb0/z1;

    .line 418
    .line 419
    iget-object v8, v8, Lb0/z1;->f:Ljava/util/HashSet;

    .line 420
    .line 421
    if-eqz v8, :cond_13

    .line 422
    .line 423
    new-instance v9, Ljava/util/HashSet;

    .line 424
    .line 425
    invoke-direct {v9, v8}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 426
    .line 427
    .line 428
    goto :goto_9

    .line 429
    :cond_13
    const/4 v9, 0x0

    .line 430
    :goto_9
    iput-object v9, v0, Lb0/z1;->f:Ljava/util/HashSet;

    .line 431
    .line 432
    iget-object v0, v1, Ll0/g;->r:Lt0/e;

    .line 433
    .line 434
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    monitor-exit v7

    .line 438
    goto/16 :goto_d

    .line 439
    .line 440
    :cond_14
    filled-new-array {v6, v4, v3}, [I

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    new-instance v8, Ljava/util/HashSet;

    .line 445
    .line 446
    invoke-direct {v8}, Ljava/util/HashSet;-><init>()V

    .line 447
    .line 448
    .line 449
    invoke-virtual {v13}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 450
    .line 451
    .line 452
    move-result-object v9

    .line 453
    :cond_15
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 454
    .line 455
    .line 456
    move-result v10

    .line 457
    if-eqz v10, :cond_1a

    .line 458
    .line 459
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v10

    .line 463
    check-cast v10, Lb0/z1;

    .line 464
    .line 465
    move v11, v5

    .line 466
    :goto_a
    const/4 v12, 0x3

    .line 467
    if-ge v11, v12, :cond_15

    .line 468
    .line 469
    aget v12, v0, v11

    .line 470
    .line 471
    invoke-virtual {v10}, Lb0/z1;->k()Ljava/util/Set;

    .line 472
    .line 473
    .line 474
    move-result-object v14

    .line 475
    invoke-interface {v14}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 476
    .line 477
    .line 478
    move-result-object v14

    .line 479
    :goto_b
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 480
    .line 481
    .line 482
    move-result v16

    .line 483
    if-eqz v16, :cond_17

    .line 484
    .line 485
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v16

    .line 489
    check-cast v16, Ljava/lang/Integer;

    .line 490
    .line 491
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Integer;->intValue()I

    .line 492
    .line 493
    .line 494
    move-result v15

    .line 495
    and-int v4, v12, v15

    .line 496
    .line 497
    if-ne v4, v15, :cond_16

    .line 498
    .line 499
    move v4, v6

    .line 500
    goto :goto_c

    .line 501
    :cond_16
    const/4 v4, 0x2

    .line 502
    goto :goto_b

    .line 503
    :cond_17
    move v4, v5

    .line 504
    :goto_c
    if-eqz v4, :cond_19

    .line 505
    .line 506
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 507
    .line 508
    .line 509
    move-result-object v4

    .line 510
    invoke-virtual {v8, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 511
    .line 512
    .line 513
    move-result v4

    .line 514
    if-eqz v4, :cond_18

    .line 515
    .line 516
    monitor-exit v7

    .line 517
    goto/16 :goto_8

    .line 518
    .line 519
    :cond_18
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 520
    .line 521
    .line 522
    move-result-object v4

    .line 523
    invoke-virtual {v8, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 524
    .line 525
    .line 526
    :cond_19
    add-int/lit8 v11, v11, 0x1

    .line 527
    .line 528
    const/4 v4, 0x2

    .line 529
    goto :goto_a

    .line 530
    :cond_1a
    new-instance v8, Lt0/e;

    .line 531
    .line 532
    iget-object v9, v1, Ll0/g;->d:Lh0/d;

    .line 533
    .line 534
    iget-object v10, v1, Ll0/g;->e:Lh0/d;

    .line 535
    .line 536
    iget-object v11, v1, Ll0/g;->s:Lb0/x;

    .line 537
    .line 538
    iget-object v12, v1, Ll0/g;->t:Lb0/x;

    .line 539
    .line 540
    iget-object v14, v1, Ll0/g;->f:Lh0/r2;

    .line 541
    .line 542
    invoke-direct/range {v8 .. v14}, Lt0/e;-><init>(Lh0/b0;Lh0/b0;Lb0/x;Lb0/x;Ljava/util/HashSet;Lh0/r2;)V

    .line 543
    .line 544
    .line 545
    monitor-exit v7
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 546
    move-object v0, v8

    .line 547
    :goto_d
    iget-object v4, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 548
    .line 549
    monitor-enter v4

    .line 550
    :try_start_2
    new-instance v7, Ljava/util/ArrayList;

    .line 551
    .line 552
    invoke-direct {v7, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 553
    .line 554
    .line 555
    if-eqz v0, :cond_1b

    .line 556
    .line 557
    invoke-virtual {v7, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 558
    .line 559
    .line 560
    iget-object v8, v0, Lt0/e;->q:Lt0/h;

    .line 561
    .line 562
    iget-object v8, v8, Lt0/h;->d:Ljava/util/HashSet;

    .line 563
    .line 564
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 565
    .line 566
    .line 567
    goto :goto_e

    .line 568
    :catchall_2
    move-exception v0

    .line 569
    goto/16 :goto_1a

    .line 570
    .line 571
    :cond_1b
    :goto_e
    iget-object v8, v1, Ll0/g;->n:Ljava/lang/Object;

    .line 572
    .line 573
    monitor-enter v8
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 574
    :try_start_3
    iget-object v9, v1, Ll0/g;->m:Lh0/t;

    .line 575
    .line 576
    sget-object v10, Lh0/t;->y0:Lh0/g;

    .line 577
    .line 578
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 579
    .line 580
    .line 581
    move-result-object v11

    .line 582
    invoke-interface {v9, v10, v11}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    move-result-object v9

    .line 586
    check-cast v9, Ljava/lang/Integer;

    .line 587
    .line 588
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 589
    .line 590
    .line 591
    move-result v9

    .line 592
    if-ne v9, v6, :cond_1c

    .line 593
    .line 594
    move v9, v6

    .line 595
    goto :goto_f

    .line 596
    :cond_1c
    move v9, v5

    .line 597
    :goto_f
    monitor-exit v8
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 598
    if-eqz v9, :cond_28

    .line 599
    .line 600
    :try_start_4
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 601
    .line 602
    .line 603
    move-result-object v8

    .line 604
    move v9, v5

    .line 605
    move v10, v9

    .line 606
    :cond_1d
    :goto_10
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 607
    .line 608
    .line 609
    move-result v11

    .line 610
    if-eqz v11, :cond_20

    .line 611
    .line 612
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 613
    .line 614
    .line 615
    move-result-object v11

    .line 616
    check-cast v11, Lb0/z1;

    .line 617
    .line 618
    instance-of v12, v11, Lb0/k1;

    .line 619
    .line 620
    if-nez v12, :cond_1f

    .line 621
    .line 622
    instance-of v12, v11, Lt0/e;

    .line 623
    .line 624
    if-eqz v12, :cond_1e

    .line 625
    .line 626
    goto :goto_11

    .line 627
    :cond_1e
    instance-of v11, v11, Lb0/u0;

    .line 628
    .line 629
    if-eqz v11, :cond_1d

    .line 630
    .line 631
    move v9, v6

    .line 632
    goto :goto_10

    .line 633
    :cond_1f
    :goto_11
    move v10, v6

    .line 634
    goto :goto_10

    .line 635
    :cond_20
    if-eqz v9, :cond_22

    .line 636
    .line 637
    if-nez v10, :cond_22

    .line 638
    .line 639
    iget-object v7, v1, Ll0/g;->q:Lb0/z1;

    .line 640
    .line 641
    instance-of v8, v7, Lb0/k1;

    .line 642
    .line 643
    if-eqz v8, :cond_21

    .line 644
    .line 645
    goto :goto_14

    .line 646
    :cond_21
    new-instance v7, Lb0/h1;

    .line 647
    .line 648
    invoke-direct {v7, v5}, Lb0/h1;-><init>(I)V

    .line 649
    .line 650
    .line 651
    const-string v8, "Preview-Extra"

    .line 652
    .line 653
    iget-object v9, v7, Lb0/h1;->b:Lh0/j1;

    .line 654
    .line 655
    sget-object v10, Ll0/k;->g1:Lh0/g;

    .line 656
    .line 657
    invoke-virtual {v9, v10, v8}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 658
    .line 659
    .line 660
    invoke-virtual {v7}, Lb0/h1;->c()Lb0/k1;

    .line 661
    .line 662
    .line 663
    move-result-object v7

    .line 664
    new-instance v8, Lj9/d;

    .line 665
    .line 666
    invoke-direct {v8, v3}, Lj9/d;-><init>(I)V

    .line 667
    .line 668
    .line 669
    invoke-virtual {v7, v8}, Lb0/k1;->E(Lb0/j1;)V

    .line 670
    .line 671
    .line 672
    goto :goto_14

    .line 673
    :cond_22
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 674
    .line 675
    .line 676
    move-result-object v3

    .line 677
    move v7, v5

    .line 678
    move v8, v7

    .line 679
    :cond_23
    :goto_12
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 680
    .line 681
    .line 682
    move-result v9

    .line 683
    if-eqz v9, :cond_26

    .line 684
    .line 685
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 686
    .line 687
    .line 688
    move-result-object v9

    .line 689
    check-cast v9, Lb0/z1;

    .line 690
    .line 691
    instance-of v10, v9, Lb0/k1;

    .line 692
    .line 693
    if-nez v10, :cond_25

    .line 694
    .line 695
    instance-of v10, v9, Lt0/e;

    .line 696
    .line 697
    if-eqz v10, :cond_24

    .line 698
    .line 699
    goto :goto_13

    .line 700
    :cond_24
    instance-of v9, v9, Lb0/u0;

    .line 701
    .line 702
    if-eqz v9, :cond_23

    .line 703
    .line 704
    move v8, v6

    .line 705
    goto :goto_12

    .line 706
    :cond_25
    :goto_13
    move v7, v6

    .line 707
    goto :goto_12

    .line 708
    :cond_26
    if-eqz v7, :cond_28

    .line 709
    .line 710
    if-nez v8, :cond_28

    .line 711
    .line 712
    iget-object v7, v1, Ll0/g;->q:Lb0/z1;

    .line 713
    .line 714
    instance-of v3, v7, Lb0/u0;

    .line 715
    .line 716
    if-eqz v3, :cond_27

    .line 717
    .line 718
    goto :goto_14

    .line 719
    :cond_27
    invoke-static {}, Ll0/g;->u()Lb0/u0;

    .line 720
    .line 721
    .line 722
    move-result-object v7

    .line 723
    goto :goto_14

    .line 724
    :cond_28
    const/4 v7, 0x0

    .line 725
    :goto_14
    monitor-exit v4
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 726
    new-instance v3, Ljava/util/ArrayList;

    .line 727
    .line 728
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 729
    .line 730
    .line 731
    if-eqz v7, :cond_29

    .line 732
    .line 733
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 734
    .line 735
    .line 736
    :cond_29
    if-eqz v0, :cond_2a

    .line 737
    .line 738
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 739
    .line 740
    .line 741
    iget-object v4, v0, Lt0/e;->q:Lt0/h;

    .line 742
    .line 743
    iget-object v4, v4, Lt0/h;->d:Ljava/util/HashSet;

    .line 744
    .line 745
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 746
    .line 747
    .line 748
    :cond_2a
    new-instance v11, Ljava/util/ArrayList;

    .line 749
    .line 750
    invoke-direct {v11, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 751
    .line 752
    .line 753
    iget-object v4, v1, Ll0/g;->i:Ljava/util/ArrayList;

    .line 754
    .line 755
    invoke-virtual {v11, v4}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 756
    .line 757
    .line 758
    new-instance v12, Ljava/util/ArrayList;

    .line 759
    .line 760
    invoke-direct {v12, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 761
    .line 762
    .line 763
    iget-object v4, v1, Ll0/g;->i:Ljava/util/ArrayList;

    .line 764
    .line 765
    invoke-virtual {v12, v4}, Ljava/util/ArrayList;->retainAll(Ljava/util/Collection;)Z

    .line 766
    .line 767
    .line 768
    move v4, v5

    .line 769
    new-instance v5, Ljava/util/ArrayList;

    .line 770
    .line 771
    iget-object v8, v1, Ll0/g;->i:Ljava/util/ArrayList;

    .line 772
    .line 773
    invoke-direct {v5, v8}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 774
    .line 775
    .line 776
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 777
    .line 778
    .line 779
    iget-object v8, v1, Ll0/g;->m:Lh0/t;

    .line 780
    .line 781
    sget-object v9, Lh0/t;->x0:Lh0/g;

    .line 782
    .line 783
    sget-object v10, Lh0/r2;->a:Lh0/p2;

    .line 784
    .line 785
    invoke-interface {v8, v9, v10}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v8

    .line 789
    check-cast v8, Lh0/r2;

    .line 790
    .line 791
    iget-object v9, v1, Ll0/g;->f:Lh0/r2;

    .line 792
    .line 793
    iget-object v10, v1, Ll0/g;->l:Landroid/util/Range;

    .line 794
    .line 795
    invoke-static {v11, v8, v9, v10}, Ll0/g;->x(Ljava/util/ArrayList;Lh0/r2;Lh0/r2;Landroid/util/Range;)Ljava/util/HashMap;

    .line 796
    .line 797
    .line 798
    move-result-object v17

    .line 799
    const/4 v8, 0x2

    .line 800
    new-array v9, v8, [Ljava/util/List;

    .line 801
    .line 802
    aput-object v11, v9, v4

    .line 803
    .line 804
    aput-object v12, v9, v6

    .line 805
    .line 806
    move v10, v4

    .line 807
    :goto_15
    if-ge v4, v8, :cond_2d

    .line 808
    .line 809
    aget-object v13, v9, v4

    .line 810
    .line 811
    invoke-interface {v13}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 812
    .line 813
    .line 814
    move-result-object v13

    .line 815
    :cond_2b
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 816
    .line 817
    .line 818
    move-result v14

    .line 819
    if-eqz v14, :cond_2c

    .line 820
    .line 821
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 822
    .line 823
    .line 824
    move-result-object v14

    .line 825
    check-cast v14, Lb0/z1;

    .line 826
    .line 827
    iget-object v14, v14, Lb0/z1;->f:Ljava/util/HashSet;

    .line 828
    .line 829
    if-eqz v14, :cond_2b

    .line 830
    .line 831
    move v10, v6

    .line 832
    :cond_2c
    if-eqz v10, :cond_2e

    .line 833
    .line 834
    :cond_2d
    move v15, v10

    .line 835
    goto :goto_16

    .line 836
    :cond_2e
    add-int/lit8 v4, v4, 0x1

    .line 837
    .line 838
    goto :goto_15

    .line 839
    :goto_16
    :try_start_5
    iget-object v8, v1, Ll0/g;->v:Lc2/k;

    .line 840
    .line 841
    invoke-virtual {v1}, Ll0/g;->w()I

    .line 842
    .line 843
    .line 844
    move-result v9

    .line 845
    iget-object v4, v1, Ll0/g;->d:Lh0/d;

    .line 846
    .line 847
    iget-object v10, v4, Lh0/d;->e:Lh0/c;

    .line 848
    .line 849
    iget-object v13, v1, Ll0/g;->m:Lh0/t;

    .line 850
    .line 851
    iget-object v14, v1, Ll0/g;->l:Landroid/util/Range;

    .line 852
    .line 853
    invoke-virtual/range {v8 .. v15}, Lc2/k;->p(ILh0/z;Ljava/util/ArrayList;Ljava/util/ArrayList;Lh0/t;Landroid/util/Range;Z)Ll0/j;

    .line 854
    .line 855
    .line 856
    move-result-object v4

    .line 857
    iget-object v8, v1, Ll0/g;->e:Lh0/d;

    .line 858
    .line 859
    if-eqz v8, :cond_2f

    .line 860
    .line 861
    iget-object v8, v1, Ll0/g;->v:Lc2/k;

    .line 862
    .line 863
    invoke-virtual {v1}, Ll0/g;->w()I

    .line 864
    .line 865
    .line 866
    move-result v9

    .line 867
    iget-object v10, v1, Ll0/g;->e:Lh0/d;

    .line 868
    .line 869
    invoke-static {v10}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 870
    .line 871
    .line 872
    iget-object v10, v10, Lh0/d;->e:Lh0/c;

    .line 873
    .line 874
    iget-object v13, v1, Ll0/g;->m:Lh0/t;

    .line 875
    .line 876
    iget-object v14, v1, Ll0/g;->l:Landroid/util/Range;

    .line 877
    .line 878
    invoke-virtual/range {v8 .. v15}, Lc2/k;->p(ILh0/z;Ljava/util/ArrayList;Ljava/util/ArrayList;Lh0/t;Landroid/util/Range;Z)Ll0/j;

    .line 879
    .line 880
    .line 881
    move-result-object v15
    :try_end_5
    .catch Ljava/lang/IllegalArgumentException; {:try_start_5 .. :try_end_5} :catch_0

    .line 882
    move-object v10, v15

    .line 883
    :goto_17
    move-object v6, v0

    .line 884
    goto :goto_18

    .line 885
    :catch_0
    move-exception v0

    .line 886
    goto :goto_19

    .line 887
    :cond_2f
    const/4 v10, 0x0

    .line 888
    goto :goto_17

    .line 889
    :goto_18
    new-instance v0, Ll0/b;

    .line 890
    .line 891
    move-object v1, v2

    .line 892
    move-object v2, v3

    .line 893
    move-object v9, v4

    .line 894
    move-object v3, v11

    .line 895
    move-object v4, v12

    .line 896
    move-object/from16 v8, v17

    .line 897
    .line 898
    invoke-direct/range {v0 .. v10}, Ll0/b;-><init>(Ljava/util/LinkedHashSet;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Lt0/e;Lb0/z1;Ljava/util/HashMap;Ll0/j;Ll0/j;)V

    .line 899
    .line 900
    .line 901
    return-object v0

    .line 902
    :goto_19
    if-nez p2, :cond_30

    .line 903
    .line 904
    invoke-virtual {v1}, Ll0/g;->A()V

    .line 905
    .line 906
    .line 907
    iget-object v3, v1, Ll0/g;->e:Lh0/d;

    .line 908
    .line 909
    if-nez v3, :cond_30

    .line 910
    .line 911
    invoke-virtual {v1, v2, v6}, Ll0/g;->s(Ljava/util/LinkedHashSet;Z)Ll0/b;

    .line 912
    .line 913
    .line 914
    move-result-object v0

    .line 915
    return-object v0

    .line 916
    :cond_30
    throw v0

    .line 917
    :catchall_3
    move-exception v0

    .line 918
    :try_start_6
    monitor-exit v8
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 919
    :try_start_7
    throw v0

    .line 920
    :goto_1a
    monitor-exit v4
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 921
    throw v0

    .line 922
    :goto_1b
    :try_start_8
    monitor-exit v7
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 923
    throw v0

    .line 924
    :goto_1c
    :try_start_9
    monitor-exit v3
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 925
    throw v0
.end method

.method public final v()V
    .locals 4

    .line 1
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Ll0/g;->o:Z

    .line 5
    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    iget-object v1, p0, Ll0/g;->d:Lh0/d;

    .line 9
    .line 10
    new-instance v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    iget-object v3, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v2}, Lh0/d;->o(Ljava/util/ArrayList;)V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Ll0/g;->e:Lh0/d;

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    new-instance v2, Ljava/util/ArrayList;

    .line 25
    .line 26
    iget-object v3, p0, Ll0/g;->i:Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v2}, Lh0/d;->o(Ljava/util/ArrayList;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_2

    .line 37
    :cond_0
    :goto_0
    iget-object v1, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 38
    .line 39
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    :try_start_1
    iget-object v2, p0, Ll0/g;->d:Lh0/d;

    .line 41
    .line 42
    iget-object v2, v2, Lh0/d;->f:Lh0/b;

    .line 43
    .line 44
    iget-object v3, v2, Lh0/b;->b:Lh0/y;

    .line 45
    .line 46
    invoke-interface {v3}, Lh0/y;->c()Lh0/q0;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iput-object v3, p0, Ll0/g;->p:Lh0/q0;

    .line 51
    .line 52
    invoke-virtual {v2}, Lh0/b;->g()V

    .line 53
    .line 54
    .line 55
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 56
    const/4 v1, 0x0

    .line 57
    :try_start_2
    iput-boolean v1, p0, Ll0/g;->o:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :catchall_1
    move-exception p0

    .line 61
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 62
    :try_start_4
    throw p0

    .line 63
    :cond_1
    :goto_1
    monitor-exit v0

    .line 64
    return-void

    .line 65
    :goto_2
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 66
    throw p0
.end method

.method public final w()I
    .locals 2

    .line 1
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Ll0/g;->j:Lz/a;

    .line 5
    .line 6
    invoke-virtual {p0}, Lz/a;->b()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v1, 0x2

    .line 11
    if-ne p0, v1, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    monitor-exit v0

    .line 15
    return p0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    monitor-exit v0

    .line 19
    const/4 p0, 0x0

    .line 20
    return p0

    .line 21
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method

.method public final y(Ljava/util/LinkedHashSet;Z)Ljava/util/HashSet;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    iget-object p0, p0, Ll0/g;->k:Ljava/util/List;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-nez v2, :cond_4

    .line 20
    .line 21
    if-eqz p2, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x3

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    :cond_1
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    if-eqz p2, :cond_3

    .line 36
    .line 37
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Lb0/z1;

    .line 42
    .line 43
    instance-of v1, p2, Lt0/e;

    .line 44
    .line 45
    xor-int/lit8 v1, v1, 0x1

    .line 46
    .line 47
    const-string v2, "Only support one level of sharing for now."

    .line 48
    .line 49
    invoke-static {v1, v2}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p2}, Lb0/z1;->k()Ljava/util/Set;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    :cond_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v2, :cond_1

    .line 65
    .line 66
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    check-cast v2, Ljava/lang/Integer;

    .line 71
    .line 72
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    and-int v3, p0, v2

    .line 77
    .line 78
    if-ne v3, v2, :cond_2

    .line 79
    .line 80
    invoke-virtual {v0, p2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_3
    return-object v0

    .line 85
    :catchall_0
    move-exception p0

    .line 86
    goto :goto_2

    .line 87
    :cond_4
    :try_start_1
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-nez p0, :cond_5

    .line 92
    .line 93
    const/4 p0, 0x0

    .line 94
    throw p0

    .line 95
    :cond_5
    new-instance p0, Ljava/lang/ClassCastException;

    .line 96
    .line 97
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :goto_2
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 102
    throw p0
.end method

.method public final z()Ljava/util/List;
    .locals 2

    .line 1
    iget-object v0, p0, Ll0/g;->n:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    new-instance v1, Ljava/util/ArrayList;

    .line 5
    .line 6
    iget-object p0, p0, Ll0/g;->h:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-object v1

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method
