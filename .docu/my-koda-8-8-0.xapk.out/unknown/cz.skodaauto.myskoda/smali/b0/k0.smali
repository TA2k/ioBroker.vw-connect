.class public final synthetic Lb0/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:Lb0/l0;

.field public final synthetic e:Lb0/a1;

.field public final synthetic f:Landroid/graphics/Matrix;

.field public final synthetic g:Lb0/a1;

.field public final synthetic h:Landroid/graphics/Rect;

.field public final synthetic i:Lb0/d0;

.field public final synthetic j:Ly4/h;


# direct methods
.method public synthetic constructor <init>(Lb0/l0;Lb0/a1;Landroid/graphics/Matrix;Lb0/a1;Landroid/graphics/Rect;Lb0/d0;Ly4/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb0/k0;->d:Lb0/l0;

    .line 5
    .line 6
    iput-object p2, p0, Lb0/k0;->e:Lb0/a1;

    .line 7
    .line 8
    iput-object p3, p0, Lb0/k0;->f:Landroid/graphics/Matrix;

    .line 9
    .line 10
    iput-object p4, p0, Lb0/k0;->g:Lb0/a1;

    .line 11
    .line 12
    iput-object p5, p0, Lb0/k0;->h:Landroid/graphics/Rect;

    .line 13
    .line 14
    iput-object p6, p0, Lb0/k0;->i:Lb0/d0;

    .line 15
    .line 16
    iput-object p7, p0, Lb0/k0;->j:Ly4/h;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 13

    .line 1
    iget-object v0, p0, Lb0/k0;->d:Lb0/l0;

    .line 2
    .line 3
    iget-object v1, p0, Lb0/k0;->e:Lb0/a1;

    .line 4
    .line 5
    iget-object v7, p0, Lb0/k0;->f:Landroid/graphics/Matrix;

    .line 6
    .line 7
    iget-object v9, p0, Lb0/k0;->g:Lb0/a1;

    .line 8
    .line 9
    iget-object v10, p0, Lb0/k0;->h:Landroid/graphics/Rect;

    .line 10
    .line 11
    iget-object v11, p0, Lb0/k0;->i:Lb0/d0;

    .line 12
    .line 13
    iget-object p0, p0, Lb0/k0;->j:Ly4/h;

    .line 14
    .line 15
    iget-boolean v2, v0, Lb0/l0;->x:Z

    .line 16
    .line 17
    if-eqz v2, :cond_3

    .line 18
    .line 19
    invoke-interface {v1}, Lb0/a1;->i0()Lb0/v0;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-interface {v2}, Lb0/v0;->b()Lh0/j2;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-interface {v1}, Lb0/a1;->i0()Lb0/v0;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-interface {v2}, Lb0/v0;->c()J

    .line 32
    .line 33
    .line 34
    move-result-wide v4

    .line 35
    iget-boolean v2, v0, Lb0/l0;->h:Z

    .line 36
    .line 37
    const/4 v12, 0x0

    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    move v6, v12

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget v0, v0, Lb0/l0;->e:I

    .line 43
    .line 44
    move v6, v0

    .line 45
    :goto_0
    invoke-interface {v1}, Lb0/a1;->i0()Lb0/v0;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-interface {v0}, Lb0/v0;->a()I

    .line 50
    .line 51
    .line 52
    move-result v8

    .line 53
    new-instance v2, Lb0/f;

    .line 54
    .line 55
    invoke-direct/range {v2 .. v8}, Lb0/f;-><init>(Lh0/j2;JILandroid/graphics/Matrix;I)V

    .line 56
    .line 57
    .line 58
    new-instance v0, Lb0/p1;

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    invoke-direct {v0, v9, v1, v2}, Lb0/p1;-><init>(Lb0/a1;Landroid/util/Size;Lb0/v0;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v10}, Landroid/graphics/Rect;->isEmpty()Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-nez v2, :cond_2

    .line 69
    .line 70
    new-instance v2, Landroid/graphics/Rect;

    .line 71
    .line 72
    invoke-direct {v2, v10}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    .line 73
    .line 74
    .line 75
    iget v3, v0, Lb0/p1;->i:I

    .line 76
    .line 77
    iget v4, v0, Lb0/p1;->j:I

    .line 78
    .line 79
    invoke-virtual {v2, v12, v12, v3, v4}, Landroid/graphics/Rect;->intersect(IIII)Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-nez v3, :cond_1

    .line 84
    .line 85
    invoke-virtual {v2}, Landroid/graphics/Rect;->setEmpty()V

    .line 86
    .line 87
    .line 88
    :cond_1
    iget-object v2, v0, Lb0/p1;->g:Ljava/lang/Object;

    .line 89
    .line 90
    monitor-enter v2

    .line 91
    :try_start_0
    monitor-exit v2

    .line 92
    goto :goto_1

    .line 93
    :catchall_0
    move-exception v0

    .line 94
    move-object p0, v0

    .line 95
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 96
    throw p0

    .line 97
    :cond_2
    :goto_1
    invoke-interface {v11, v0}, Lb0/d0;->d(Lb0/p1;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :cond_3
    new-instance v0, La8/r0;

    .line 105
    .line 106
    const-string v1, "ImageAnalysis is detached"

    .line 107
    .line 108
    invoke-direct {v0, v1}, La8/r0;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 112
    .line 113
    .line 114
    return-void
.end method
