.class public final synthetic Lb0/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly4/i;


# instance fields
.field public final synthetic d:Lb0/l0;

.field public final synthetic e:Ljava/util/concurrent/Executor;

.field public final synthetic f:Lb0/a1;

.field public final synthetic g:Landroid/graphics/Matrix;

.field public final synthetic h:Lb0/a1;

.field public final synthetic i:Landroid/graphics/Rect;

.field public final synthetic j:Lb0/d0;


# direct methods
.method public synthetic constructor <init>(Lb0/l0;Ljava/util/concurrent/Executor;Lb0/a1;Landroid/graphics/Matrix;Lb0/a1;Landroid/graphics/Rect;Lb0/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb0/j0;->d:Lb0/l0;

    .line 5
    .line 6
    iput-object p2, p0, Lb0/j0;->e:Ljava/util/concurrent/Executor;

    .line 7
    .line 8
    iput-object p3, p0, Lb0/j0;->f:Lb0/a1;

    .line 9
    .line 10
    iput-object p4, p0, Lb0/j0;->g:Landroid/graphics/Matrix;

    .line 11
    .line 12
    iput-object p5, p0, Lb0/j0;->h:Lb0/a1;

    .line 13
    .line 14
    iput-object p6, p0, Lb0/j0;->i:Landroid/graphics/Rect;

    .line 15
    .line 16
    iput-object p7, p0, Lb0/j0;->j:Lb0/d0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final h(Ly4/h;)Ljava/lang/Object;
    .locals 8

    .line 1
    new-instance v0, Lb0/k0;

    .line 2
    .line 3
    iget-object v1, p0, Lb0/j0;->d:Lb0/l0;

    .line 4
    .line 5
    iget-object v2, p0, Lb0/j0;->f:Lb0/a1;

    .line 6
    .line 7
    iget-object v3, p0, Lb0/j0;->g:Landroid/graphics/Matrix;

    .line 8
    .line 9
    iget-object v4, p0, Lb0/j0;->h:Lb0/a1;

    .line 10
    .line 11
    iget-object v5, p0, Lb0/j0;->i:Landroid/graphics/Rect;

    .line 12
    .line 13
    iget-object v6, p0, Lb0/j0;->j:Lb0/d0;

    .line 14
    .line 15
    move-object v7, p1

    .line 16
    invoke-direct/range {v0 .. v7}, Lb0/k0;-><init>(Lb0/l0;Lb0/a1;Landroid/graphics/Matrix;Lb0/a1;Landroid/graphics/Rect;Lb0/d0;Ly4/h;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lb0/j0;->e:Ljava/util/concurrent/Executor;

    .line 20
    .line 21
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 22
    .line 23
    .line 24
    const-string p0, "analyzeImage"

    .line 25
    .line 26
    return-object p0
.end method
