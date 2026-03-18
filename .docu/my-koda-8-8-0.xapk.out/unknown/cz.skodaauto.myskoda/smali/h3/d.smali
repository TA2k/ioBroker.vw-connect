.class public final Lh3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Laq/a;

.field public final b:Lg3/b;

.field public final c:Landroid/graphics/RenderNode;

.field public d:J

.field public e:Landroid/graphics/Paint;

.field public f:Landroid/graphics/Matrix;

.field public g:Z

.field public h:F

.field public i:I

.field public j:F

.field public k:F

.field public l:F

.field public m:F

.field public n:F

.field public o:J

.field public p:J

.field public q:F

.field public r:F

.field public s:F

.field public t:F

.field public u:Z

.field public v:Z

.field public w:Z

.field public x:Le3/o;

.field public y:I


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    new-instance v0, Laq/a;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    invoke-direct {v0, v1}, Laq/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lg3/b;

    .line 9
    .line 10
    invoke-direct {v1}, Lg3/b;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lh3/d;->a:Laq/a;

    .line 17
    .line 18
    iput-object v1, p0, Lh3/d;->b:Lg3/b;

    .line 19
    .line 20
    new-instance v0, Landroid/graphics/RenderNode;

    .line 21
    .line 22
    const-string v1, "graphicsLayer"

    .line 23
    .line 24
    invoke-direct {v0, v1}, Landroid/graphics/RenderNode;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 28
    .line 29
    const-wide/16 v1, 0x0

    .line 30
    .line 31
    iput-wide v1, p0, Lh3/d;->d:J

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-virtual {v0, v1}, Landroid/graphics/RenderNode;->setClipToBounds(Z)Z

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, v0, v1}, Lh3/d;->b(Landroid/graphics/RenderNode;I)V

    .line 38
    .line 39
    .line 40
    const/high16 v0, 0x3f800000    # 1.0f

    .line 41
    .line 42
    iput v0, p0, Lh3/d;->h:F

    .line 43
    .line 44
    const/4 v2, 0x3

    .line 45
    iput v2, p0, Lh3/d;->i:I

    .line 46
    .line 47
    iput v0, p0, Lh3/d;->j:F

    .line 48
    .line 49
    iput v0, p0, Lh3/d;->k:F

    .line 50
    .line 51
    sget-wide v2, Le3/s;->b:J

    .line 52
    .line 53
    iput-wide v2, p0, Lh3/d;->o:J

    .line 54
    .line 55
    iput-wide v2, p0, Lh3/d;->p:J

    .line 56
    .line 57
    const/high16 v0, 0x41000000    # 8.0f

    .line 58
    .line 59
    iput v0, p0, Lh3/d;->t:F

    .line 60
    .line 61
    iput v1, p0, Lh3/d;->y:I

    .line 62
    .line 63
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lh3/d;->u:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-boolean v3, p0, Lh3/d;->g:Z

    .line 8
    .line 9
    if-nez v3, :cond_0

    .line 10
    .line 11
    move v3, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v3, v1

    .line 14
    :goto_0
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-boolean v0, p0, Lh3/d;->g:Z

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    move v1, v2

    .line 21
    :cond_1
    iget-boolean v0, p0, Lh3/d;->v:Z

    .line 22
    .line 23
    iget-object v2, p0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 24
    .line 25
    if-eq v3, v0, :cond_2

    .line 26
    .line 27
    iput-boolean v3, p0, Lh3/d;->v:Z

    .line 28
    .line 29
    invoke-virtual {v2, v3}, Landroid/graphics/RenderNode;->setClipToBounds(Z)Z

    .line 30
    .line 31
    .line 32
    :cond_2
    iget-boolean v0, p0, Lh3/d;->w:Z

    .line 33
    .line 34
    if-eq v1, v0, :cond_3

    .line 35
    .line 36
    iput-boolean v1, p0, Lh3/d;->w:Z

    .line 37
    .line 38
    invoke-virtual {v2, v1}, Landroid/graphics/RenderNode;->setClipToOutline(Z)Z

    .line 39
    .line 40
    .line 41
    :cond_3
    return-void
.end method

.method public final b(Landroid/graphics/RenderNode;I)V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p2, v0, :cond_0

    .line 3
    .line 4
    iget-object p0, p0, Lh3/d;->e:Landroid/graphics/Paint;

    .line 5
    .line 6
    invoke-virtual {p1, v0, p0}, Landroid/graphics/RenderNode;->setUseCompositingLayer(ZLandroid/graphics/Paint;)Z

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, v0}, Landroid/graphics/RenderNode;->setHasOverlappingRendering(Z)Z

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    const/4 v1, 0x2

    .line 14
    const/4 v2, 0x0

    .line 15
    if-ne p2, v1, :cond_1

    .line 16
    .line 17
    iget-object p0, p0, Lh3/d;->e:Landroid/graphics/Paint;

    .line 18
    .line 19
    invoke-virtual {p1, v2, p0}, Landroid/graphics/RenderNode;->setUseCompositingLayer(ZLandroid/graphics/Paint;)Z

    .line 20
    .line 21
    .line 22
    invoke-virtual {p1, v2}, Landroid/graphics/RenderNode;->setHasOverlappingRendering(Z)Z

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    iget-object p0, p0, Lh3/d;->e:Landroid/graphics/Paint;

    .line 27
    .line 28
    invoke-virtual {p1, v2, p0}, Landroid/graphics/RenderNode;->setUseCompositingLayer(ZLandroid/graphics/Paint;)Z

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, v0}, Landroid/graphics/RenderNode;->setHasOverlappingRendering(Z)Z

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final c(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lh3/d;->u:Z

    .line 2
    .line 3
    invoke-virtual {p0}, Lh3/d;->a()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()V
    .locals 5

    .line 1
    iget v0, p0, Lh3/d;->y:I

    .line 2
    .line 3
    iget-object v1, p0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-ne v0, v2, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget v3, p0, Lh3/d;->i:I

    .line 10
    .line 11
    const/4 v4, 0x3

    .line 12
    if-ne v3, v4, :cond_2

    .line 13
    .line 14
    iget-object v3, p0, Lh3/d;->x:Le3/o;

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    invoke-virtual {p0, v1, v0}, Lh3/d;->b(Landroid/graphics/RenderNode;I)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_2
    :goto_0
    invoke-virtual {p0, v1, v2}, Lh3/d;->b(Landroid/graphics/RenderNode;I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
