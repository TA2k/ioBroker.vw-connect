.class public Lcom/google/android/filament/RenderableManager$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/RenderableManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/RenderableManager$Builder$BuilderFinalizer;,
        Lcom/google/android/filament/RenderableManager$Builder$GeometryType;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/RenderableManager$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lcom/google/android/filament/RenderableManager;->A(I)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance p1, Lcom/google/android/filament/RenderableManager$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {p1, v0, v1}, Lcom/google/android/filament/RenderableManager$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lcom/google/android/filament/RenderableManager$Builder;->mFinalizer:Lcom/google/android/filament/RenderableManager$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public blendOrder(II)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->a(JII)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public boundingBox(Lcom/google/android/filament/Box;)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 10

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 4
    .line 5
    .line 6
    move-result-object v2

    .line 7
    const/4 v3, 0x0

    .line 8
    aget v2, v2, v3

    .line 9
    .line 10
    invoke-virtual {p1}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 11
    .line 12
    .line 13
    move-result-object v4

    .line 14
    const/4 v5, 0x1

    .line 15
    aget v4, v4, v5

    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 18
    .line 19
    .line 20
    move-result-object v6

    .line 21
    const/4 v7, 0x2

    .line 22
    aget v6, v6, v7

    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 25
    .line 26
    .line 27
    move-result-object v8

    .line 28
    aget v3, v8, v3

    .line 29
    .line 30
    invoke-virtual {p1}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    aget v5, v8, v5

    .line 35
    .line 36
    invoke-virtual {p1}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    aget v7, p1, v7

    .line 41
    .line 42
    move v9, v5

    .line 43
    move v5, v3

    .line 44
    move v3, v4

    .line 45
    move v4, v6

    .line 46
    move v6, v9

    .line 47
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/RenderableManager;->b(JFFFFFF)V

    .line 48
    .line 49
    .line 50
    return-object p0
.end method

.method public build(Lcom/google/android/filament/Engine;I)V
    .locals 2
    .param p2    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {p2, v0, v1, p0, p1}, Lcom/google/android/filament/RenderableManager;->c(IJJ)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "Couldn\'t create Renderable component for entity "

    .line 17
    .line 18
    const-string v0, ", see log."

    .line 19
    .line 20
    invoke-static {p1, p2, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public castShadows(Z)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->d(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public channel(I)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/RenderableManager;->e(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public culling(Z)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->f(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public enableSkinningBuffers(Z)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->g(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public fog(Z)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->h(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public geometry(ILcom/google/android/filament/RenderableManager$PrimitiveType;Lcom/google/android/filament/VertexBuffer;Lcom/google/android/filament/IndexBuffer;)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 8

    .line 7
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-virtual {p2}, Lcom/google/android/filament/RenderableManager$PrimitiveType;->getValue()I

    move-result v3

    .line 8
    invoke-virtual {p3}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    move-result-wide v4

    invoke-virtual {p4}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    move-result-wide v6

    move v2, p1

    .line 9
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/RenderableManager;->i(JIIJJ)V

    return-object p0
.end method

.method public geometry(ILcom/google/android/filament/RenderableManager$PrimitiveType;Lcom/google/android/filament/VertexBuffer;Lcom/google/android/filament/IndexBuffer;II)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 10

    .line 4
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-virtual {p2}, Lcom/google/android/filament/RenderableManager$PrimitiveType;->getValue()I

    move-result v3

    invoke-virtual {p3}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    move-result-wide v4

    .line 5
    invoke-virtual {p4}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    move-result-wide v6

    move v2, p1

    move v8, p5

    move/from16 v9, p6

    .line 6
    invoke-static/range {v0 .. v9}, Lcom/google/android/filament/RenderableManager;->j(JIIJJII)V

    return-object p0
.end method

.method public geometry(ILcom/google/android/filament/RenderableManager$PrimitiveType;Lcom/google/android/filament/VertexBuffer;Lcom/google/android/filament/IndexBuffer;IIII)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 12

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-virtual {p2}, Lcom/google/android/filament/RenderableManager$PrimitiveType;->getValue()I

    move-result v3

    invoke-virtual {p3}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    move-result-wide v4

    .line 2
    invoke-virtual/range {p4 .. p4}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    move-result-wide v6

    move v2, p1

    move/from16 v8, p5

    move/from16 v9, p6

    move/from16 v10, p7

    move/from16 v11, p8

    .line 3
    invoke-static/range {v0 .. v11}, Lcom/google/android/filament/RenderableManager;->k(JIIJJIIII)V

    return-object p0
.end method

.method public geometryType(Lcom/google/android/filament/RenderableManager$Builder$GeometryType;)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/RenderableManager;->l(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public globalBlendOrderEnabled(IZ)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->m(JIZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public instances(I)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/RenderableManager;->n(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public layerMask(II)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    and-int/lit16 p1, p1, 0xff

    .line 4
    .line 5
    and-int/lit16 p2, p2, 0xff

    .line 6
    .line 7
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->o(JII)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public lightChannel(IZ)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->p(JIZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public material(ILcom/google/android/filament/MaterialInstance;)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p2}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {p1, v0, v1, v2, v3}, Lcom/google/android/filament/RenderableManager;->q(IJJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public morphing(I)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-static {p1, v0, v1}, Lcom/google/android/filament/RenderableManager;->r(IJ)V

    return-object p0
.end method

.method public morphing(III)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 3
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->w(JIII)V

    return-object p0
.end method

.method public morphing(Lcom/google/android/filament/MorphTargetBuffer;)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 4

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-virtual {p1}, Lcom/google/android/filament/MorphTargetBuffer;->getNativeObject()J

    move-result-wide v2

    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/RenderableManager;->s(JJ)V

    return-object p0
.end method

.method public priority(I)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/RenderableManager;->t(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public receiveShadows(Z)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->u(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public screenSpaceContactShadows(Z)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->v(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public skinning(I)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 2

    .line 4
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-static {p1, v0, v1}, Lcom/google/android/filament/RenderableManager;->x(IJ)V

    return-object p0
.end method

.method public skinning(ILjava/nio/Buffer;)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 3

    .line 5
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    move-result v2

    invoke-static {v0, v1, p1, p2, v2}, Lcom/google/android/filament/RenderableManager;->y(JILjava/nio/Buffer;I)I

    move-result p1

    if-ltz p1, :cond_0

    return-object p0

    .line 6
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw p0
.end method

.method public skinning(Lcom/google/android/filament/SkinningBuffer;II)Lcom/google/android/filament/RenderableManager$Builder;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager$Builder;->mNativeBuilder:J

    if-eqz p1, :cond_0

    .line 2
    invoke-virtual {p1}, Lcom/google/android/filament/SkinningBuffer;->getNativeObject()J

    move-result-wide v2

    :goto_0
    move-wide v4, v2

    move v2, p2

    move v3, p3

    goto :goto_1

    :cond_0
    const-wide/16 v2, 0x0

    goto :goto_0

    .line 3
    :goto_1
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/RenderableManager;->z(JIIJ)V

    return-object p0
.end method
