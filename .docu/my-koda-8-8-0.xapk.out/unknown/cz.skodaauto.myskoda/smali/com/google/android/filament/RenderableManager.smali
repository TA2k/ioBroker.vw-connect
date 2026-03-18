.class public Lcom/google/android/filament/RenderableManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/RenderableManager$PrimitiveType;,
        Lcom/google/android/filament/RenderableManager$Builder;
    }
.end annotation


# static fields
.field private static final LOG_TAG:Ljava/lang/String; = "Filament"

.field private static final sVertexAttributeValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;


# instance fields
.field private mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->values()[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/RenderableManager;->sVertexAttributeValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method public static bridge synthetic A(I)J
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/RenderableManager;->nCreateBuilder(I)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic B(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/RenderableManager;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic a(JII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nBuilderBlendOrder(JII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic b(JFFFFFF)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p7}, Lcom/google/android/filament/RenderableManager;->nBuilderBoundingBox(JFFFFFF)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(IJJ)Z
    .locals 0

    .line 1
    invoke-static {p1, p2, p3, p4, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderBuild(JJI)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic d(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->nBuilderCastShadows(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderChannel(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->nBuilderCulling(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->nBuilderEnableSkinningBuffers(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic h(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->nBuilderFog(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(JIIJJ)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p7}, Lcom/google/android/filament/RenderableManager;->nBuilderGeometry(JIIJJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic j(JIIJJII)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p9}, Lcom/google/android/filament/RenderableManager;->nBuilderGeometry(JIIJJII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k(JIIJJIIII)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p11}, Lcom/google/android/filament/RenderableManager;->nBuilderGeometry(JIIJJIIII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic l(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderGeometryType(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic m(JIZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nBuilderGlobalBlendOrderEnabled(JIZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic n(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderInstances(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBlendOrder(JII)V
.end method

.method private static native nBuilderBoundingBox(JFFFFFF)V
.end method

.method private static native nBuilderBuild(JJI)Z
.end method

.method private static native nBuilderCastShadows(JZ)V
.end method

.method private static native nBuilderChannel(JI)V
.end method

.method private static native nBuilderCulling(JZ)V
.end method

.method private static native nBuilderEnableSkinningBuffers(JZ)V
.end method

.method private static native nBuilderFog(JZ)V
.end method

.method private static native nBuilderGeometry(JIIJJ)V
.end method

.method private static native nBuilderGeometry(JIIJJII)V
.end method

.method private static native nBuilderGeometry(JIIJJIIII)V
.end method

.method private static native nBuilderGeometryType(JI)V
.end method

.method private static native nBuilderGlobalBlendOrderEnabled(JIZ)V
.end method

.method private static native nBuilderInstances(JI)V
.end method

.method private static native nBuilderLayerMask(JII)V
.end method

.method private static native nBuilderLightChannel(JIZ)V
.end method

.method private static native nBuilderMaterial(JIJ)V
.end method

.method private static native nBuilderMorphing(JI)V
.end method

.method private static native nBuilderMorphingStandard(JJ)V
.end method

.method private static native nBuilderPriority(JI)V
.end method

.method private static native nBuilderReceiveShadows(JZ)V
.end method

.method private static native nBuilderScreenSpaceContactShadows(JZ)V
.end method

.method private static native nBuilderSetMorphTargetBufferOffsetAt(JIII)V
.end method

.method private static native nBuilderSkinning(JI)V
.end method

.method private static native nBuilderSkinningBones(JILjava/nio/Buffer;I)I
.end method

.method private static native nBuilderSkinningBuffer(JJII)V
.end method

.method private static native nCreateBuilder(I)J
.end method

.method private static native nDestroy(JI)V
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetAxisAlignedBoundingBox(JI[F[F)V
.end method

.method private static native nGetEnabledAttributesAt(JII)I
.end method

.method private static native nGetFogEnabled(JI)Z
.end method

.method private static native nGetInstance(JI)I
.end method

.method private static native nGetLightChannel(JII)Z
.end method

.method private static native nGetMaterialInstanceAt(JII)J
.end method

.method private static native nGetMorphTargetCount(JI)I
.end method

.method private static native nGetPrimitiveCount(JI)I
.end method

.method private static native nHasComponent(JI)Z
.end method

.method private static native nIsShadowCaster(JI)Z
.end method

.method private static native nIsShadowReceiver(JI)Z
.end method

.method private static native nSetAxisAlignedBoundingBox(JIFFFFFF)V
.end method

.method private static native nSetBlendOrderAt(JIII)V
.end method

.method private static native nSetBonesAsMatrices(JILjava/nio/Buffer;III)I
.end method

.method private static native nSetBonesAsQuaternions(JILjava/nio/Buffer;III)I
.end method

.method private static native nSetCastShadows(JIZ)V
.end method

.method private static native nSetChannel(JII)V
.end method

.method private static native nSetCulling(JIZ)V
.end method

.method private static native nSetFogEnabled(JIZ)V
.end method

.method private static native nSetGeometryAt(JIIIJJII)V
.end method

.method private static native nSetGlobalBlendOrderEnabledAt(JIIZ)V
.end method

.method private static native nSetLayerMask(JIII)V
.end method

.method private static native nSetLightChannel(JIIZ)V
.end method

.method private static native nSetMaterialInstanceAt(JIIJ)V
.end method

.method private static native nSetMorphTargetBufferOffsetAt(JIIIJI)V
.end method

.method private static native nSetMorphWeights(JI[FI)V
.end method

.method private static native nSetPriority(JII)V
.end method

.method private static native nSetReceiveShadows(JIZ)V
.end method

.method private static native nSetScreenSpaceContactShadows(JIZ)V
.end method

.method private static native nSetSkinningBuffer(JIJII)V
.end method

.method public static bridge synthetic o(JII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nBuilderLayerMask(JII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic p(JIZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nBuilderLightChannel(JIZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic q(IJJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0, p3, p4}, Lcom/google/android/filament/RenderableManager;->nBuilderMaterial(JIJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic r(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderMorphing(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic s(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nBuilderMorphingStandard(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic t(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderPriority(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic u(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->nBuilderReceiveShadows(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic v(JZ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->nBuilderScreenSpaceContactShadows(JZ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic w(JIII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/RenderableManager;->nBuilderSetMorphTargetBufferOffsetAt(JIII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic x(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/RenderableManager;->nBuilderSkinning(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic y(JILjava/nio/Buffer;I)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/google/android/filament/RenderableManager;->nBuilderSkinningBones(JILjava/nio/Buffer;I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static bridge synthetic z(JIIJ)V
    .locals 2

    .line 1
    move-wide v0, p4

    .line 2
    move p4, p2

    .line 3
    move p5, p3

    .line 4
    move-wide p2, v0

    .line 5
    invoke-static/range {p0 .. p5}, Lcom/google/android/filament/RenderableManager;->nBuilderSkinningBuffer(JJII)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public destroy(I)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nDestroy(JI)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public getAxisAlignedBoundingBox(ILcom/google/android/filament/Box;)Lcom/google/android/filament/Box;
    .locals 3
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    new-instance p2, Lcom/google/android/filament/Box;

    .line 4
    .line 5
    invoke-direct {p2}, Lcom/google/android/filament/Box;-><init>()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 9
    .line 10
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-static {v0, v1, p1, p0, v2}, Lcom/google/android/filament/RenderableManager;->nGetAxisAlignedBoundingBox(JI[F[F)V

    .line 19
    .line 20
    .line 21
    return-object p2
.end method

.method public getEnabledAttributesAt(II)Ljava/util/Set;
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(II)",
            "Ljava/util/Set<",
            "Lcom/google/android/filament/VertexBuffer$VertexAttribute;",
            ">;"
        }
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nGetEnabledAttributesAt(JII)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const-class p1, Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 8
    .line 9
    invoke-static {p1}, Ljava/util/EnumSet;->noneOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    sget-object p2, Lcom/google/android/filament/RenderableManager;->sVertexAttributeValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    :goto_0
    array-length v1, p2

    .line 17
    if-ge v0, v1, :cond_1

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    shl-int/2addr v1, v0

    .line 21
    and-int/2addr v1, p0

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    aget-object v1, p2, v0

    .line 25
    .line 26
    invoke-interface {p1, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public getFogEnabled(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nGetFogEnabled(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getInstance(I)I
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param
    .annotation build Lcom/google/android/filament/EntityInstance;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nGetInstance(JI)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getLightChannel(II)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nGetLightChannel(JII)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getMaterialInstanceAt(II)Lcom/google/android/filament/MaterialInstance;
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nGetMaterialInstanceAt(JII)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    new-instance p2, Lcom/google/android/filament/MaterialInstance;

    .line 8
    .line 9
    invoke-direct {p2, p0, p1}, Lcom/google/android/filament/MaterialInstance;-><init>(J)V

    .line 10
    .line 11
    .line 12
    return-object p2
.end method

.method public getMorphTargetCount(I)I
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nGetMorphTargetCount(JI)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getNativeObject()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getPrimitiveCount(I)I
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nGetPrimitiveCount(JI)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public hasComponent(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nHasComponent(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public isShadowCaster(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nIsShadowCaster(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public isShadowReceiver(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/RenderableManager;->nIsShadowReceiver(JI)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public setAxisAlignedBoundingBox(ILcom/google/android/filament/Box;)V
    .locals 9
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v2, 0x0

    .line 8
    aget v3, p0, v2

    .line 9
    .line 10
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 v4, 0x1

    .line 15
    aget p0, p0, v4

    .line 16
    .line 17
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    const/4 v6, 0x2

    .line 22
    aget v5, v5, v6

    .line 23
    .line 24
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    aget v2, v7, v2

    .line 29
    .line 30
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 31
    .line 32
    .line 33
    move-result-object v7

    .line 34
    aget v7, v7, v4

    .line 35
    .line 36
    invoke-virtual {p2}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 37
    .line 38
    .line 39
    move-result-object p2

    .line 40
    aget v8, p2, v6

    .line 41
    .line 42
    move v4, p0

    .line 43
    move v6, v2

    .line 44
    move v2, p1

    .line 45
    invoke-static/range {v0 .. v8}, Lcom/google/android/filament/RenderableManager;->nSetAxisAlignedBoundingBox(JIFFFFFF)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public setBlendOrderAt(III)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nSetBlendOrderAt(JIII)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setBonesAsMatrices(ILjava/nio/Buffer;II)V
    .locals 7
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result v4

    .line 7
    move v2, p1

    .line 8
    move-object v3, p2

    .line 9
    move v5, p3

    .line 10
    move v6, p4

    .line 11
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/RenderableManager;->nSetBonesAsMatrices(JILjava/nio/Buffer;III)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-ltz p0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public setBonesAsQuaternions(ILjava/nio/Buffer;II)V
    .locals 7
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 4
    .line 5
    .line 6
    move-result v4

    .line 7
    move v2, p1

    .line 8
    move-object v3, p2

    .line 9
    move v5, p3

    .line 10
    move v6, p4

    .line 11
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/RenderableManager;->nSetBonesAsQuaternions(JILjava/nio/Buffer;III)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-ltz p0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/nio/BufferOverflowException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public setCastShadows(IZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetCastShadows(JIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setChannel(II)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetChannel(JII)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setCulling(IZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetCulling(JIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setFogEnabled(IZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetFogEnabled(JIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setGeometryAt(IILcom/google/android/filament/RenderableManager$PrimitiveType;Lcom/google/android/filament/VertexBuffer;Lcom/google/android/filament/IndexBuffer;)V
    .locals 11
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    invoke-virtual {p3}, Lcom/google/android/filament/RenderableManager$PrimitiveType;->getValue()I

    move-result v4

    invoke-virtual {p4}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    move-result-wide v5

    invoke-virtual/range {p5 .. p5}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    move-result-wide v7

    const/4 v9, 0x0

    .line 3
    invoke-virtual/range {p5 .. p5}, Lcom/google/android/filament/IndexBuffer;->getIndexCount()I

    move-result v10

    move v2, p1

    move v3, p2

    .line 4
    invoke-static/range {v0 .. v10}, Lcom/google/android/filament/RenderableManager;->nSetGeometryAt(JIIIJJII)V

    return-void
.end method

.method public setGeometryAt(IILcom/google/android/filament/RenderableManager$PrimitiveType;Lcom/google/android/filament/VertexBuffer;Lcom/google/android/filament/IndexBuffer;II)V
    .locals 11
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    invoke-virtual {p3}, Lcom/google/android/filament/RenderableManager$PrimitiveType;->getValue()I

    move-result v4

    invoke-virtual {p4}, Lcom/google/android/filament/VertexBuffer;->getNativeObject()J

    move-result-wide v5

    invoke-virtual/range {p5 .. p5}, Lcom/google/android/filament/IndexBuffer;->getNativeObject()J

    move-result-wide v7

    move v2, p1

    move v3, p2

    move/from16 v9, p6

    move/from16 v10, p7

    invoke-static/range {v0 .. v10}, Lcom/google/android/filament/RenderableManager;->nSetGeometryAt(JIIIJJII)V

    return-void
.end method

.method public setGlobalBlendOrderEnabledAt(IIZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nSetGlobalBlendOrderEnabledAt(JIIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setLayerMask(III)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nSetLayerMask(JIII)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setLightChannel(IIZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nSetLightChannel(JIIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setMaterialInstanceAt(IILcom/google/android/filament/MaterialInstance;)V
    .locals 8
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p3}, Lcom/google/android/filament/MaterialInstance;->getMaterial()Lcom/google/android/filament/Material;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lcom/google/android/filament/Material;->getRequiredAttributesAsInt()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-wide v1, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 10
    .line 11
    invoke-static {v1, v2, p1, p2}, Lcom/google/android/filament/RenderableManager;->nGetEnabledAttributesAt(JII)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    and-int/2addr v1, v0

    .line 16
    if-eq v1, v0, :cond_0

    .line 17
    .line 18
    invoke-static {}, Lcom/google/android/filament/Platform;->get()Lcom/google/android/filament/Platform;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, " of Renderable at "

    .line 23
    .line 24
    const-string v2, ": declared attributes "

    .line 25
    .line 26
    const-string v3, "setMaterialInstanceAt() on primitive "

    .line 27
    .line 28
    invoke-static {p2, p1, v3, v1, v2}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/RenderableManager;->getEnabledAttributesAt(II)Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v2, " do no satisfy required attributes "

    .line 40
    .line 41
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p3}, Lcom/google/android/filament/MaterialInstance;->getMaterial()Lcom/google/android/filament/Material;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v2}, Lcom/google/android/filament/Material;->getRequiredAttributes()Ljava/util/Set;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v0, v1}, Lcom/google/android/filament/Platform;->warn(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :cond_0
    iget-wide v2, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 63
    .line 64
    invoke-virtual {p3}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 65
    .line 66
    .line 67
    move-result-wide v6

    .line 68
    move v4, p1

    .line 69
    move v5, p2

    .line 70
    invoke-static/range {v2 .. v7}, Lcom/google/android/filament/RenderableManager;->nSetMaterialInstanceAt(JIIJ)V

    .line 71
    .line 72
    .line 73
    return-void
.end method

.method public setMorphTargetBufferOffsetAt(IIII)V
    .locals 8
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    const-wide/16 v5, 0x0

    .line 4
    .line 5
    move v2, p1

    .line 6
    move v3, p2

    .line 7
    move v4, p3

    .line 8
    move v7, p4

    .line 9
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/RenderableManager;->nSetMorphTargetBufferOffsetAt(JIIIJI)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setMorphWeights(I[FI)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/RenderableManager;->nSetMorphWeights(JI[FI)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setPriority(II)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetPriority(JII)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setReceiveShadows(IZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetReceiveShadows(JIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setScreenSpaceContactShadows(IZ)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderableManager;->nSetScreenSpaceContactShadows(JIZ)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public setSkinningBuffer(ILcom/google/android/filament/SkinningBuffer;II)V
    .locals 7
    .param p1    # I
        .annotation build Lcom/google/android/filament/EntityInstance;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderableManager;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p2}, Lcom/google/android/filament/SkinningBuffer;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v3

    .line 7
    move v2, p1

    .line 8
    move v5, p3

    .line 9
    move v6, p4

    .line 10
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/RenderableManager;->nSetSkinningBuffer(JIJII)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
