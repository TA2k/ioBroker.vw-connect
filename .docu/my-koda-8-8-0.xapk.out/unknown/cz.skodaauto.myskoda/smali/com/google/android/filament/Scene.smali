.class public Lcom/google/android/filament/Scene;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Scene$EntityProcessor;
    }
.end annotation


# instance fields
.field private mIndirectLight:Lcom/google/android/filament/IndirectLight;

.field private mNativeObject:J

.field private mSkybox:Lcom/google/android/filament/Skybox;


# direct methods
.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/Scene;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method private static native nAddEntities(J[I)V
.end method

.method private static native nAddEntity(JI)V
.end method

.method private static native nGetEntities(J[II)Z
.end method

.method private static native nGetEntityCount(J)I
.end method

.method private static native nGetLightCount(J)I
.end method

.method private static native nGetRenderableCount(J)I
.end method

.method private static native nHasEntity(JI)Z
.end method

.method private static native nRemove(JI)V
.end method

.method private static native nRemoveEntities(J[I)V
.end method

.method private static native nSetIndirectLight(JJ)V
.end method

.method private static native nSetSkybox(JJ)V
.end method


# virtual methods
.method public addEntities([I)V
    .locals 2
    .param p1    # [I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Scene;->nAddEntities(J[I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public addEntity(I)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Scene;->nAddEntity(JI)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Scene;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public forEach(Lcom/google/android/filament/Scene$EntityProcessor;)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lcom/google/android/filament/Scene;->getEntities([I)[I

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    array-length v0, p0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    aget v2, p0, v1

    .line 11
    .line 12
    invoke-interface {p1, v2}, Lcom/google/android/filament/Scene$EntityProcessor;->process(I)V

    .line 13
    .line 14
    .line 15
    add-int/lit8 v1, v1, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    return-void
.end method

.method public getEntities()[I
    .locals 1

    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lcom/google/android/filament/Scene;->getEntities([I)[I

    move-result-object p0

    return-object p0
.end method

.method public getEntities([I)[I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getEntityCount()I

    move-result v0

    if-eqz p1, :cond_0

    .line 2
    array-length v1, p1

    if-ge v1, v0, :cond_1

    .line 3
    :cond_0
    new-array p1, v0, [I

    .line 4
    :cond_1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    move-result-wide v0

    array-length p0, p1

    invoke-static {v0, v1, p1, p0}, Lcom/google/android/filament/Scene;->nGetEntities(J[II)Z

    move-result p0

    if-eqz p0, :cond_2

    return-object p1

    .line 5
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Error retriving Scene\'s entities"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public getEntityCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Scene;->nGetEntityCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getIndirectLight()Lcom/google/android/filament/IndirectLight;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Scene;->mIndirectLight:Lcom/google/android/filament/IndirectLight;

    .line 2
    .line 3
    return-object p0
.end method

.method public getLightCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Scene;->nGetLightCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Scene;->mNativeObject:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Calling method on destroyed Scene"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getRenderableCount()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Scene;->nGetRenderableCount(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getSkybox()Lcom/google/android/filament/Skybox;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Scene;->mSkybox:Lcom/google/android/filament/Skybox;

    .line 2
    .line 3
    return-object p0
.end method

.method public hasEntity(I)Z
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Scene;->nHasEntity(JI)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public remove(I)V
    .locals 0
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/android/filament/Scene;->removeEntity(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public removeEntities([I)V
    .locals 2
    .param p1    # [I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Scene;->nRemoveEntities(J[I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public removeEntity(I)V
    .locals 2
    .param p1    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Scene;->nRemove(JI)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setIndirectLight(Lcom/google/android/filament/IndirectLight;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Scene;->mIndirectLight:Lcom/google/android/filament/IndirectLight;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p0, p0, Lcom/google/android/filament/Scene;->mIndirectLight:Lcom/google/android/filament/IndirectLight;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const-wide/16 p0, 0x0

    .line 17
    .line 18
    :goto_0
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Scene;->nSetIndirectLight(JJ)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public setSkybox(Lcom/google/android/filament/Skybox;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Scene;->mSkybox:Lcom/google/android/filament/Skybox;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p0, p0, Lcom/google/android/filament/Scene;->mSkybox:Lcom/google/android/filament/Skybox;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/Skybox;->getNativeObject()J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const-wide/16 p0, 0x0

    .line 17
    .line 18
    :goto_0
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Scene;->nSetSkybox(JJ)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
