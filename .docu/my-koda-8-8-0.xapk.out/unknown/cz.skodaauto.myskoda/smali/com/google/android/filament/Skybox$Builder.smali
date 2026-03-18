.class public Lcom/google/android/filament/Skybox$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Skybox;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Skybox$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/Skybox$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/Skybox;->f()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/Skybox$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/Skybox$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/Skybox$Builder;->mFinalizer:Lcom/google/android/filament/Skybox$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/Skybox;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Skybox;->a(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide p0

    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    cmp-long v0, p0, v0

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Lcom/google/android/filament/Skybox;

    .line 18
    .line 19
    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/Skybox;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "Couldn\'t create Skybox"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public color(FFFF)Lcom/google/android/filament/Skybox$Builder;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    move v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Skybox;->b(JFFFF)V

    return-object p0
.end method

.method public color([F)Lcom/google/android/filament/Skybox$Builder;
    .locals 6

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    const/4 v2, 0x0

    aget v2, p1, v2

    const/4 v3, 0x1

    aget v3, p1, v3

    const/4 v4, 0x2

    aget v4, p1, v4

    const/4 v5, 0x3

    aget v5, p1, v5

    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Skybox;->b(JFFFF)V

    return-object p0
.end method

.method public environment(Lcom/google/android/filament/Texture;)Lcom/google/android/filament/Skybox$Builder;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Skybox;->c(JJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public intensity(F)Lcom/google/android/filament/Skybox$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Skybox;->d(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public showSun(Z)Lcom/google/android/filament/Skybox$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Skybox$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Skybox;->e(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
