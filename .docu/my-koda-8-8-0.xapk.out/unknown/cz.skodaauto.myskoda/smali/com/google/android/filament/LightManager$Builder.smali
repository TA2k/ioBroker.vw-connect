.class public Lcom/google/android/filament/LightManager$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/LightManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/LightManager$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/LightManager$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/LightManager$Type;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-static {p1}, Lcom/google/android/filament/LightManager;->t(I)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 13
    .line 14
    new-instance p1, Lcom/google/android/filament/LightManager$Builder$BuilderFinalizer;

    .line 15
    .line 16
    invoke-direct {p1, v0, v1}, Lcom/google/android/filament/LightManager$Builder$BuilderFinalizer;-><init>(J)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcom/google/android/filament/LightManager$Builder;->mFinalizer:Lcom/google/android/filament/LightManager$Builder$BuilderFinalizer;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;I)V
    .locals 2
    .param p2    # I
        .annotation build Lcom/google/android/filament/Entity;
        .end annotation
    .end param

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {p2, v0, v1, p0, p1}, Lcom/google/android/filament/LightManager;->b(IJJ)Z

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
    const-string p1, "Couldn\'t create Light component for entity "

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

.method public castLight(Z)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->c(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public castShadows(Z)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->d(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public color(FFF)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/LightManager;->e(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public direction(FFF)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/LightManager;->f(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public falloff(F)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->g(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public intensity(F)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->j(JF)V

    return-object p0
.end method

.method public intensity(FF)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->k(JFF)V

    return-object p0
.end method

.method public intensityCandela(F)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->l(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public lightChannel(IZ)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->m(JIZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public position(FFF)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2, p3}, Lcom/google/android/filament/LightManager;->n(JFFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public shadowOptions(Lcom/google/android/filament/LightManager$ShadowOptions;)Lcom/google/android/filament/LightManager$Builder;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-wide v2, v0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 6
    .line 7
    move-wide v4, v2

    .line 8
    iget v3, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->mapSize:I

    .line 9
    .line 10
    move-wide v5, v4

    .line 11
    iget v4, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowCascades:I

    .line 12
    .line 13
    move-wide v6, v5

    .line 14
    iget-object v5, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->cascadeSplitPositions:[F

    .line 15
    .line 16
    move-wide v7, v6

    .line 17
    iget v6, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->constantBias:F

    .line 18
    .line 19
    move-wide v8, v7

    .line 20
    iget v7, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->normalBias:F

    .line 21
    .line 22
    move-wide v9, v8

    .line 23
    iget v8, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowFar:F

    .line 24
    .line 25
    move-wide v10, v9

    .line 26
    iget v9, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowNearHint:F

    .line 27
    .line 28
    move-wide v11, v10

    .line 29
    iget v10, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowFarHint:F

    .line 30
    .line 31
    move-wide v12, v11

    .line 32
    iget-boolean v11, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->stable:Z

    .line 33
    .line 34
    move-wide v13, v12

    .line 35
    iget-boolean v12, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->lispsm:Z

    .line 36
    .line 37
    move-wide v14, v13

    .line 38
    iget v13, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->polygonOffsetConstant:F

    .line 39
    .line 40
    move-wide v15, v14

    .line 41
    iget v14, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->polygonOffsetSlope:F

    .line 42
    .line 43
    move-wide/from16 v16, v15

    .line 44
    .line 45
    iget-boolean v15, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->screenSpaceContactShadows:Z

    .line 46
    .line 47
    iget v2, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->stepCount:I

    .line 48
    .line 49
    iget v0, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->maxShadowDistance:F

    .line 50
    .line 51
    move/from16 v18, v0

    .line 52
    .line 53
    iget-boolean v0, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->elvsm:Z

    .line 54
    .line 55
    move/from16 v19, v0

    .line 56
    .line 57
    iget v0, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->blurWidth:F

    .line 58
    .line 59
    move/from16 v20, v0

    .line 60
    .line 61
    iget v0, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowBulbRadius:F

    .line 62
    .line 63
    iget-object v1, v1, Lcom/google/android/filament/LightManager$ShadowOptions;->transform:[F

    .line 64
    .line 65
    move-object/from16 v21, v1

    .line 66
    .line 67
    move/from16 v22, v20

    .line 68
    .line 69
    move/from16 v20, v0

    .line 70
    .line 71
    move-wide/from16 v23, v16

    .line 72
    .line 73
    move/from16 v16, v2

    .line 74
    .line 75
    move-wide/from16 v1, v23

    .line 76
    .line 77
    move/from16 v17, v18

    .line 78
    .line 79
    move/from16 v18, v19

    .line 80
    .line 81
    move/from16 v19, v22

    .line 82
    .line 83
    invoke-static/range {v1 .. v21}, Lcom/google/android/filament/LightManager;->o(JII[FFFFFFZZFFZIFZFF[F)V

    .line 84
    .line 85
    .line 86
    return-object p0
.end method

.method public spotLightCone(FF)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/LightManager;->p(JFF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public sunAngularRadius(F)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->a(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public sunHaloFalloff(F)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->h(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public sunHaloSize(F)Lcom/google/android/filament/LightManager$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/LightManager$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/LightManager;->i(JF)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
