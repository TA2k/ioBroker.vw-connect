.class final Lcom/google/android/filament/Material$EnumCache;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Material;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "EnumCache"
.end annotation


# static fields
.field static final sBlendingModeValues:[Lcom/google/android/filament/Material$BlendingMode;

.field static final sCullingModeValues:[Lcom/google/android/filament/Material$CullingMode;

.field static final sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

.field static final sInterpolationValues:[Lcom/google/android/filament/Material$Interpolation;

.field static final sReflectionModeValues:[Lcom/google/android/filament/Material$ReflectionMode;

.field static final sRefractionModeValues:[Lcom/google/android/filament/Material$RefractionMode;

.field static final sRefractionTypeValues:[Lcom/google/android/filament/Material$RefractionType;

.field static final sShadingValues:[Lcom/google/android/filament/Material$Shading;

.field static final sVertexAttributeValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

.field static final sVertexDomainValues:[Lcom/google/android/filament/Material$VertexDomain;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/Material$Shading;->values()[Lcom/google/android/filament/Material$Shading;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sShadingValues:[Lcom/google/android/filament/Material$Shading;

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/filament/Material$Interpolation;->values()[Lcom/google/android/filament/Material$Interpolation;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sInterpolationValues:[Lcom/google/android/filament/Material$Interpolation;

    .line 12
    .line 13
    invoke-static {}, Lcom/google/android/filament/Material$BlendingMode;->values()[Lcom/google/android/filament/Material$BlendingMode;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sBlendingModeValues:[Lcom/google/android/filament/Material$BlendingMode;

    .line 18
    .line 19
    invoke-static {}, Lcom/google/android/filament/Material$RefractionMode;->values()[Lcom/google/android/filament/Material$RefractionMode;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sRefractionModeValues:[Lcom/google/android/filament/Material$RefractionMode;

    .line 24
    .line 25
    invoke-static {}, Lcom/google/android/filament/Material$RefractionType;->values()[Lcom/google/android/filament/Material$RefractionType;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sRefractionTypeValues:[Lcom/google/android/filament/Material$RefractionType;

    .line 30
    .line 31
    invoke-static {}, Lcom/google/android/filament/Material$ReflectionMode;->values()[Lcom/google/android/filament/Material$ReflectionMode;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sReflectionModeValues:[Lcom/google/android/filament/Material$ReflectionMode;

    .line 36
    .line 37
    invoke-static {}, Lcom/google/android/filament/Engine$FeatureLevel;->values()[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sFeatureLevelValues:[Lcom/google/android/filament/Engine$FeatureLevel;

    .line 42
    .line 43
    invoke-static {}, Lcom/google/android/filament/Material$VertexDomain;->values()[Lcom/google/android/filament/Material$VertexDomain;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sVertexDomainValues:[Lcom/google/android/filament/Material$VertexDomain;

    .line 48
    .line 49
    invoke-static {}, Lcom/google/android/filament/Material$CullingMode;->values()[Lcom/google/android/filament/Material$CullingMode;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sCullingModeValues:[Lcom/google/android/filament/Material$CullingMode;

    .line 54
    .line 55
    invoke-static {}, Lcom/google/android/filament/VertexBuffer$VertexAttribute;->values()[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sput-object v0, Lcom/google/android/filament/Material$EnumCache;->sVertexAttributeValues:[Lcom/google/android/filament/VertexBuffer$VertexAttribute;

    .line 60
    .line 61
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
