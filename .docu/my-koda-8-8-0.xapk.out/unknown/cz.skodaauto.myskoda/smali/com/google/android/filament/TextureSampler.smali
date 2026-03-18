.class public Lcom/google/android/filament/TextureSampler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/TextureSampler$MinFilter;,
        Lcom/google/android/filament/TextureSampler$MagFilter;,
        Lcom/google/android/filament/TextureSampler$WrapMode;,
        Lcom/google/android/filament/TextureSampler$CompareFunction;,
        Lcom/google/android/filament/TextureSampler$CompareMode;,
        Lcom/google/android/filament/TextureSampler$EnumCache;
    }
.end annotation


# instance fields
.field mSampler:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$MinFilter;->LINEAR_MIPMAP_LINEAR:Lcom/google/android/filament/TextureSampler$MinFilter;

    sget-object v1, Lcom/google/android/filament/TextureSampler$MagFilter;->LINEAR:Lcom/google/android/filament/TextureSampler$MagFilter;

    sget-object v2, Lcom/google/android/filament/TextureSampler$WrapMode;->REPEAT:Lcom/google/android/filament/TextureSampler$WrapMode;

    invoke-direct {p0, v0, v1, v2}, Lcom/google/android/filament/TextureSampler;-><init>(Lcom/google/android/filament/TextureSampler$MinFilter;Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/TextureSampler$CompareMode;)V
    .locals 1

    .line 10
    sget-object v0, Lcom/google/android/filament/TextureSampler$CompareFunction;->LESS_EQUAL:Lcom/google/android/filament/TextureSampler$CompareFunction;

    invoke-direct {p0, p1, v0}, Lcom/google/android/filament/TextureSampler;-><init>(Lcom/google/android/filament/TextureSampler$CompareMode;Lcom/google/android/filament/TextureSampler$CompareFunction;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/TextureSampler$CompareMode;Lcom/google/android/filament/TextureSampler$CompareFunction;)V
    .locals 2

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, 0x0

    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 13
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    invoke-static {p1, p2}, Lcom/google/android/filament/TextureSampler;->nCreateCompareSampler(II)J

    move-result-wide p1

    iput-wide p1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/TextureSampler$MagFilter;)V
    .locals 1

    .line 2
    sget-object v0, Lcom/google/android/filament/TextureSampler$WrapMode;->CLAMP_TO_EDGE:Lcom/google/android/filament/TextureSampler$WrapMode;

    invoke-direct {p0, p1, v0}, Lcom/google/android/filament/TextureSampler;-><init>(Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;)V
    .locals 1

    .line 3
    invoke-static {p1}, Lcom/google/android/filament/TextureSampler;->minFilterFromMagFilter(Lcom/google/android/filament/TextureSampler$MagFilter;)Lcom/google/android/filament/TextureSampler$MinFilter;

    move-result-object v0

    invoke-direct {p0, v0, p1, p2}, Lcom/google/android/filament/TextureSampler;-><init>(Lcom/google/android/filament/TextureSampler$MinFilter;Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/TextureSampler$MinFilter;Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;)V
    .locals 6

    move-object v4, p3

    move-object v5, p3

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    .line 4
    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/TextureSampler;-><init>(Lcom/google/android/filament/TextureSampler$MinFilter;Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;Lcom/google/android/filament/TextureSampler$WrapMode;Lcom/google/android/filament/TextureSampler$WrapMode;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/TextureSampler$MinFilter;Lcom/google/android/filament/TextureSampler$MagFilter;Lcom/google/android/filament/TextureSampler$WrapMode;Lcom/google/android/filament/TextureSampler$WrapMode;Lcom/google/android/filament/TextureSampler$WrapMode;)V
    .locals 2

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, 0x0

    .line 6
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    .line 8
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    move-result p3

    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    move-result p4

    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    move-result p5

    .line 9
    invoke-static {p1, p2, p3, p4, p5}, Lcom/google/android/filament/TextureSampler;->nCreateSampler(IIIII)J

    move-result-wide p1

    iput-wide p1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    return-void
.end method

.method private static minFilterFromMagFilter(Lcom/google/android/filament/TextureSampler$MagFilter;)Lcom/google/android/filament/TextureSampler$MinFilter;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$1;->$SwitchMap$com$google$android$filament$TextureSampler$MagFilter:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    aget p0, v0, p0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_0

    .line 11
    .line 12
    sget-object p0, Lcom/google/android/filament/TextureSampler$MinFilter;->LINEAR:Lcom/google/android/filament/TextureSampler$MinFilter;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    sget-object p0, Lcom/google/android/filament/TextureSampler$MinFilter;->NEAREST:Lcom/google/android/filament/TextureSampler$MinFilter;

    .line 16
    .line 17
    return-object p0
.end method

.method private static native nCreateCompareSampler(II)J
.end method

.method private static native nCreateSampler(IIIII)J
.end method

.method private static native nGetAnisotropy(J)F
.end method

.method private static native nGetCompareFunction(J)I
.end method

.method private static native nGetCompareMode(J)I
.end method

.method private static native nGetMagFilter(J)I
.end method

.method private static native nGetMinFilter(J)I
.end method

.method private static native nGetWrapModeR(J)I
.end method

.method private static native nGetWrapModeS(J)I
.end method

.method private static native nGetWrapModeT(J)I
.end method

.method private static native nSetAnisotropy(JF)J
.end method

.method private static native nSetCompareFunction(JI)J
.end method

.method private static native nSetCompareMode(JI)J
.end method

.method private static native nSetMagFilter(JI)J
.end method

.method private static native nSetMinFilter(JI)J
.end method

.method private static native nSetWrapModeR(JI)J
.end method

.method private static native nSetWrapModeS(JI)J
.end method

.method private static native nSetWrapModeT(JI)J
.end method


# virtual methods
.method public getAnisotropy()F
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/TextureSampler;->nGetAnisotropy(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public getCompareFunction()Lcom/google/android/filament/TextureSampler$CompareFunction;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sCompareFunctionValues:[Lcom/google/android/filament/TextureSampler$CompareFunction;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetCompareFunction(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public getCompareMode()Lcom/google/android/filament/TextureSampler$CompareMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sCompareModeValues:[Lcom/google/android/filament/TextureSampler$CompareMode;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetCompareMode(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public getMagFilter()Lcom/google/android/filament/TextureSampler$MagFilter;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sMagFilterValues:[Lcom/google/android/filament/TextureSampler$MagFilter;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetMagFilter(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public getMinFilter()Lcom/google/android/filament/TextureSampler$MinFilter;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sMinFilterValues:[Lcom/google/android/filament/TextureSampler$MinFilter;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetMinFilter(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public getWrapModeR()Lcom/google/android/filament/TextureSampler$WrapMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sWrapModeValues:[Lcom/google/android/filament/TextureSampler$WrapMode;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetWrapModeR(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public getWrapModeS()Lcom/google/android/filament/TextureSampler$WrapMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sWrapModeValues:[Lcom/google/android/filament/TextureSampler$WrapMode;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetWrapModeS(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public getWrapModeT()Lcom/google/android/filament/TextureSampler$WrapMode;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sWrapModeValues:[Lcom/google/android/filament/TextureSampler$WrapMode;

    .line 2
    .line 3
    iget-wide v1, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 4
    .line 5
    invoke-static {v1, v2}, Lcom/google/android/filament/TextureSampler;->nGetWrapModeT(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    aget-object p0, v0, p0

    .line 10
    .line 11
    return-object p0
.end method

.method public setAnisotropy(F)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetAnisotropy(JF)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 8
    .line 9
    return-void
.end method

.method public setCompareFunction(Lcom/google/android/filament/TextureSampler$CompareFunction;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetCompareFunction(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method

.method public setCompareMode(Lcom/google/android/filament/TextureSampler$CompareMode;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetCompareMode(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method

.method public setMagFilter(Lcom/google/android/filament/TextureSampler$MagFilter;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetMagFilter(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method

.method public setMinFilter(Lcom/google/android/filament/TextureSampler$MinFilter;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetMinFilter(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method

.method public setWrapModeR(Lcom/google/android/filament/TextureSampler$WrapMode;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetWrapModeR(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method

.method public setWrapModeS(Lcom/google/android/filament/TextureSampler$WrapMode;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetWrapModeS(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method

.method public setWrapModeT(Lcom/google/android/filament/TextureSampler$WrapMode;)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/TextureSampler;->nSetWrapModeT(JI)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lcom/google/android/filament/TextureSampler;->mSampler:J

    .line 12
    .line 13
    return-void
.end method
