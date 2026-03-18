.class public Lcom/google/android/filament/Texture$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Texture;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Texture$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/Texture$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/Texture;->k()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/Texture$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/Texture$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/Texture$Builder;->mFinalizer:Lcom/google/android/filament/Texture$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/Texture;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Texture;->a(JJ)J

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
    new-instance v0, Lcom/google/android/filament/Texture;

    .line 18
    .line 19
    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/Texture;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "Couldn\'t create Texture"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public depth(I)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->b(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public format(Lcom/google/android/filament/Texture$InternalFormat;)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->c(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public height(I)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->d(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public importTexture(J)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/Texture;->e(JJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public levels(I)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->f(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public sampler(Lcom/google/android/filament/Texture$Sampler;)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->g(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public swizzle(Lcom/google/android/filament/Texture$Swizzle;Lcom/google/android/filament/Texture$Swizzle;Lcom/google/android/filament/Texture$Swizzle;Lcom/google/android/filament/Texture$Swizzle;)Lcom/google/android/filament/Texture$Builder;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Texture;->h(JIIII)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public usage(I)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->i(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public width(I)Lcom/google/android/filament/Texture$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Texture;->j(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
