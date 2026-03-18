.class public Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/IBLPrefilterContext;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "SpecularFilter"
.end annotation


# instance fields
.field private mNativeObject:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/utils/IBLPrefilterContext;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->getNativeObject()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->b(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;->mNativeObject:J

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public destroy()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->d(J)V

    .line 6
    .line 7
    .line 8
    const-wide/16 v0, 0x0

    .line 9
    .line 10
    iput-wide v0, p0, Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;->mNativeObject:J

    .line 11
    .line 12
    return-void
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed SpecularFilter"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public run(Lcom/google/android/filament/Texture;)Lcom/google/android/filament/Texture;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/IBLPrefilterContext$SpecularFilter;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/utils/IBLPrefilterContext;->f(JJ)J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    new-instance v0, Lcom/google/android/filament/Texture;

    .line 14
    .line 15
    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/Texture;-><init>(J)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method
