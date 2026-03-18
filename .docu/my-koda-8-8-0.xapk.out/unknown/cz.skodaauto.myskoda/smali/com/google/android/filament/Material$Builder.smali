.class public Lcom/google/android/filament/Material$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Material;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation


# instance fields
.field private mBuffer:Ljava/nio/Buffer;

.field private mShBandCount:I

.field private mSize:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/android/filament/Material$Builder;->mShBandCount:I

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/Material;
    .locals 3

    .line 1
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-object p1, p0, Lcom/google/android/filament/Material$Builder;->mBuffer:Ljava/nio/Buffer;

    .line 6
    .line 7
    iget v2, p0, Lcom/google/android/filament/Material$Builder;->mSize:I

    .line 8
    .line 9
    iget p0, p0, Lcom/google/android/filament/Material$Builder;->mShBandCount:I

    .line 10
    .line 11
    invoke-static {v0, v1, v2, p1, p0}, Lcom/google/android/filament/Material;->a(JILjava/nio/Buffer;I)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    const-wide/16 v0, 0x0

    .line 16
    .line 17
    cmp-long v0, p0, v0

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    new-instance v0, Lcom/google/android/filament/Material;

    .line 22
    .line 23
    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/Material;-><init>(J)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "Couldn\'t create Material"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public payload(Ljava/nio/Buffer;I)Lcom/google/android/filament/Material$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Material$Builder;->mBuffer:Ljava/nio/Buffer;

    .line 2
    .line 3
    iput p2, p0, Lcom/google/android/filament/Material$Builder;->mSize:I

    .line 4
    .line 5
    return-object p0
.end method

.method public sphericalHarmonicsBandCount(I)Lcom/google/android/filament/Material$Builder;
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/Material$Builder;->mShBandCount:I

    .line 2
    .line 3
    return-object p0
.end method
