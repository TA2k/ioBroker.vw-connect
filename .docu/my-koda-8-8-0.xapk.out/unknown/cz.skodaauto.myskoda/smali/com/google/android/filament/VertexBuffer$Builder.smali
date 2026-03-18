.class public Lcom/google/android/filament/VertexBuffer$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/VertexBuffer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/VertexBuffer$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/VertexBuffer$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/VertexBuffer;->g()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/VertexBuffer$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/VertexBuffer$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mFinalizer:Lcom/google/android/filament/VertexBuffer$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public attribute(Lcom/google/android/filament/VertexBuffer$VertexAttribute;ILcom/google/android/filament/VertexBuffer$AttributeType;)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 6

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    .line 4
    invoke-virtual/range {v0 .. v5}, Lcom/google/android/filament/VertexBuffer$Builder;->attribute(Lcom/google/android/filament/VertexBuffer$VertexAttribute;ILcom/google/android/filament/VertexBuffer$AttributeType;II)Lcom/google/android/filament/VertexBuffer$Builder;

    move-result-object p0

    return-object p0
.end method

.method public attribute(Lcom/google/android/filament/VertexBuffer$VertexAttribute;ILcom/google/android/filament/VertexBuffer$AttributeType;II)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 7

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    .line 2
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    move-result v4

    move v3, p2

    move v5, p4

    move v6, p5

    .line 3
    invoke-static/range {v0 .. v6}, Lcom/google/android/filament/VertexBuffer;->a(JIIIII)V

    return-object p0
.end method

.method public bufferCount(I)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/VertexBuffer;->b(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/VertexBuffer;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/VertexBuffer;->c(JJ)J

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
    new-instance v0, Lcom/google/android/filament/VertexBuffer;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {v0, p0, p1, v1}, Lcom/google/android/filament/VertexBuffer;-><init>(JI)V

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "Couldn\'t create VertexBuffer"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public enableBufferObjects(Z)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/VertexBuffer;->d(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public normalized(Lcom/google/android/filament/VertexBuffer$VertexAttribute;)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 3

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/4 v2, 0x1

    invoke-static {v0, v1, p1, v2}, Lcom/google/android/filament/VertexBuffer;->e(JIZ)V

    return-object p0
.end method

.method public normalized(Lcom/google/android/filament/VertexBuffer$VertexAttribute;Z)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 2

    .line 2
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/VertexBuffer;->e(JIZ)V

    return-object p0
.end method

.method public vertexCount(I)Lcom/google/android/filament/VertexBuffer$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/VertexBuffer$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/VertexBuffer;->f(IJ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method
