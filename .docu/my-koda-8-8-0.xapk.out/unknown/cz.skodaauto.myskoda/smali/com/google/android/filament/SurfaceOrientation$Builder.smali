.class public Lcom/google/android/filament/SurfaceOrientation$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/SurfaceOrientation;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation


# instance fields
.field private mNormals:Ljava/nio/Buffer;

.field private mNormalsStride:I

.field private mPositions:Ljava/nio/Buffer;

.field private mPositionsStride:I

.field private mTangents:Ljava/nio/Buffer;

.field private mTangentsStride:I

.field private mTexCoords:Ljava/nio/Buffer;

.field private mTexCoordsStride:I

.field private mTriangleCount:I

.field private mTrianglesUint16:Ljava/nio/Buffer;

.field private mTrianglesUint32:Ljava/nio/Buffer;

.field private mVertexCount:I


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public build()Lcom/google/android/filament/SurfaceOrientation;
    .locals 5

    .line 1
    invoke-static {}, Lcom/google/android/filament/SurfaceOrientation;->j()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mVertexCount:I

    .line 6
    .line 7
    invoke-static {v2, v0, v1}, Lcom/google/android/filament/SurfaceOrientation;->i(IJ)V

    .line 8
    .line 9
    .line 10
    iget v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTriangleCount:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lcom/google/android/filament/SurfaceOrientation;->e(IJ)V

    .line 13
    .line 14
    .line 15
    iget-object v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mNormals:Ljava/nio/Buffer;

    .line 16
    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/nio/Buffer;->remaining()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    iget v4, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mNormalsStride:I

    .line 24
    .line 25
    invoke-static {v0, v1, v3, v2, v4}, Lcom/google/android/filament/SurfaceOrientation;->b(JILjava/nio/Buffer;I)V

    .line 26
    .line 27
    .line 28
    :cond_0
    iget-object v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTangents:Ljava/nio/Buffer;

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {v2}, Ljava/nio/Buffer;->remaining()I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    iget v4, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTangentsStride:I

    .line 37
    .line 38
    invoke-static {v0, v1, v3, v2, v4}, Lcom/google/android/filament/SurfaceOrientation;->d(JILjava/nio/Buffer;I)V

    .line 39
    .line 40
    .line 41
    :cond_1
    iget-object v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTexCoords:Ljava/nio/Buffer;

    .line 42
    .line 43
    if-eqz v2, :cond_2

    .line 44
    .line 45
    invoke-virtual {v2}, Ljava/nio/Buffer;->remaining()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    iget v4, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTexCoordsStride:I

    .line 50
    .line 51
    invoke-static {v0, v1, v3, v2, v4}, Lcom/google/android/filament/SurfaceOrientation;->h(JILjava/nio/Buffer;I)V

    .line 52
    .line 53
    .line 54
    :cond_2
    iget-object v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mPositions:Ljava/nio/Buffer;

    .line 55
    .line 56
    if-eqz v2, :cond_3

    .line 57
    .line 58
    invoke-virtual {v2}, Ljava/nio/Buffer;->remaining()I

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    iget v4, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mPositionsStride:I

    .line 63
    .line 64
    invoke-static {v0, v1, v3, v2, v4}, Lcom/google/android/filament/SurfaceOrientation;->c(JILjava/nio/Buffer;I)V

    .line 65
    .line 66
    .line 67
    :cond_3
    iget-object v2, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTrianglesUint16:Ljava/nio/Buffer;

    .line 68
    .line 69
    if-eqz v2, :cond_4

    .line 70
    .line 71
    invoke-virtual {v2}, Ljava/nio/Buffer;->remaining()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/SurfaceOrientation;->f(JLjava/nio/Buffer;I)V

    .line 76
    .line 77
    .line 78
    :cond_4
    iget-object p0, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTrianglesUint32:Ljava/nio/Buffer;

    .line 79
    .line 80
    if-eqz p0, :cond_5

    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/nio/Buffer;->remaining()I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    invoke-static {v0, v1, p0, v2}, Lcom/google/android/filament/SurfaceOrientation;->g(JLjava/nio/Buffer;I)V

    .line 87
    .line 88
    .line 89
    :cond_5
    invoke-static {v0, v1}, Lcom/google/android/filament/SurfaceOrientation;->a(J)J

    .line 90
    .line 91
    .line 92
    move-result-wide v2

    .line 93
    invoke-static {v0, v1}, Lcom/google/android/filament/SurfaceOrientation;->k(J)V

    .line 94
    .line 95
    .line 96
    const-wide/16 v0, 0x0

    .line 97
    .line 98
    cmp-long p0, v2, v0

    .line 99
    .line 100
    if-eqz p0, :cond_6

    .line 101
    .line 102
    new-instance p0, Lcom/google/android/filament/SurfaceOrientation;

    .line 103
    .line 104
    const/4 v0, 0x0

    .line 105
    invoke-direct {p0, v2, v3, v0}, Lcom/google/android/filament/SurfaceOrientation;-><init>(JI)V

    .line 106
    .line 107
    .line 108
    return-object p0

    .line 109
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    const-string v0, "Could not create SurfaceOrientation"

    .line 112
    .line 113
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw p0
.end method

.method public normals(Ljava/nio/Buffer;)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mNormals:Ljava/nio/Buffer;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mNormalsStride:I

    .line 5
    .line 6
    return-object p0
.end method

.method public positions(Ljava/nio/Buffer;)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mPositions:Ljava/nio/Buffer;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mPositionsStride:I

    .line 5
    .line 6
    return-object p0
.end method

.method public tangents(Ljava/nio/Buffer;)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTangents:Ljava/nio/Buffer;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTangentsStride:I

    .line 5
    .line 6
    return-object p0
.end method

.method public triangleCount(I)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTriangleCount:I

    .line 2
    .line 3
    return-object p0
.end method

.method public triangles_uint16(Ljava/nio/Buffer;)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTrianglesUint16:Ljava/nio/Buffer;

    .line 2
    .line 3
    return-object p0
.end method

.method public triangles_uint32(Ljava/nio/Buffer;)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTrianglesUint32:Ljava/nio/Buffer;

    .line 2
    .line 3
    return-object p0
.end method

.method public uvs(Ljava/nio/Buffer;)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTexCoords:Ljava/nio/Buffer;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mTexCoordsStride:I

    .line 5
    .line 6
    return-object p0
.end method

.method public vertexCount(I)Lcom/google/android/filament/SurfaceOrientation$Builder;
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/SurfaceOrientation$Builder;->mVertexCount:I

    .line 2
    .line 3
    return-object p0
.end method
