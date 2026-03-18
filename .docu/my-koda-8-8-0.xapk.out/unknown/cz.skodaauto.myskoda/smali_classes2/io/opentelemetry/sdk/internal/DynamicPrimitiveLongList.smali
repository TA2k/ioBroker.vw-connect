.class public Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;
.super Ljava/util/AbstractList;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/util/AbstractList<",
        "Ljava/lang/Long;",
        ">;"
    }
.end annotation


# static fields
.field private static final DEFAULT_SUBARRAY_CAPACITY:I = 0xa


# instance fields
.field private arrayCount:I

.field private arrays:[[J

.field private size:I

.field private final subarrayCapacity:I


# direct methods
.method public constructor <init>()V
    .locals 1

    const/16 v0, 0xa

    .line 1
    invoke-direct {p0, v0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/util/AbstractList;-><init>()V

    if-lez p1, :cond_0

    .line 3
    iput p1, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->subarrayCapacity:I

    const/4 v0, 0x2

    .line 4
    new-array v0, v0, [I

    const/4 v1, 0x1

    aput p1, v0, v1

    const/4 p1, 0x0

    aput p1, v0, p1

    sget-object v1, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    invoke-static {v1, v0}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [[J

    iput-object v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrays:[[J

    .line 5
    iput p1, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrayCount:I

    .line 6
    iput p1, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size:I

    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Subarray capacity must be positive"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static empty()Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private ensureCapacity(I)V
    .locals 3

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->subarrayCapacity:I

    .line 2
    .line 3
    add-int/2addr p1, v0

    .line 4
    add-int/lit8 p1, p1, -0x1

    .line 5
    .line 6
    div-int/2addr p1, v0

    .line 7
    iget v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrayCount:I

    .line 8
    .line 9
    if-le p1, v0, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrays:[[J

    .line 12
    .line 13
    invoke-static {v0, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, [[J

    .line 18
    .line 19
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrays:[[J

    .line 20
    .line 21
    iget v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrayCount:I

    .line 22
    .line 23
    :goto_0
    if-ge v0, p1, :cond_0

    .line 24
    .line 25
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrays:[[J

    .line 26
    .line 27
    iget v2, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->subarrayCapacity:I

    .line 28
    .line 29
    new-array v2, v2, [J

    .line 30
    .line 31
    aput-object v2, v1, v0

    .line 32
    .line 33
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iput p1, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrayCount:I

    .line 37
    .line 38
    :cond_1
    return-void
.end method

.method public static varargs of([J)Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;
    .locals 4

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;-><init>()V

    .line 4
    .line 5
    .line 6
    array-length v1, p0

    .line 7
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->resizeAndClear(I)V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    :goto_0
    array-length v2, p0

    .line 12
    if-ge v1, v2, :cond_0

    .line 13
    .line 14
    aget-wide v2, p0, v1

    .line 15
    .line 16
    invoke-virtual {v0, v1, v2, v3}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->setLong(IJ)J

    .line 17
    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-object v0
.end method

.method public static ofSubArrayCapacity(I)Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private outOfBoundsMsg(I)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "Index: "

    .line 2
    .line 3
    const-string v1, ", Size: "

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget p0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size:I

    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method private rangeCheck(I)V
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 9
    .line 10
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->outOfBoundsMsg(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw v0
.end method


# virtual methods
.method public get(I)Ljava/lang/Long;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->getLong(I)J

    move-result-wide p0

    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic get(I)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->get(I)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public getLong(I)J
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->rangeCheck(I)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrays:[[J

    .line 5
    .line 6
    iget p0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->subarrayCapacity:I

    .line 7
    .line 8
    div-int v1, p1, p0

    .line 9
    .line 10
    aget-object v0, v0, v1

    .line 11
    .line 12
    rem-int/2addr p1, p0

    .line 13
    aget-wide p0, v0, p1

    .line 14
    .line 15
    return-wide p0
.end method

.method public resizeAndClear(I)V
    .locals 3

    .line 1
    if-ltz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->ensureCapacity(I)V

    .line 4
    .line 5
    .line 6
    iput p1, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size:I

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    :goto_0
    if-ge v0, p1, :cond_0

    .line 10
    .line 11
    const-wide/16 v1, 0x0

    .line 12
    .line 13
    invoke-virtual {p0, v0, v1, v2}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->setLong(IJ)J

    .line 14
    .line 15
    .line 16
    add-int/lit8 v0, v0, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    return-void

    .line 20
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 21
    .line 22
    const-string p1, "New size must be non-negative"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public set(ILjava/lang/Long;)Ljava/lang/Long;
    .locals 2

    .line 2
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    invoke-virtual {p0, p1, v0, v1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->setLong(IJ)J

    move-result-wide p0

    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p2, Ljava/lang/Long;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->set(ILjava/lang/Long;)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public setLong(IJ)J
    .locals 4

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->rangeCheck(I)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->arrays:[[J

    .line 5
    .line 6
    iget p0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->subarrayCapacity:I

    .line 7
    .line 8
    div-int v1, p1, p0

    .line 9
    .line 10
    aget-object v1, v0, v1

    .line 11
    .line 12
    rem-int v2, p1, p0

    .line 13
    .line 14
    aget-wide v1, v1, v2

    .line 15
    .line 16
    div-int v3, p1, p0

    .line 17
    .line 18
    aget-object v0, v0, v3

    .line 19
    .line 20
    rem-int/2addr p1, p0

    .line 21
    aput-wide p2, v0, p1

    .line 22
    .line 23
    return-wide v1
.end method

.method public size()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size:I

    .line 2
    .line 3
    return p0
.end method
