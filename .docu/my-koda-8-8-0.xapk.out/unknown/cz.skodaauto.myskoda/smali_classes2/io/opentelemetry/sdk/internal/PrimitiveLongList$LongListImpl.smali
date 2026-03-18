.class Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;
.super Ljava/util/AbstractList;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/internal/PrimitiveLongList;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "LongListImpl"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/util/AbstractList<",
        "Ljava/lang/Long;",
        ">;"
    }
.end annotation


# instance fields
.field private final values:[J


# direct methods
.method public constructor <init>([J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractList;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    .line 5
    .line 6
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;)[J
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 1
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    instance-of v0, p1, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Ljava/util/AbstractList;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    .line 11
    .line 12
    check-cast p1, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;

    .line 13
    .line 14
    iget-object p1, p1, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    .line 15
    .line 16
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([J[J)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0
.end method

.method public get(I)Ljava/lang/Long;
    .locals 0

    .line 2
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    aget-wide p0, p0, p1

    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic get(I)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->get(I)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public size()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/PrimitiveLongList$LongListImpl;->values:[J

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method
