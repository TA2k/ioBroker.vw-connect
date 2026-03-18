.class Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "RepeatedElementPairSizeCalculator"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/function/BiConsumer<",
        "TK;TV;>;"
    }
.end annotation


# instance fields
.field private context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

.field private fieldTagSize:I

.field private marshaler:Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
            "TK;TV;>;"
        }
    .end annotation
.end field

.field private size:I


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;-><init>()V

    return-void
.end method

.method public static synthetic access$100(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;)I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->size:I

    .line 2
    .line 3
    return p0
.end method


# virtual methods
.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;TV;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addSize()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->marshaler:Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;

    .line 8
    .line 9
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 10
    .line 11
    invoke-interface {v1, p1, p2, v2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;->getBinarySerializedSize(Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    iget-object p2, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 16
    .line 17
    invoke-virtual {p2, v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->setSize(II)V

    .line 18
    .line 19
    .line 20
    iget p2, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->size:I

    .line 21
    .line 22
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->fieldTagSize:I

    .line 23
    .line 24
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    add-int/2addr v1, v0

    .line 29
    add-int/2addr v1, p1

    .line 30
    add-int/2addr v1, p2

    .line 31
    iput v1, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->size:I

    .line 32
    .line 33
    return-void
.end method

.method public initialize(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
            "TK;TV;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->size:I

    .line 3
    .line 4
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->fieldTagSize:I

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->marshaler:Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 13
    .line 14
    return-void
.end method
