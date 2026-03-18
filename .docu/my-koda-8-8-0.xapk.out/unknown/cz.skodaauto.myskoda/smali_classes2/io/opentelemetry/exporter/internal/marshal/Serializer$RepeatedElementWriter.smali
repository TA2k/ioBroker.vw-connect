.class Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/marshal/Serializer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "RepeatedElementWriter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/function/Consumer<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

.field private field:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field private marshaler:Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "TT;>;"
        }
    .end annotation
.end field

.field private output:Lio/opentelemetry/exporter/internal/marshal/Serializer;


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/marshal/Serializer$1;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;-><init>()V

    return-void
.end method


# virtual methods
.method public accept(Ljava/lang/Object;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)V"
        }
    .end annotation

    .line 1
    :try_start_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->output:Lio/opentelemetry/exporter/internal/marshal/Serializer;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->field:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 6
    .line 7
    invoke-virtual {v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getSize()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {v0, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeStartRepeatedElement(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->marshaler:Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;

    .line 15
    .line 16
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->output:Lio/opentelemetry/exporter/internal/marshal/Serializer;

    .line 17
    .line 18
    iget-object v2, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 19
    .line 20
    invoke-interface {v0, v1, p1, v2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->output:Lio/opentelemetry/exporter/internal/marshal/Serializer;

    .line 24
    .line 25
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->writeEndRepeatedElement()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :catch_0
    move-exception p0

    .line 30
    new-instance p1, Ljava/io/UncheckedIOException;

    .line 31
    .line 32
    invoke-direct {p1, p0}, Ljava/io/UncheckedIOException;-><init>(Ljava/io/IOException;)V

    .line 33
    .line 34
    .line 35
    throw p1
.end method

.method public initialize(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Lio/opentelemetry/exporter/internal/marshal/Serializer;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->field:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->output:Lio/opentelemetry/exporter/internal/marshal/Serializer;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->marshaler:Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;

    .line 6
    .line 7
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/marshal/Serializer$RepeatedElementWriter;->context:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 8
    .line 9
    return-void
.end method
