.class public final Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
        "Lio/opentelemetry/api/common/Value<",
        "*>;>;"
    }
.end annotation


# static fields
.field public static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getBinarySerializedSize(Lio/opentelemetry/api/common/Value;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 2
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler$1;->$SwitchMap$io$opentelemetry$api$common$ValueType:[I

    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getType()Lio/opentelemetry/api/common/ValueType;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget p0, p0, v0

    packed-switch p0, :pswitch_data_0

    .line 3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported value type."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 4
    :pswitch_0
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueStatelessMarshaler;

    .line 5
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/nio/ByteBuffer;

    .line 6
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/nio/ByteBuffer;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 7
    :pswitch_1
    sget-object p0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->KVLIST_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueStatelessMarshaler;

    .line 9
    invoke-static {p0, p1, v0, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 10
    :pswitch_2
    sget-object p0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->ARRAY_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueStatelessMarshaler;

    .line 12
    invoke-static {p0, p1, v0, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 13
    :pswitch_3
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;

    .line 14
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Double;

    .line 15
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Double;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 16
    :pswitch_4
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;

    .line 17
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Long;

    .line 18
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Long;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 19
    :pswitch_5
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;

    .line 20
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    .line 21
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Boolean;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 22
    :pswitch_6
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;

    .line 23
    invoke-interface {p1}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    .line 24
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/api/common/Value;

    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/api/common/Value;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/Serializer;",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 2
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler$1;->$SwitchMap$io$opentelemetry$api$common$ValueType:[I

    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getType()Lio/opentelemetry/api/common/ValueType;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget p0, p0, v0

    packed-switch p0, :pswitch_data_0

    .line 3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported value type."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 4
    :pswitch_0
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueStatelessMarshaler;

    .line 5
    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/nio/ByteBuffer;

    .line 6
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/BytesAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/nio/ByteBuffer;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    .line 7
    :pswitch_1
    sget-object p0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->KVLIST_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 8
    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/List;

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/KeyValueListAnyValueStatelessMarshaler;

    .line 9
    invoke-virtual {p1, p0, p2, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    .line 10
    :pswitch_2
    sget-object p0, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->ARRAY_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/List;

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/ArrayAnyValueStatelessMarshaler;

    .line 12
    invoke-virtual {p1, p0, p2, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    .line 13
    :pswitch_3
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;

    .line 14
    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Double;

    .line 15
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Double;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    .line 16
    :pswitch_4
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;

    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Long;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Long;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    .line 17
    :pswitch_5
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;

    .line 18
    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Boolean;

    .line 19
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Boolean;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    .line 20
    :pswitch_6
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;

    .line 21
    invoke-interface {p2}, Lio/opentelemetry/api/common/Value;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/String;

    .line 22
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/api/common/Value;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/AnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/api/common/Value;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
