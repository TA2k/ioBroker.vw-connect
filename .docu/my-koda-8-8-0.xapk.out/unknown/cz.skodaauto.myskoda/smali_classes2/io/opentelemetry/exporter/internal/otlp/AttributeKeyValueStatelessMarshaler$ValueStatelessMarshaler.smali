.class Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ValueStatelessMarshaler"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
        "Lio/opentelemetry/api/common/AttributeKey<",
        "*>;",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;

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
.method public getBinarySerializedSize(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/api/common/AttributeKey;->getType()Lio/opentelemetry/api/common/AttributeType;

    move-result-object p0

    .line 3
    sget-object p1, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget p1, p1, v0

    packed-switch p1, :pswitch_data_0

    .line 4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported attribute type."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 5
    :pswitch_0
    sget-object p1, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->ARRAY_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    check-cast p2, Ljava/util/List;

    sget-object v0, Lio/opentelemetry/exporter/internal/otlp/AttributeArrayAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeArrayAnyValueStatelessMarshaler;

    invoke-static {p1, p0, p2, v0, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 6
    :pswitch_1
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;

    check-cast p2, Ljava/lang/Double;

    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Double;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 7
    :pswitch_2
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Boolean;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 8
    :pswitch_3
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;

    check-cast p2, Ljava/lang/Long;

    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Long;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 9
    :pswitch_4
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;

    check-cast p2, Ljava/lang/String;

    invoke-virtual {p0, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->getBinarySerializedSize(Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic getBinarySerializedSize(Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;->getBinarySerializedSize(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0
.end method

.method public writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/Serializer;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")V"
        }
    .end annotation

    .line 2
    invoke-interface {p2}, Lio/opentelemetry/api/common/AttributeKey;->getType()Lio/opentelemetry/api/common/AttributeType;

    move-result-object v2

    .line 3
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$1;->$SwitchMap$io$opentelemetry$api$common$AttributeType:[I

    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p0, p0, p2

    packed-switch p0, :pswitch_data_0

    .line 4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported attribute type."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 5
    :pswitch_0
    sget-object v1, Lio/opentelemetry/proto/common/v1/internal/AnyValue;->ARRAY_VALUE:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    move-object v3, p3

    check-cast v3, Ljava/util/List;

    sget-object v4, Lio/opentelemetry/exporter/internal/otlp/AttributeArrayAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/AttributeArrayAnyValueStatelessMarshaler;

    move-object v0, p1

    move-object v5, p4

    invoke-virtual/range {v0 .. v5}, Lio/opentelemetry/exporter/internal/marshal/Serializer;->serializeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    :pswitch_1
    move-object v0, p1

    move-object v5, p4

    .line 6
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;

    check-cast p3, Ljava/lang/Double;

    invoke-virtual {p0, v0, p3, v5}, Lio/opentelemetry/exporter/internal/otlp/DoubleAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Double;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    :pswitch_2
    move-object v0, p1

    move-object v5, p4

    .line 7
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p0, v0, p3, v5}, Lio/opentelemetry/exporter/internal/otlp/BoolAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Boolean;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    :pswitch_3
    move-object v0, p1

    move-object v5, p4

    .line 8
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;

    check-cast p3, Ljava/lang/Long;

    invoke-virtual {p0, v0, p3, v5}, Lio/opentelemetry/exporter/internal/otlp/IntAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Long;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    :pswitch_4
    move-object v0, p1

    move-object v5, p4

    .line 9
    sget-object p0, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->INSTANCE:Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;

    check-cast p3, Ljava/lang/String;

    invoke-virtual {p0, v0, p3, v5}, Lio/opentelemetry/exporter/internal/otlp/StringAnyValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    check-cast p2, Lio/opentelemetry/api/common/AttributeKey;

    invoke-virtual {p0, p1, p2, p3, p4}, Lio/opentelemetry/exporter/internal/otlp/AttributeKeyValueStatelessMarshaler$ValueStatelessMarshaler;->writeTo(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    return-void
.end method
