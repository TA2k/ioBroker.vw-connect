.class public final synthetic Lio/opentelemetry/exporter/internal/otlp/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

.field public final synthetic c:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

.field public final synthetic d:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;[ILio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/b;->c:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/b;->d:Ljava/lang/Object;

    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/b;->b:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lio/opentelemetry/exporter/internal/otlp/b;->d:Ljava/lang/Object;

    iput-object p2, p0, Lio/opentelemetry/exporter/internal/otlp/b;->b:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    iput-object p3, p0, Lio/opentelemetry/exporter/internal/otlp/b;->c:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->d:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/exporter/internal/marshal/Serializer;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/b;->c:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 11
    .line 12
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 13
    .line 14
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->b:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 15
    .line 16
    invoke-static {v0, p0, v1, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/ExtendedAttributeKeyValueStatelessMarshaler;->b(Lio/opentelemetry/exporter/internal/marshal/Serializer;Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->d:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, [I

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/exporter/internal/otlp/b;->b:Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 25
    .line 26
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 27
    .line 28
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/otlp/b;->c:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;

    .line 29
    .line 30
    invoke-static {p0, v0, v1, p1, p2}, Lio/opentelemetry/exporter/internal/otlp/ExtendedAttributeKeyValueStatelessMarshaler;->a(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;[ILio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
