.class public final synthetic Lio/opentelemetry/api/incubator/logs/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/api/incubator/logs/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/api/incubator/logs/a;->b:Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/api/incubator/logs/a;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/api/incubator/logs/a;->b:Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 9
    .line 10
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->a(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p1, Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;

    .line 15
    .line 16
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;->b(Lio/opentelemetry/api/incubator/logs/ExtendedLogRecordBuilder;Lio/opentelemetry/api/incubator/common/ExtendedAttributeKey;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
