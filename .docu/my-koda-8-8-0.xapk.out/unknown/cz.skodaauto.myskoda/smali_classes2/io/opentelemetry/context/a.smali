.class public final synthetic Lio/opentelemetry/context/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Supplier;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/context/a;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/context/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/context/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/context/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/context/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientPeerServiceAttributesExtractor;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/context/a;->f:Ljava/lang/Object;

    .line 11
    .line 12
    invoke-static {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientPeerServiceAttributesExtractor;->a(Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientPeerServiceAttributesExtractor;Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/context/a;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lio/opentelemetry/context/Context;

    .line 20
    .line 21
    iget-object p0, p0, Lio/opentelemetry/context/a;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Ljava/util/function/Supplier;

    .line 24
    .line 25
    invoke-static {v0, p0}, Lio/opentelemetry/context/Context;->a(Lio/opentelemetry/context/Context;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
