.class public final synthetic Lex0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Supplier;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lex0/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lex0/n;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lex0/n;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lex0/n;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;

    .line 9
    .line 10
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->a(Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;)Ljava/util/Map;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    check-cast p0, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;

    .line 16
    .line 17
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->e(Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;)Ljava/util/Map;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lio/opentelemetry/api/metrics/MeterProvider;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
