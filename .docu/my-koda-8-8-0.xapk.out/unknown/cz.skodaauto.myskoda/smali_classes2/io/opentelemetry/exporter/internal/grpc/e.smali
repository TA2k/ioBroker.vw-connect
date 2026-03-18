.class public final synthetic Lio/opentelemetry/exporter/internal/grpc/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/util/HashMap;


# direct methods
.method public synthetic constructor <init>(Ljava/util/HashMap;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/exporter/internal/grpc/e;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

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
    iget v0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 7
    .line 8
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;->a(Ljava/util/HashMap;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/String;

    .line 15
    .line 16
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;->i(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    check-cast p1, Ljava/lang/String;

    .line 23
    .line 24
    check-cast p2, Ljava/lang/String;

    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 27
    .line 28
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;->b(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_2
    check-cast p1, Ljava/lang/String;

    .line 33
    .line 34
    check-cast p2, Ljava/lang/String;

    .line 35
    .line 36
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 37
    .line 38
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;->e(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_3
    check-cast p1, Ljava/lang/String;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/String;

    .line 45
    .line 46
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 47
    .line 48
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->b(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :pswitch_4
    check-cast p1, Ljava/lang/String;

    .line 53
    .line 54
    check-cast p2, Ljava/lang/String;

    .line 55
    .line 56
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 57
    .line 58
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->d(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :pswitch_5
    check-cast p1, Ljava/lang/String;

    .line 63
    .line 64
    check-cast p2, Ljava/lang/String;

    .line 65
    .line 66
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 67
    .line 68
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->b(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_6
    check-cast p1, Ljava/lang/String;

    .line 73
    .line 74
    check-cast p2, Ljava/lang/String;

    .line 75
    .line 76
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/e;->b:Ljava/util/HashMap;

    .line 77
    .line 78
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->f(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    nop

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
