.class public final synthetic Lio/opentelemetry/exporter/internal/grpc/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/util/StringJoiner;


# direct methods
.method public synthetic constructor <init>(Ljava/util/StringJoiner;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/exporter/internal/grpc/c;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/exporter/internal/grpc/c;->b:Ljava/util/StringJoiner;

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
    iget v0, p0, Lio/opentelemetry/exporter/internal/grpc/c;->a:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/String;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/grpc/c;->b:Ljava/util/StringJoiner;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->e(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/http/HttpExporterBuilder;->c(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->a(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_2
    invoke-static {p0, p1, p2}, Lio/opentelemetry/exporter/internal/grpc/GrpcExporterBuilder;->c(Ljava/util/StringJoiner;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
