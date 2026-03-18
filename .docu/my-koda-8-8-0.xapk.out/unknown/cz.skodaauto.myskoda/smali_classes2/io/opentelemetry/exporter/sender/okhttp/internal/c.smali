.class public final synthetic Lio/opentelemetry/exporter/sender/okhttp/internal/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/context/Context;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/util/function/Consumer;

    .line 13
    .line 14
    invoke-static {v0, p0, p1}, Lio/opentelemetry/context/Context;->h(Lio/opentelemetry/context/Context;Ljava/util/function/Consumer;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->b:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Ld01/j0;

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->c:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Ljava/lang/String;

    .line 25
    .line 26
    check-cast p1, Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->a(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Ld01/j0;

    .line 35
    .line 36
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/c;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ljava/lang/String;

    .line 39
    .line 40
    check-cast p1, Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v0, p0, p1}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->c(Ld01/j0;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
