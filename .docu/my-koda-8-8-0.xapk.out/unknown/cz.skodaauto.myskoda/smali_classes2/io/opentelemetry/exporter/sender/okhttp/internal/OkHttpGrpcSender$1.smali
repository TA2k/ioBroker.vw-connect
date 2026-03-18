.class Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->send(Lio/opentelemetry/exporter/internal/marshal/Marshaler;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;

.field final synthetic val$onError:Ljava/util/function/Consumer;

.field final synthetic val$onResponse:Ljava/util/function/Consumer;


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;->this$0:Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;->val$onError:Ljava/util/function/Consumer;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;->val$onResponse:Ljava/util/function/Consumer;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public onFailure(Ld01/j;Ljava/io/IOException;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;->val$onError:Ljava/util/function/Consumer;

    .line 2
    .line 3
    invoke-interface {p0, p2}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onResponse(Ld01/j;Ld01/t0;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p1, p2, Ld01/t0;->j:Ld01/v0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ld01/v0;->a()[B
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 4
    .line 5
    .line 6
    invoke-static {p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->access$000(Ld01/t0;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-static {p2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender;->access$100(Ld01/t0;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    :try_start_1
    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    move-result p1
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_0

    .line 18
    goto :goto_0

    .line 19
    :catch_0
    const/4 p1, 0x2

    .line 20
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;->val$onResponse:Ljava/util/function/Consumer;

    .line 21
    .line 22
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;->create(ILjava/lang/String;)Lio/opentelemetry/exporter/internal/grpc/GrpcResponse;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-interface {p0, p1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :catch_1
    move-exception p1

    .line 31
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpGrpcSender$1;->val$onError:Ljava/util/function/Consumer;

    .line 32
    .line 33
    new-instance p2, Ljava/lang/RuntimeException;

    .line 34
    .line 35
    const-string v0, "Could not consume server response"

    .line 36
    .line 37
    invoke-direct {p2, v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    invoke-interface {p0, p2}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method
