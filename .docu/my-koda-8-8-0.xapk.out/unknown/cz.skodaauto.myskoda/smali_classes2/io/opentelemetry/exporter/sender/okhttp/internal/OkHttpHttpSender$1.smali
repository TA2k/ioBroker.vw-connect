.class Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;->send(Lio/opentelemetry/exporter/internal/marshal/Marshaler;ILjava/util/function/Consumer;Ljava/util/function/Consumer;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;

.field final synthetic val$onError:Ljava/util/function/Consumer;

.field final synthetic val$onResponse:Ljava/util/function/Consumer;


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;Ljava/util/function/Consumer;Ljava/util/function/Consumer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;->this$0:Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;->val$onError:Ljava/util/function/Consumer;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;->val$onResponse:Ljava/util/function/Consumer;

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
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;->val$onError:Ljava/util/function/Consumer;

    .line 2
    .line 3
    invoke-interface {p0, p2}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onResponse(Ld01/j;Ld01/t0;)V
    .locals 2

    .line 1
    iget-object p1, p2, Ld01/t0;->j:Ld01/v0;

    .line 2
    .line 3
    :try_start_0
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;->val$onResponse:Ljava/util/function/Consumer;

    .line 4
    .line 5
    new-instance v1, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;

    .line 6
    .line 7
    invoke-direct {v1, p0, p2, p1}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;-><init>(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;Ld01/t0;Ld01/v0;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {v0, v1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Ld01/v0;->close()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    :try_start_1
    invoke-virtual {p1}, Ld01/v0;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_1
    move-exception p1

    .line 27
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    :goto_0
    throw p0
.end method
