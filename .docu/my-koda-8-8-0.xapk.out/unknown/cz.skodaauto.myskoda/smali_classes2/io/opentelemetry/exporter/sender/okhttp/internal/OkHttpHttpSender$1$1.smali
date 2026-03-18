.class Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/exporter/internal/http/HttpSender$Response;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;->onResponse(Ld01/j;Ld01/t0;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field private bodyBytes:[B
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field final synthetic this$1:Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;

.field final synthetic val$body:Ld01/v0;

.field final synthetic val$response:Ld01/t0;


# direct methods
.method public constructor <init>(Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;Ld01/t0;Ld01/v0;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->this$1:Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1;

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->val$response:Ld01/t0;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->val$body:Ld01/v0;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public responseBody()[B
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->bodyBytes:[B

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->val$body:Ld01/v0;

    .line 6
    .line 7
    invoke-virtual {v0}, Ld01/v0;->a()[B

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->bodyBytes:[B

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->bodyBytes:[B

    .line 14
    .line 15
    return-object p0
.end method

.method public statusCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->val$response:Ld01/t0;

    .line 2
    .line 3
    iget p0, p0, Ld01/t0;->g:I

    .line 4
    .line 5
    return p0
.end method

.method public statusMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpHttpSender$1$1;->val$response:Ld01/t0;

    .line 2
    .line 3
    iget-object p0, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method
