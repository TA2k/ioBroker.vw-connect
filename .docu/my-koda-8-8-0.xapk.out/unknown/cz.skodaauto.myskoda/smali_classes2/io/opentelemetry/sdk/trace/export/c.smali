.class public final synthetic Lio/opentelemetry/sdk/trace/export/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lio/opentelemetry/sdk/common/CompletableResultCode;

.field public final synthetic f:Lio/opentelemetry/sdk/common/CompletableResultCode;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;I)V
    .locals 0

    .line 1
    iput p4, p0, Lio/opentelemetry/sdk/trace/export/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/export/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/export/c;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 6
    .line 7
    iput-object p3, p0, Lio/opentelemetry/sdk/trace/export/c;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/trace/export/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/export/c;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/export/c;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/c;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 13
    .line 14
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;->a(Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/export/c;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;

    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/export/c;->e:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 23
    .line 24
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/export/c;->f:Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 25
    .line 26
    invoke-static {v0, v1, p0}, Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;->c(Lio/opentelemetry/sdk/trace/export/BatchSpanProcessor$Worker;Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
