.class public final synthetic Lio/opentelemetry/sdk/internal/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lio/opentelemetry/sdk/internal/ComponentRegistry;

.field public final synthetic c:Ljava/lang/String;

.field public final synthetic d:Lio/opentelemetry/api/common/Attributes;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;I)V
    .locals 0

    .line 1
    iput p4, p0, Lio/opentelemetry/sdk/internal/d;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/d;->b:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 4
    .line 5
    iput-object p2, p0, Lio/opentelemetry/sdk/internal/d;->c:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lio/opentelemetry/sdk/internal/d;->d:Lio/opentelemetry/api/common/Attributes;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/internal/d;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/d;->d:Lio/opentelemetry/api/common/Attributes;

    .line 7
    .line 8
    check-cast p1, Ljava/lang/String;

    .line 9
    .line 10
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/d;->b:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/d;->c:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0, v1, p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->h(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/d;->d:Lio/opentelemetry/api/common/Attributes;

    .line 20
    .line 21
    check-cast p1, Ljava/lang/String;

    .line 22
    .line 23
    iget-object v1, p0, Lio/opentelemetry/sdk/internal/d;->b:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 24
    .line 25
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/d;->c:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {v0, v1, p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->e(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
