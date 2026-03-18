.class public final synthetic Lio/opentelemetry/context/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/context/b;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lio/opentelemetry/context/b;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lio/opentelemetry/context/b;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/context/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/context/b;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;

    .line 9
    .line 10
    iget-object p0, p0, Lio/opentelemetry/context/b;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/lang/String;

    .line 13
    .line 14
    check-cast p1, Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {v0, p0, p1}, Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;->d(Lio/opentelemetry/sdk/autoconfigure/spi/internal/DefaultConfigProperties;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    iget-object v0, p0, Lio/opentelemetry/context/b;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 24
    .line 25
    iget-object p0, p0, Lio/opentelemetry/context/b;->c:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lio/opentelemetry/api/common/Attributes;

    .line 28
    .line 29
    check-cast p1, Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v0, p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->d(Lio/opentelemetry/sdk/internal/ComponentRegistry;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    iget-object v0, p0, Lio/opentelemetry/context/b;->b:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lio/opentelemetry/context/Context;

    .line 39
    .line 40
    iget-object p0, p0, Lio/opentelemetry/context/b;->c:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Ljava/util/function/Function;

    .line 43
    .line 44
    invoke-static {v0, p0, p1}, Lio/opentelemetry/context/Context;->e(Lio/opentelemetry/context/Context;Ljava/util/function/Function;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
