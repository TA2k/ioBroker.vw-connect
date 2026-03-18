.class public final synthetic Lio/opentelemetry/api/internal/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Predicate;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio/opentelemetry/api/internal/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/api/internal/a;->b:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final test(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/api/internal/a;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/api/internal/a;->b:Ljava/lang/String;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p1, Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/internal/ScopeConfiguratorBuilder;->a(Ljava/lang/String;Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0

    .line 22
    :pswitch_1
    check-cast p1, Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/internal/IncludeExcludePredicate;->a(Ljava/lang/String;Ljava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0

    .line 29
    :pswitch_2
    check-cast p1, Ljava/util/Map$Entry;

    .line 30
    .line 31
    invoke-static {p0, p1}, Lio/opentelemetry/api/internal/ConfigUtil;->c(Ljava/lang/String;Ljava/util/Map$Entry;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0

    .line 36
    :pswitch_3
    check-cast p1, Ljava/util/Map$Entry;

    .line 37
    .line 38
    invoke-static {p0, p1}, Lio/opentelemetry/api/internal/ConfigUtil;->b(Ljava/lang/String;Ljava/util/Map$Entry;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    return p0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
