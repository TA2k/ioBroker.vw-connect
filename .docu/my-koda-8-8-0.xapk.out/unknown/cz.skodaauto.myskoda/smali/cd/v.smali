.class public final Lcd/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final serializer()Lqz0/a;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    new-instance p0, Lcd/i;

    .line 2
    .line 3
    const-class v0, Lcd/z;

    .line 4
    .line 5
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {p0, v0, v1}, Lcd/i;-><init>(Lhy0/d;I)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method
