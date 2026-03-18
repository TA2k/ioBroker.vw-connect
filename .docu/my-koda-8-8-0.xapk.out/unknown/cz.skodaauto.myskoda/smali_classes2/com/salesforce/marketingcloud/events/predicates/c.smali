.class public Lcom/salesforce/marketingcloud/events/predicates/c;
.super Lcom/salesforce/marketingcloud/events/predicates/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/salesforce/marketingcloud/events/predicates/h<",
        "Ljava/lang/Double;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/events/predicates/h;-><init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public bridge synthetic a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/events/predicates/c;->b(Ljava/lang/Object;)Ljava/lang/Double;

    move-result-object p0

    return-object p0
.end method

.method public a(Ljava/lang/Double;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Double;)Z
    .locals 4

    const/4 p0, 0x0

    if-eqz p1, :cond_0

    if-eqz p3, :cond_0

    .line 3
    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v0

    .line 4
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v2

    .line 5
    sget-object p1, Lcom/salesforce/marketingcloud/events/predicates/c$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p3

    aget p1, p1, p3

    packed-switch p1, :pswitch_data_0

    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    sget-object p1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 7
    new-instance p1, Ljava/lang/StringBuilder;

    const-string p3, "Operator "

    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, " not supported for Double data types."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0

    :pswitch_0
    cmpl-double p1, v0, v2

    if-ltz p1, :cond_0

    goto :goto_0

    :pswitch_1
    cmpg-double p1, v0, v2

    if-gtz p1, :cond_0

    goto :goto_0

    :pswitch_2
    cmpl-double p1, v0, v2

    if-lez p1, :cond_0

    goto :goto_0

    :pswitch_3
    cmpg-double p1, v0, v2

    if-gez p1, :cond_0

    goto :goto_0

    :pswitch_4
    cmpl-double p1, v0, v2

    if-eqz p1, :cond_0

    goto :goto_0

    :pswitch_5
    cmpl-double p1, v0, v2

    if-nez p1, :cond_0

    :goto_0
    const/4 p0, 0x1

    :cond_0
    return p0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)Z
    .locals 0

    .line 2
    check-cast p1, Ljava/lang/Double;

    check-cast p3, Ljava/lang/Double;

    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/events/predicates/c;->a(Ljava/lang/Double;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Double;)Z

    move-result p0

    return p0
.end method

.method public b(Ljava/lang/Object;)Ljava/lang/Double;
    .locals 0

    .line 1
    instance-of p0, p1, Ljava/lang/Double;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljava/lang/Double;

    .line 6
    .line 7
    return-object p1

    .line 8
    :cond_0
    instance-of p0, p1, Ljava/lang/Number;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    check-cast p1, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    .line 15
    .line 16
    .line 17
    move-result-wide p0

    .line 18
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    instance-of p0, p1, Ljava/lang/String;

    .line 24
    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    :try_start_0
    check-cast p1, Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {p1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 34
    .line 35
    .line 36
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    return-object p0

    .line 38
    :catch_0
    :cond_2
    const/4 p0, 0x0

    .line 39
    return-object p0
.end method
