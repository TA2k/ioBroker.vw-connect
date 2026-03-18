.class public Lcom/salesforce/marketingcloud/events/predicates/b;
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
        "Ljava/lang/Boolean;",
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
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/events/predicates/b;->b(Ljava/lang/Object;)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0
.end method

.method public a(Ljava/lang/Boolean;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Boolean;)Z
    .locals 3

    const/4 p0, 0x0

    if-eqz p1, :cond_2

    if-eqz p3, :cond_2

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/events/predicates/b$a;->a:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x1

    if-eq v0, v1, :cond_1

    const/4 v2, 0x2

    if-ne v0, v2, :cond_0

    if-eq p1, p3, :cond_2

    goto :goto_0

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    sget-object p1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 5
    new-instance p1, Ljava/lang/StringBuilder;

    const-string p3, "Operator "

    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, " not supported for Boolean data types."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    if-ne p1, p3, :cond_2

    :goto_0
    return v1

    :cond_2
    return p0
.end method

.method public bridge synthetic a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)Z
    .locals 0

    .line 2
    check-cast p1, Ljava/lang/Boolean;

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/events/predicates/b;->a(Ljava/lang/Boolean;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Boolean;)Z

    move-result p0

    return p0
.end method

.method public b(Ljava/lang/Object;)Ljava/lang/Boolean;
    .locals 0

    .line 1
    instance-of p0, p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljava/lang/Boolean;

    .line 6
    .line 7
    return-object p1

    .line 8
    :cond_0
    instance-of p0, p1, Ljava/lang/String;

    .line 9
    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    check-cast p1, Ljava/lang/String;

    .line 13
    .line 14
    const-string p0, "true"

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    const-string p0, "false"

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_2
    const/4 p0, 0x0

    .line 37
    return-object p0
.end method
