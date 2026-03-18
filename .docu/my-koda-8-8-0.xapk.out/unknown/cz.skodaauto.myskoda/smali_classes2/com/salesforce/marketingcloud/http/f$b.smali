.class public final Lcom/salesforce/marketingcloud/http/f$b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/http/f;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/http/f$b;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/http/f$a;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/http/f$a;

    invoke-direct {p0}, Lcom/salesforce/marketingcloud/http/f$a;-><init>()V

    return-object p0
.end method

.method public final a(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/http/f;
    .locals 2

    const-string v0, "message"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/http/f$b;->a()Lcom/salesforce/marketingcloud/http/f$a;

    move-result-object p0

    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/http/f$a;->a(I)Lcom/salesforce/marketingcloud/http/f$a;

    move-result-object p0

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/http/f$a;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f$a;

    move-result-object p0

    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/http/f$a;->b(J)Lcom/salesforce/marketingcloud/http/f$a;

    move-result-object p0

    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/http/f$a;->a(J)Lcom/salesforce/marketingcloud/http/f$a;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/http/f$a;->a()Lcom/salesforce/marketingcloud/http/f;

    move-result-object p0

    return-object p0
.end method
