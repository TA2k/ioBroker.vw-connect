.class public Lcom/salesforce/marketingcloud/push/f;
.super Ljava/lang/Exception;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/f$a;
    }
.end annotation


# instance fields
.field private final b:Lcom/salesforce/marketingcloud/push/f$a;

.field private final c:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/push/f$a;Ljava/lang/String;)V
    .locals 1

    const-string v0, "errorCode"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0, p2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/f;->b:Lcom/salesforce/marketingcloud/push/f$a;

    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/push/f;->c:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/push/f$a;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/push/f;-><init>(Lcom/salesforce/marketingcloud/push/f$a;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/push/f$a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/f;->b:Lcom/salesforce/marketingcloud/push/f$a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/f;->b:Lcom/salesforce/marketingcloud/push/f$a;

    .line 7
    .line 8
    const-string v2, "errorCode"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/push/f;->getMessage()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const-string v1, "message"

    .line 20
    .line 21
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 22
    .line 23
    .line 24
    :cond_0
    return-object v0
.end method

.method public getMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/f;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
