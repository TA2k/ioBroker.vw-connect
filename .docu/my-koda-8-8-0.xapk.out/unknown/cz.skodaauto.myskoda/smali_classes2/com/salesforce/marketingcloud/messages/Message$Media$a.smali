.class public final Lcom/salesforce/marketingcloud/messages/Message$Media$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/Message$Media;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/Message$Media$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/Message$Media;
    .locals 2

    .line 1
    const/4 p0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    const-string v0, "androidUrl"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object v0, p0

    .line 12
    :goto_0
    if-eqz p1, :cond_1

    .line 13
    .line 14
    const-string v1, "alt"

    .line 15
    .line 16
    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object p1, p0

    .line 22
    :goto_1
    if-nez v0, :cond_3

    .line 23
    .line 24
    if-eqz p1, :cond_2

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_2
    return-object p0

    .line 28
    :cond_3
    :goto_2
    new-instance p0, Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 29
    .line 30
    if-nez v0, :cond_4

    .line 31
    .line 32
    const-string v0, ""

    .line 33
    .line 34
    :cond_4
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/messages/Message$Media;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method
