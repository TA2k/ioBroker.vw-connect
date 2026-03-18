.class public final Lcom/salesforce/marketingcloud/internal/c$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/internal/c;
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/internal/c$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->Companion:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;->a()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    move-result-object p0

    return-object p0
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/String;
    .locals 0

    const-string p0, "message"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->getActivityInstanceId$sdk_release()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Lorg/json/JSONObject;
    .locals 0

    .line 1
    const-string p0, "message"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->toJson()Lorg/json/JSONObject;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method
