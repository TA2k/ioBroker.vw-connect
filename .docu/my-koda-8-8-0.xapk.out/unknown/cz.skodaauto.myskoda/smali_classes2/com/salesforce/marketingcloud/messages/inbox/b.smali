.class public final Lcom/salesforce/marketingcloud/messages/inbox/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final A:Ljava/lang/String; = "messageType"

.field private static final B:Ljava/lang/String; = "contentType"

.field private static final C:Ljava/lang/String; = "notificationMessage"

.field private static final D:I = 0x1

.field public static final a:Ljava/lang/String; = "requestId"

.field public static final b:Ljava/lang/String; = "title"

.field public static final c:Ljava/lang/String; = "alert"

.field public static final d:Ljava/lang/String; = "sound"

.field public static final e:Ljava/lang/String; = "media"

.field public static final f:Ljava/lang/String; = "url"

.field public static final g:Ljava/lang/String; = "custom"

.field public static final h:Ljava/lang/String; = "keys"

.field public static final i:Ljava/lang/String; = "subtitle"

.field public static final j:Ljava/lang/String; = "type"

.field public static final k:Ljava/lang/String; = "androidUrl"

.field public static final l:Ljava/lang/String; = "alt"

.field public static final m:Ljava/lang/String; = "richFeatures"

.field public static final n:Ljava/lang/String; = "trigger"

.field public static final o:Ljava/lang/String; = "id"

.field private static final p:Ljava/lang/String; = "hash"

.field private static final q:Ljava/lang/String; = "subject"

.field private static final r:Ljava/lang/String; = "startDateUtc"

.field private static final s:Ljava/lang/String; = "endDateUtc"

.field private static final t:Ljava/lang/String; = "_endDt"

.field private static final u:Ljava/lang/String; = "sendDateUtc"

.field private static final v:Ljava/lang/String; = "viewCount"

.field private static final w:Ljava/lang/String; = "isDeleted"

.field private static final x:Ljava/lang/String; = "inboxMessage"

.field private static final y:Ljava/lang/String; = "inboxSubtitle"

.field private static final z:Ljava/lang/String; = "calculatedType"


# direct methods
.method public static final a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    const-string v0, "androidUrl"

    invoke-virtual {p0, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "optString(...)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 5
    const-string v2, "alt"

    .line 6
    invoke-static {p0, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-nez v0, :cond_1

    if-eqz p0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    return-object p0

    .line 7
    :cond_1
    :goto_0
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    if-nez v0, :cond_2

    const-string v0, ""

    :cond_2
    invoke-direct {v1, v0, p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    return-object v1
.end method

.method public static final a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;)Lorg/json/JSONObject;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;->getUrl()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;->getUrl()Ljava/lang/String;

    move-result-object v1

    const-string v2, "androidUrl"

    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 3
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;->getAltText()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;->getAltText()Ljava/lang/String;

    move-result-object p0

    const-string v1, "alt"

    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    :cond_1
    return-object v0
.end method
