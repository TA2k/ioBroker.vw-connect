.class public final Lcom/salesforce/marketingcloud/messages/Message;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/Message$Companion;,
        Lcom/salesforce/marketingcloud/messages/Message$Media;,
        Lcom/salesforce/marketingcloud/messages/Message$MessageType;
    }
.end annotation


# static fields
.field public static final CONTENT_TYPE_ALERT:I = 0x1

.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/messages/Message$Companion;

.field public static final MESSAGE_TYPE_FENCE_ENTRY:I = 0x3

.field public static final MESSAGE_TYPE_FENCE_EXIT:I = 0x4

.field public static final MESSAGE_TYPE_NONE:I = 0x0

.field public static final MESSAGE_TYPE_PROXIMITY:I = 0x5

.field public static final PERIOD_TYPE_UNIT_DAY:I = 0x4

.field public static final PERIOD_TYPE_UNIT_HOUR:I = 0x5

.field public static final PERIOD_TYPE_UNIT_MONTH:I = 0x2

.field public static final PERIOD_TYPE_UNIT_NONE:I = 0x0

.field public static final PERIOD_TYPE_UNIT_WEEK:I = 0x3

.field public static final PERIOD_TYPE_UNIT_YEAR:I = 0x1

.field public static final PROXIMITY_UNKNOWN:I

.field private static final TAG:Ljava/lang/String;


# instance fields
.field public final alert:Ljava/lang/String;

.field public final contentType:I

.field public final custom:Ljava/lang/String;

.field public final customKeys:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public final endDateUtc:Ljava/util/Date;

.field public final id:Ljava/lang/String;

.field public final isRollingPeriod:Z

.field private lastShownDate:Ljava/util/Date;

.field public final media:Lcom/salesforce/marketingcloud/messages/Message$Media;

.field public final messageLimit:I

.field public final messageType:I

.field public final messagesPerPeriod:I

.field private nextAllowedShow:Ljava/util/Date;

.field private notificationId:I

.field public final numberOfPeriods:I

.field public final openDirect:Ljava/lang/String;

.field private periodShowCount:I

.field public final periodType:I

.field public final proximity:I

.field private showCount:I

.field public final sound:Ljava/lang/String;

.field public final startDateUtc:Ljava/util/Date;

.field public final title:Ljava/lang/String;

.field public final url:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/Message$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/Message$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/Message;->Companion:Lcom/salesforce/marketingcloud/messages/Message$Companion;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/messages/Message$a;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/Message$a;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/messages/Message;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    const-string v0, "Message"

    .line 17
    .line 18
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lcom/salesforce/marketingcloud/messages/Message;->TAG:Ljava/lang/String;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/Message$Media;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "II",
            "Ljava/lang/String;",
            "IIIZII",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "alert"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 8
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 9
    iput p8, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 10
    iput p9, p0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 11
    iput-object p10, p0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 12
    iput p11, p0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 13
    iput p12, p0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 14
    iput p13, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 15
    iput-boolean p14, p0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    move/from16 p1, p15

    .line 16
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    move/from16 p1, p16

    .line 17
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    move-object/from16 p1, p17

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    move-object/from16 p1, p18

    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    move-object/from16 p1, p19

    .line 20
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    const/4 p1, -0x1

    .line 21
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->notificationId:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 23

    move/from16 v0, p20

    and-int/lit8 v1, v0, 0x2

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move-object v5, v2

    goto :goto_0

    :cond_0
    move-object/from16 v5, p2

    :goto_0
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_1

    move-object v7, v2

    goto :goto_1

    :cond_1
    move-object/from16 v7, p4

    :goto_1
    and-int/lit8 v1, v0, 0x10

    if-eqz v1, :cond_2

    move-object v8, v2

    goto :goto_2

    :cond_2
    move-object/from16 v8, p5

    :goto_2
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_3

    move-object v9, v2

    goto :goto_3

    :cond_3
    move-object/from16 v9, p6

    :goto_3
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_4

    move-object v10, v2

    goto :goto_4

    :cond_4
    move-object/from16 v10, p7

    :goto_4
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_5

    move-object v13, v2

    goto :goto_5

    :cond_5
    move-object/from16 v13, p10

    :goto_5
    and-int/lit16 v1, v0, 0x400

    const/4 v3, -0x1

    if-eqz v1, :cond_6

    move v14, v3

    goto :goto_6

    :cond_6
    move/from16 v14, p11

    :goto_6
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_7

    move v15, v3

    goto :goto_7

    :cond_7
    move/from16 v15, p12

    :goto_7
    and-int/lit16 v1, v0, 0x1000

    const/4 v4, 0x0

    if-eqz v1, :cond_8

    move/from16 v16, v4

    goto :goto_8

    :cond_8
    move/from16 v16, p13

    :goto_8
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_9

    move/from16 v17, v4

    goto :goto_9

    :cond_9
    move/from16 v17, p14

    :goto_9
    and-int/lit16 v1, v0, 0x4000

    if-eqz v1, :cond_a

    move/from16 v18, v3

    goto :goto_a

    :cond_a
    move/from16 v18, p15

    :goto_a
    const v1, 0x8000

    and-int/2addr v1, v0

    if-eqz v1, :cond_b

    move/from16 v19, v4

    goto :goto_b

    :cond_b
    move/from16 v19, p16

    :goto_b
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    if-eqz v1, :cond_c

    move-object/from16 v20, v2

    goto :goto_c

    :cond_c
    move-object/from16 v20, p17

    :goto_c
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_d

    move-object/from16 v21, v2

    goto :goto_d

    :cond_d
    move-object/from16 v21, p18

    :goto_d
    const/high16 v1, 0x40000

    and-int/2addr v0, v1

    if-eqz v0, :cond_e

    move-object/from16 v22, v2

    :goto_e
    move-object/from16 v3, p0

    move-object/from16 v4, p1

    move-object/from16 v6, p3

    move/from16 v11, p8

    move/from16 v12, p9

    goto :goto_f

    :cond_e
    move-object/from16 v22, p19

    goto :goto_e

    .line 22
    :goto_f
    invoke-direct/range {v3 .. v22}, Lcom/salesforce/marketingcloud/messages/Message;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 22

    move-object/from16 v0, p1

    const-string v1, "json"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    const-string v1, "id"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 24
    const-string v1, "title"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    .line 25
    const-string v1, "alert"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    .line 26
    const-string v1, "sound"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 27
    sget-object v1, Lcom/salesforce/marketingcloud/messages/Message$Media;->Companion:Lcom/salesforce/marketingcloud/messages/Message$Media$a;

    const-string v2, "media"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v2

    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/messages/Message$Media$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/Message$Media;

    move-result-object v7

    .line 28
    const-string v1, "startDateUtc"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v1

    move-object v8, v1

    goto :goto_0

    :cond_0
    const/4 v8, 0x0

    .line 29
    :goto_0
    const-string v1, "endDateUtc"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v1

    move-object v9, v1

    goto :goto_1

    :cond_1
    const/4 v9, 0x0

    .line 30
    :goto_1
    const-string v1, "messageType"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v10

    .line 31
    const-string v1, "contentType"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v11

    .line 32
    const-string v1, "url"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    .line 33
    const-string v1, "openDirect"

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v19

    .line 34
    const-string v1, "messageObjectPerPeriod"

    const/4 v13, -0x1

    invoke-virtual {v0, v1, v13}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v1

    .line 35
    const-string v14, "numberOfPeriods"

    invoke-virtual {v0, v14, v13}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v14

    .line 36
    const-string v15, "periodType"

    const/4 v2, 0x0

    invoke-virtual {v0, v15, v2}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v15

    .line 37
    const-string v2, "isRollingPeriod"

    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;)Z

    move-result v2

    move/from16 v18, v1

    .line 38
    const-string v1, "messageLimit"

    invoke-virtual {v0, v1, v13}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v1

    .line 39
    const-string v13, "proximity"

    move/from16 v20, v1

    const/4 v1, 0x0

    invoke-virtual {v0, v13, v1}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v1

    .line 40
    const-string v13, "keys"

    invoke-virtual {v0, v13}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v13

    if-eqz v13, :cond_2

    invoke-static {v13}, Lcom/salesforce/marketingcloud/internal/o;->b(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object v13

    move-object/from16 v16, v13

    goto :goto_2

    :cond_2
    const/16 v16, 0x0

    .line 41
    :goto_2
    const-string v13, "custom"

    invoke-static {v0, v13}, Lcom/salesforce/marketingcloud/extensions/PushExtensionsKt;->getStringOrNull(Lorg/json/JSONObject;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v21

    .line 42
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 43
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    move/from16 v13, v18

    move/from16 v17, v20

    move/from16 v18, v1

    move-object/from16 v20, v16

    move/from16 v16, v2

    move-object/from16 v2, p0

    .line 44
    invoke-direct/range {v2 .. v21}, Lcom/salesforce/marketingcloud/messages/Message;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)V

    return-void
.end method

.method public static final synthetic access$getTAG$cp()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/Message;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/messages/Message;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/messages/Message;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p20

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object/from16 v2, p1

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    iget-object v3, v0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object/from16 v3, p2

    .line 22
    .line 23
    :goto_1
    and-int/lit8 v4, v1, 0x4

    .line 24
    .line 25
    if-eqz v4, :cond_2

    .line 26
    .line 27
    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 28
    .line 29
    goto :goto_2

    .line 30
    :cond_2
    move-object/from16 v4, p3

    .line 31
    .line 32
    :goto_2
    and-int/lit8 v5, v1, 0x8

    .line 33
    .line 34
    if-eqz v5, :cond_3

    .line 35
    .line 36
    iget-object v5, v0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 37
    .line 38
    goto :goto_3

    .line 39
    :cond_3
    move-object/from16 v5, p4

    .line 40
    .line 41
    :goto_3
    and-int/lit8 v6, v1, 0x10

    .line 42
    .line 43
    if-eqz v6, :cond_4

    .line 44
    .line 45
    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_4
    move-object/from16 v6, p5

    .line 49
    .line 50
    :goto_4
    and-int/lit8 v7, v1, 0x20

    .line 51
    .line 52
    if-eqz v7, :cond_5

    .line 53
    .line 54
    iget-object v7, v0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 55
    .line 56
    goto :goto_5

    .line 57
    :cond_5
    move-object/from16 v7, p6

    .line 58
    .line 59
    :goto_5
    and-int/lit8 v8, v1, 0x40

    .line 60
    .line 61
    if-eqz v8, :cond_6

    .line 62
    .line 63
    iget-object v8, v0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 64
    .line 65
    goto :goto_6

    .line 66
    :cond_6
    move-object/from16 v8, p7

    .line 67
    .line 68
    :goto_6
    and-int/lit16 v9, v1, 0x80

    .line 69
    .line 70
    if-eqz v9, :cond_7

    .line 71
    .line 72
    iget v9, v0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 73
    .line 74
    goto :goto_7

    .line 75
    :cond_7
    move/from16 v9, p8

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 78
    .line 79
    if-eqz v10, :cond_8

    .line 80
    .line 81
    iget v10, v0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 82
    .line 83
    goto :goto_8

    .line 84
    :cond_8
    move/from16 v10, p9

    .line 85
    .line 86
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 87
    .line 88
    if-eqz v11, :cond_9

    .line 89
    .line 90
    iget-object v11, v0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 91
    .line 92
    goto :goto_9

    .line 93
    :cond_9
    move-object/from16 v11, p10

    .line 94
    .line 95
    :goto_9
    and-int/lit16 v12, v1, 0x400

    .line 96
    .line 97
    if-eqz v12, :cond_a

    .line 98
    .line 99
    iget v12, v0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 100
    .line 101
    goto :goto_a

    .line 102
    :cond_a
    move/from16 v12, p11

    .line 103
    .line 104
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 105
    .line 106
    if-eqz v13, :cond_b

    .line 107
    .line 108
    iget v13, v0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 109
    .line 110
    goto :goto_b

    .line 111
    :cond_b
    move/from16 v13, p12

    .line 112
    .line 113
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 114
    .line 115
    if-eqz v14, :cond_c

    .line 116
    .line 117
    iget v14, v0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 118
    .line 119
    goto :goto_c

    .line 120
    :cond_c
    move/from16 v14, p13

    .line 121
    .line 122
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 123
    .line 124
    if-eqz v15, :cond_d

    .line 125
    .line 126
    iget-boolean v15, v0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move/from16 v15, p14

    .line 130
    .line 131
    :goto_d
    move-object/from16 p1, v2

    .line 132
    .line 133
    and-int/lit16 v2, v1, 0x4000

    .line 134
    .line 135
    if-eqz v2, :cond_e

    .line 136
    .line 137
    iget v2, v0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 138
    .line 139
    goto :goto_e

    .line 140
    :cond_e
    move/from16 v2, p15

    .line 141
    .line 142
    :goto_e
    const v16, 0x8000

    .line 143
    .line 144
    .line 145
    and-int v16, v1, v16

    .line 146
    .line 147
    if-eqz v16, :cond_f

    .line 148
    .line 149
    iget v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 150
    .line 151
    goto :goto_f

    .line 152
    :cond_f
    move/from16 v1, p16

    .line 153
    .line 154
    :goto_f
    const/high16 v16, 0x10000

    .line 155
    .line 156
    and-int v16, p20, v16

    .line 157
    .line 158
    move/from16 p2, v1

    .line 159
    .line 160
    if-eqz v16, :cond_10

    .line 161
    .line 162
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 163
    .line 164
    goto :goto_10

    .line 165
    :cond_10
    move-object/from16 v1, p17

    .line 166
    .line 167
    :goto_10
    const/high16 v16, 0x20000

    .line 168
    .line 169
    and-int v16, p20, v16

    .line 170
    .line 171
    move-object/from16 p3, v1

    .line 172
    .line 173
    if-eqz v16, :cond_11

    .line 174
    .line 175
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 176
    .line 177
    goto :goto_11

    .line 178
    :cond_11
    move-object/from16 v1, p18

    .line 179
    .line 180
    :goto_11
    const/high16 v16, 0x40000

    .line 181
    .line 182
    and-int v16, p20, v16

    .line 183
    .line 184
    if-eqz v16, :cond_12

    .line 185
    .line 186
    move-object/from16 p4, v1

    .line 187
    .line 188
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 189
    .line 190
    move-object/from16 p19, p4

    .line 191
    .line 192
    move-object/from16 p20, v1

    .line 193
    .line 194
    :goto_12
    move/from16 p17, p2

    .line 195
    .line 196
    move-object/from16 p18, p3

    .line 197
    .line 198
    move/from16 p16, v2

    .line 199
    .line 200
    move-object/from16 p3, v3

    .line 201
    .line 202
    move-object/from16 p4, v4

    .line 203
    .line 204
    move-object/from16 p5, v5

    .line 205
    .line 206
    move-object/from16 p6, v6

    .line 207
    .line 208
    move-object/from16 p7, v7

    .line 209
    .line 210
    move-object/from16 p8, v8

    .line 211
    .line 212
    move/from16 p9, v9

    .line 213
    .line 214
    move/from16 p10, v10

    .line 215
    .line 216
    move-object/from16 p11, v11

    .line 217
    .line 218
    move/from16 p12, v12

    .line 219
    .line 220
    move/from16 p13, v13

    .line 221
    .line 222
    move/from16 p14, v14

    .line 223
    .line 224
    move/from16 p15, v15

    .line 225
    .line 226
    move-object/from16 p2, p1

    .line 227
    .line 228
    move-object/from16 p1, v0

    .line 229
    .line 230
    goto :goto_13

    .line 231
    :cond_12
    move-object/from16 p20, p19

    .line 232
    .line 233
    move-object/from16 p19, v1

    .line 234
    .line 235
    goto :goto_12

    .line 236
    :goto_13
    invoke-virtual/range {p1 .. p20}, Lcom/salesforce/marketingcloud/messages/Message;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/Message;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    return-object v0
.end method

.method public static synthetic getLastShownDate$sdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getNextAllowedShow$sdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getNotificationId$sdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getPeriodShowCount$sdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getShowCount$sdk_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final alert()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 2
    .line 3
    return p0
.end method

.method public final component12()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 2
    .line 3
    return p0
.end method

.method public final component13()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 2
    .line 3
    return p0
.end method

.method public final component14()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component15()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 2
    .line 3
    return p0
.end method

.method public final component16()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 2
    .line 3
    return p0
.end method

.method public final component17()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Lcom/salesforce/marketingcloud/messages/Message$Media;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 2
    .line 3
    return p0
.end method

.method public final component9()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 2
    .line 3
    return p0
.end method

.method public final contentType()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/Message;
    .locals 21
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/Message$Media;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "II",
            "Ljava/lang/String;",
            "IIIZII",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            ")",
            "Lcom/salesforce/marketingcloud/messages/Message;"
        }
    .end annotation

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "alert"

    .line 9
    .line 10
    move-object/from16 v4, p3

    .line 11
    .line 12
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lcom/salesforce/marketingcloud/messages/Message;

    .line 16
    .line 17
    move-object/from16 v3, p2

    .line 18
    .line 19
    move-object/from16 v5, p4

    .line 20
    .line 21
    move-object/from16 v6, p5

    .line 22
    .line 23
    move-object/from16 v7, p6

    .line 24
    .line 25
    move-object/from16 v8, p7

    .line 26
    .line 27
    move/from16 v9, p8

    .line 28
    .line 29
    move/from16 v10, p9

    .line 30
    .line 31
    move-object/from16 v11, p10

    .line 32
    .line 33
    move/from16 v12, p11

    .line 34
    .line 35
    move/from16 v13, p12

    .line 36
    .line 37
    move/from16 v14, p13

    .line 38
    .line 39
    move/from16 v15, p14

    .line 40
    .line 41
    move/from16 v16, p15

    .line 42
    .line 43
    move/from16 v17, p16

    .line 44
    .line 45
    move-object/from16 v18, p17

    .line 46
    .line 47
    move-object/from16 v19, p18

    .line 48
    .line 49
    move-object/from16 v20, p19

    .line 50
    .line 51
    invoke-direct/range {v1 .. v20}, Lcom/salesforce/marketingcloud/messages/Message;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Message$Media;Ljava/util/Date;Ljava/util/Date;IILjava/lang/String;IIIZIILjava/lang/String;Ljava/util/Map;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    return-object v1
.end method

.method public final custom()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final customKeys()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final endDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/messages/Message;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/messages/Message;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 58
    .line 59
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 69
    .line 70
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 80
    .line 81
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 91
    .line 92
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 93
    .line 94
    if-eq v1, v3, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 98
    .line 99
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 100
    .line 101
    if-eq v1, v3, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 107
    .line 108
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_b

    .line 113
    .line 114
    return v2

    .line 115
    :cond_b
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 116
    .line 117
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 118
    .line 119
    if-eq v1, v3, :cond_c

    .line 120
    .line 121
    return v2

    .line 122
    :cond_c
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 123
    .line 124
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 125
    .line 126
    if-eq v1, v3, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 130
    .line 131
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 132
    .line 133
    if-eq v1, v3, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 137
    .line 138
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 139
    .line 140
    if-eq v1, v3, :cond_f

    .line 141
    .line 142
    return v2

    .line 143
    :cond_f
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 144
    .line 145
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 146
    .line 147
    if-eq v1, v3, :cond_10

    .line 148
    .line 149
    return v2

    .line 150
    :cond_10
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 151
    .line 152
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 153
    .line 154
    if-eq v1, v3, :cond_11

    .line 155
    .line 156
    return v2

    .line 157
    :cond_11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 158
    .line 159
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 160
    .line 161
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-nez v1, :cond_12

    .line 166
    .line 167
    return v2

    .line 168
    :cond_12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 169
    .line 170
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 171
    .line 172
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    if-nez v1, :cond_13

    .line 177
    .line 178
    return v2

    .line 179
    :cond_13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 180
    .line 181
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 182
    .line 183
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result p0

    .line 187
    if-nez p0, :cond_14

    .line 188
    .line 189
    return v2

    .line 190
    :cond_14
    return v0
.end method

.method public final getLastShownDate$sdk_release()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->lastShownDate:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNextAllowedShow$sdk_release()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->nextAllowedShow:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNotificationId$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->notificationId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getPeriodShowCount$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodShowCount:I

    .line 2
    .line 3
    return p0
.end method

.method public final getShowCount$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->showCount:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    move v2, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    :goto_0
    add-int/2addr v0, v2

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v2, :cond_1

    .line 32
    .line 33
    move v2, v3

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    :goto_1
    add-int/2addr v0, v2

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 42
    .line 43
    if-nez v2, :cond_2

    .line 44
    .line 45
    move v2, v3

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    :goto_2
    add-int/2addr v0, v2

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 54
    .line 55
    if-nez v2, :cond_3

    .line 56
    .line 57
    move v2, v3

    .line 58
    goto :goto_3

    .line 59
    :cond_3
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_3
    add-int/2addr v0, v2

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 66
    .line 67
    if-nez v2, :cond_4

    .line 68
    .line 69
    move v2, v3

    .line 70
    goto :goto_4

    .line 71
    :cond_4
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    :goto_4
    add-int/2addr v0, v2

    .line 76
    mul-int/2addr v0, v1

    .line 77
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 78
    .line 79
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 84
    .line 85
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v2, :cond_5

    .line 92
    .line 93
    move v2, v3

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    :goto_5
    add-int/2addr v0, v2

    .line 100
    mul-int/2addr v0, v1

    .line 101
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 102
    .line 103
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 108
    .line 109
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 114
    .line 115
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 120
    .line 121
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 126
    .line 127
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 132
    .line 133
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 138
    .line 139
    if-nez v2, :cond_6

    .line 140
    .line 141
    move v2, v3

    .line 142
    goto :goto_6

    .line 143
    :cond_6
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 144
    .line 145
    .line 146
    move-result v2

    .line 147
    :goto_6
    add-int/2addr v0, v2

    .line 148
    mul-int/2addr v0, v1

    .line 149
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 150
    .line 151
    if-nez v2, :cond_7

    .line 152
    .line 153
    move v2, v3

    .line 154
    goto :goto_7

    .line 155
    :cond_7
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 156
    .line 157
    .line 158
    move-result v2

    .line 159
    :goto_7
    add-int/2addr v0, v2

    .line 160
    mul-int/2addr v0, v1

    .line 161
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 162
    .line 163
    if-nez p0, :cond_8

    .line 164
    .line 165
    goto :goto_8

    .line 166
    :cond_8
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    :goto_8
    add-int/2addr v0, v3

    .line 171
    return v0
.end method

.method public final id()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isRollingPeriod()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 2
    .line 3
    return p0
.end method

.method public final media()Lcom/salesforce/marketingcloud/messages/Message$Media;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 2
    .line 3
    return-object p0
.end method

.method public final messageLimit()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 2
    .line 3
    return p0
.end method

.method public final messageType()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 2
    .line 3
    return p0
.end method

.method public final messagesPerPeriod()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 2
    .line 3
    return p0
.end method

.method public final numberOfPeriods()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 2
    .line 3
    return p0
.end method

.method public final openDirect()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final periodType()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 2
    .line 3
    return p0
.end method

.method public final proximity()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 2
    .line 3
    return p0
.end method

.method public final setLastShownDate$sdk_release(Ljava/util/Date;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->lastShownDate:Ljava/util/Date;

    .line 2
    .line 3
    return-void
.end method

.method public final setNextAllowedShow$sdk_release(Ljava/util/Date;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->nextAllowedShow:Ljava/util/Date;

    .line 2
    .line 3
    return-void
.end method

.method public final setNotificationId$sdk_release(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->notificationId:I

    .line 2
    .line 3
    return-void
.end method

.method public final setPeriodShowCount$sdk_release(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodShowCount:I

    .line 2
    .line 3
    return-void
.end method

.method public final setShowCount$sdk_release(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/Message;->showCount:I

    .line 2
    .line 3
    return-void
.end method

.method public final sound()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final startDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final title()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 12
    .line 13
    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 14
    .line 15
    iget-object v7, v0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 16
    .line 17
    iget v8, v0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 18
    .line 19
    iget v9, v0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 20
    .line 21
    iget-object v10, v0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 22
    .line 23
    iget v11, v0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 24
    .line 25
    iget v12, v0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 26
    .line 27
    iget v13, v0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 28
    .line 29
    iget-boolean v14, v0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 30
    .line 31
    iget v15, v0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 32
    .line 33
    move/from16 v16, v15

    .line 34
    .line 35
    iget v15, v0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 36
    .line 37
    move/from16 v17, v15

    .line 38
    .line 39
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 40
    .line 41
    move-object/from16 v18, v15

    .line 42
    .line 43
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 44
    .line 45
    iget-object v0, v0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 46
    .line 47
    move-object/from16 p0, v0

    .line 48
    .line 49
    const-string v0, ", title="

    .line 50
    .line 51
    move-object/from16 v19, v15

    .line 52
    .line 53
    const-string v15, ", alert="

    .line 54
    .line 55
    move/from16 v20, v14

    .line 56
    .line 57
    const-string v14, "Message(id="

    .line 58
    .line 59
    invoke-static {v14, v1, v0, v2, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    const-string v1, ", sound="

    .line 64
    .line 65
    const-string v2, ", media="

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", startDateUtc="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", endDateUtc="

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v1, ", messageType="

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", contentType="

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", url="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", messagesPerPeriod="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    const-string v1, ", numberOfPeriods="

    .line 119
    .line 120
    const-string v2, ", periodType="

    .line 121
    .line 122
    invoke-static {v0, v11, v1, v12, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", isRollingPeriod="

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    move/from16 v1, v20

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v1, ", messageLimit="

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    const-string v1, ", proximity="

    .line 144
    .line 145
    const-string v2, ", openDirect="

    .line 146
    .line 147
    move/from16 v3, v16

    .line 148
    .line 149
    move/from16 v4, v17

    .line 150
    .line 151
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 152
    .line 153
    .line 154
    move-object/from16 v1, v18

    .line 155
    .line 156
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    const-string v1, ", customKeys="

    .line 160
    .line 161
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    move-object/from16 v1, v19

    .line 165
    .line 166
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    const-string v1, ", custom="

    .line 170
    .line 171
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    const-string v1, ")"

    .line 175
    .line 176
    move-object/from16 v2, p0

    .line 177
    .line 178
    invoke-static {v0, v2, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    return-object v0
.end method

.method public final url()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Message;->id:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Message;->title:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Message;->alert:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Message;->sound:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/Message;->media:Lcom/salesforce/marketingcloud/messages/Message$Media;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    const/4 v2, 0x0

    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/Message$Media;->writeToParcel(Landroid/os/Parcel;I)V

    .line 40
    .line 41
    .line 42
    :goto_0
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->startDateUtc:Ljava/util/Date;

    .line 43
    .line 44
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeSerializable(Ljava/io/Serializable;)V

    .line 45
    .line 46
    .line 47
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->endDateUtc:Ljava/util/Date;

    .line 48
    .line 49
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeSerializable(Ljava/io/Serializable;)V

    .line 50
    .line 51
    .line 52
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageType:I

    .line 53
    .line 54
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 55
    .line 56
    .line 57
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->contentType:I

    .line 58
    .line 59
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 60
    .line 61
    .line 62
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->url:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->messagesPerPeriod:I

    .line 68
    .line 69
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 70
    .line 71
    .line 72
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->numberOfPeriods:I

    .line 73
    .line 74
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 75
    .line 76
    .line 77
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->periodType:I

    .line 78
    .line 79
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 80
    .line 81
    .line 82
    iget-boolean p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->isRollingPeriod:Z

    .line 83
    .line 84
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 85
    .line 86
    .line 87
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->messageLimit:I

    .line 88
    .line 89
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 90
    .line 91
    .line 92
    iget p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->proximity:I

    .line 93
    .line 94
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 95
    .line 96
    .line 97
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->openDirect:Ljava/lang/String;

    .line 98
    .line 99
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/Message;->customKeys:Ljava/util/Map;

    .line 103
    .line 104
    if-nez p2, :cond_1

    .line 105
    .line 106
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_1
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 111
    .line 112
    .line 113
    invoke-interface {p2}, Ljava/util/Map;->size()I

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 118
    .line 119
    .line 120
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 121
    .line 122
    .line 123
    move-result-object p2

    .line 124
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object p2

    .line 128
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-eqz v0, :cond_2

    .line 133
    .line 134
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Ljava/util/Map$Entry;

    .line 139
    .line 140
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    check-cast v1, Ljava/lang/String;

    .line 145
    .line 146
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    check-cast v0, Ljava/lang/String;

    .line 154
    .line 155
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_2
    :goto_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/Message;->custom:Ljava/lang/String;

    .line 160
    .line 161
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    return-void
.end method
