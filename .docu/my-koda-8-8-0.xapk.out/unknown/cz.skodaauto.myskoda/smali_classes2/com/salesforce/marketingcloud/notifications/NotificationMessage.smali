.class public final Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;,
        Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;,
        Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;,
        Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

.field private static final KNOWN_KEYS:[Ljava/lang/String;

.field public static final NOTIF_KEY_ALERT:Ljava/lang/String; = "alert"

.field public static final NOTIF_KEY_CLOUD_PAGE_URL:Ljava/lang/String; = "_x"

.field public static final NOTIF_KEY_CONTENT_TYPE:Ljava/lang/String; = "_ct"

.field public static final NOTIF_KEY_END_DATE:Ljava/lang/String; = "_endDt"

.field public static final NOTIF_KEY_ID:Ljava/lang/String; = "_m"

.field public static final NOTIF_KEY_INBOX_MESSAGE:Ljava/lang/String; = "inboxMessage"

.field public static final NOTIF_KEY_INBOX_SUB_TITLE:Ljava/lang/String; = "inboxSubtitle"

.field public static final NOTIF_KEY_MEDIA_ALT:Ljava/lang/String; = "_mediaAlt"

.field public static final NOTIF_KEY_MEDIA_URL:Ljava/lang/String; = "_mediaUrl"

.field public static final NOTIF_KEY_MESSAGE_DATE_UTC:Ljava/lang/String; = "messageDateUtc"

.field public static final NOTIF_KEY_MESSAGE_HASH:Ljava/lang/String; = "_h"

.field public static final NOTIF_KEY_MESSAGE_TYPE:Ljava/lang/String; = "_mt"

.field public static final NOTIF_KEY_OPEN_DIRECT_URL:Ljava/lang/String; = "_od"

.field public static final NOTIF_KEY_PB_ID:Ljava/lang/String; = "_pb"

.field public static final NOTIF_KEY_REQUEST_ID:Ljava/lang/String; = "_r"

.field public static final NOTIF_KEY_RICH_FEATURES:Ljava/lang/String; = "_rf"

.field public static final NOTIF_KEY_SID:Ljava/lang/String; = "_sid"

.field public static final NOTIF_KEY_SOUND:Ljava/lang/String; = "sound"

.field public static final NOTIF_KEY_SUB_TITLE:Ljava/lang/String; = "subtitle"

.field public static final NOTIF_KEY_TIMESTAMP:Ljava/lang/String; = "timestamp"

.field public static final NOTIF_KEY_TITLE:Ljava/lang/String; = "title"


# instance fields
.field public final alert:Ljava/lang/String;

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

.field public final id:Ljava/lang/String;

.field public final mediaAltText:Ljava/lang/String;

.field public final mediaUrl:Ljava/lang/String;

.field private notificationId:I

.field public final payload:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final propertyBag:Ljava/lang/String;

.field public final region:Lcom/salesforce/marketingcloud/messages/Region;

.field public final requestId:Ljava/lang/String;

.field public final richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

.field public final sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

.field public final soundName:Ljava/lang/String;

.field public final subtitle:Ljava/lang/String;

.field public final title:Ljava/lang/String;

.field public final trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

.field public final type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

.field public final url:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->Companion:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    const-string v20, "_endDt"

    .line 17
    .line 18
    const-string v21, "messageDateUtc"

    .line 19
    .line 20
    const-string v1, "_m"

    .line 21
    .line 22
    const-string v2, "_sid"

    .line 23
    .line 24
    const-string v3, "timestamp"

    .line 25
    .line 26
    const-string v4, "_mt"

    .line 27
    .line 28
    const-string v5, "_h"

    .line 29
    .line 30
    const-string v6, "_r"

    .line 31
    .line 32
    const-string v7, "_pb"

    .line 33
    .line 34
    const-string v8, "title"

    .line 35
    .line 36
    const-string v9, "subtitle"

    .line 37
    .line 38
    const-string v10, "alert"

    .line 39
    .line 40
    const-string v11, "sound"

    .line 41
    .line 42
    const-string v12, "_mediaUrl"

    .line 43
    .line 44
    const-string v13, "_mediaAlt"

    .line 45
    .line 46
    const-string v14, "_x"

    .line 47
    .line 48
    const-string v15, "_od"

    .line 49
    .line 50
    const-string v16, "_ct"

    .line 51
    .line 52
    const-string v17, "inboxSubtitle"

    .line 53
    .line 54
    const-string v18, "inboxMessage"

    .line 55
    .line 56
    const-string v19, "_rf"

    .line 57
    .line 58
    filled-new-array/range {v1 .. v21}, [Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->KNOWN_KEYS:[Ljava/lang/String;

    .line 63
    .line 64
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;I)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/push/data/RichFeatures;",
            "Ljava/lang/String;",
            "I)V"
        }
    .end annotation

    move-object/from16 v0, p14

    const-string v1, "id"

    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "alert"

    invoke-static {p4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "sound"

    invoke-static {p5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "type"

    invoke-static {p9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "trigger"

    invoke-static {p10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "customKeys"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 8
    iput-object p7, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 9
    iput-object p8, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 10
    iput-object p9, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 11
    iput-object p10, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 12
    iput-object p11, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 13
    iput-object p12, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 14
    iput-object p13, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 15
    iput-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    move-object/from16 p1, p15

    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    move-object/from16 p1, p16

    .line 17
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    move-object/from16 p1, p17

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    move-object/from16 p1, p18

    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    move/from16 p1, p19

    .line 20
    iput p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILkotlin/jvm/internal/g;)V
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
    and-int/lit8 v1, v0, 0x4

    if-eqz v1, :cond_1

    move-object v6, v2

    goto :goto_1

    :cond_1
    move-object/from16 v6, p3

    :goto_1
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_2

    move-object v9, v2

    goto :goto_2

    :cond_2
    move-object/from16 v9, p6

    :goto_2
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_3

    move-object v10, v2

    goto :goto_3

    :cond_3
    move-object/from16 v10, p7

    :goto_3
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_4

    move-object v11, v2

    goto :goto_4

    :cond_4
    move-object/from16 v11, p8

    :goto_4
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_5

    move-object v14, v2

    goto :goto_5

    :cond_5
    move-object/from16 v14, p11

    :goto_5
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_6

    move-object v15, v2

    goto :goto_6

    :cond_6
    move-object/from16 v15, p12

    :goto_6
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_7

    move-object/from16 v16, v2

    goto :goto_7

    :cond_7
    move-object/from16 v16, p13

    :goto_7
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_8

    .line 21
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    move-object/from16 v17, v1

    goto :goto_8

    :cond_8
    move-object/from16 v17, p14

    :goto_8
    and-int/lit16 v1, v0, 0x4000

    if-eqz v1, :cond_9

    move-object/from16 v18, v2

    goto :goto_9

    :cond_9
    move-object/from16 v18, p15

    :goto_9
    const v1, 0x8000

    and-int/2addr v1, v0

    if-eqz v1, :cond_a

    move-object/from16 v19, v2

    goto :goto_a

    :cond_a
    move-object/from16 v19, p16

    :goto_a
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    if-eqz v1, :cond_b

    move-object/from16 v20, v2

    goto :goto_b

    :cond_b
    move-object/from16 v20, p17

    :goto_b
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_c

    move-object/from16 v21, v2

    goto :goto_c

    :cond_c
    move-object/from16 v21, p18

    :goto_c
    const/high16 v1, 0x40000

    and-int/2addr v0, v1

    if-eqz v0, :cond_d

    const/4 v0, -0x1

    move/from16 v22, v0

    :goto_d
    move-object/from16 v3, p0

    move-object/from16 v4, p1

    move-object/from16 v7, p4

    move-object/from16 v8, p5

    move-object/from16 v12, p9

    move-object/from16 v13, p10

    goto :goto_e

    :cond_d
    move/from16 v22, p19

    goto :goto_d

    .line 22
    :goto_e
    invoke-direct/range {v3 .. v22}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;I)V

    return-void
.end method

.method public static final synthetic access$getKNOWN_KEYS$cp()[Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->KNOWN_KEYS:[Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;IILjava/lang/Object;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
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
    iget-object v2, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

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
    iget-object v3, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

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
    iget-object v4, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

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
    iget-object v5, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

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
    iget-object v6, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

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
    iget-object v7, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

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
    iget-object v8, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

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
    iget-object v9, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 73
    .line 74
    goto :goto_7

    .line 75
    :cond_7
    move-object/from16 v9, p8

    .line 76
    .line 77
    :goto_7
    and-int/lit16 v10, v1, 0x100

    .line 78
    .line 79
    if-eqz v10, :cond_8

    .line 80
    .line 81
    iget-object v10, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 82
    .line 83
    goto :goto_8

    .line 84
    :cond_8
    move-object/from16 v10, p9

    .line 85
    .line 86
    :goto_8
    and-int/lit16 v11, v1, 0x200

    .line 87
    .line 88
    if-eqz v11, :cond_9

    .line 89
    .line 90
    iget-object v11, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

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
    iget-object v12, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 100
    .line 101
    goto :goto_a

    .line 102
    :cond_a
    move-object/from16 v12, p11

    .line 103
    .line 104
    :goto_a
    and-int/lit16 v13, v1, 0x800

    .line 105
    .line 106
    if-eqz v13, :cond_b

    .line 107
    .line 108
    iget-object v13, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 109
    .line 110
    goto :goto_b

    .line 111
    :cond_b
    move-object/from16 v13, p12

    .line 112
    .line 113
    :goto_b
    and-int/lit16 v14, v1, 0x1000

    .line 114
    .line 115
    if-eqz v14, :cond_c

    .line 116
    .line 117
    iget-object v14, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 118
    .line 119
    goto :goto_c

    .line 120
    :cond_c
    move-object/from16 v14, p13

    .line 121
    .line 122
    :goto_c
    and-int/lit16 v15, v1, 0x2000

    .line 123
    .line 124
    if-eqz v15, :cond_d

    .line 125
    .line 126
    iget-object v15, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 127
    .line 128
    goto :goto_d

    .line 129
    :cond_d
    move-object/from16 v15, p14

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
    iget-object v2, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 138
    .line 139
    goto :goto_e

    .line 140
    :cond_e
    move-object/from16 v2, p15

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
    iget-object v1, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 150
    .line 151
    goto :goto_f

    .line 152
    :cond_f
    move-object/from16 v1, p16

    .line 153
    .line 154
    :goto_f
    const/high16 v16, 0x10000

    .line 155
    .line 156
    and-int v16, p20, v16

    .line 157
    .line 158
    move-object/from16 p2, v1

    .line 159
    .line 160
    if-eqz v16, :cond_10

    .line 161
    .line 162
    iget-object v1, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

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
    iget-object v1, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

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
    iget v1, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 189
    .line 190
    move-object/from16 p19, p4

    .line 191
    .line 192
    move/from16 p20, v1

    .line 193
    .line 194
    :goto_12
    move-object/from16 p17, p2

    .line 195
    .line 196
    move-object/from16 p18, p3

    .line 197
    .line 198
    move-object/from16 p16, v2

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
    move-object/from16 p9, v9

    .line 213
    .line 214
    move-object/from16 p10, v10

    .line 215
    .line 216
    move-object/from16 p11, v11

    .line 217
    .line 218
    move-object/from16 p12, v12

    .line 219
    .line 220
    move-object/from16 p13, v13

    .line 221
    .line 222
    move-object/from16 p14, v14

    .line 223
    .line 224
    move-object/from16 p15, v15

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
    move/from16 p20, p19

    .line 232
    .line 233
    move-object/from16 p19, v1

    .line 234
    .line 235
    goto :goto_12

    .line 236
    :goto_13
    invoke-virtual/range {p1 .. p20}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->copy(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;I)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    return-object v0
.end method


# virtual methods
.method public final alert()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component14()Ljava/util/Map;
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component16()Ljava/util/Map;
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component17()Lcom/salesforce/marketingcloud/push/data/RichFeatures;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcom/salesforce/marketingcloud/messages/Region;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;I)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 21
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/push/data/RichFeatures;",
            "Ljava/lang/String;",
            "I)",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;"
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
    move-object/from16 v5, p4

    .line 11
    .line 12
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "sound"

    .line 16
    .line 17
    move-object/from16 v6, p5

    .line 18
    .line 19
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "type"

    .line 23
    .line 24
    move-object/from16 v10, p9

    .line 25
    .line 26
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v0, "trigger"

    .line 30
    .line 31
    move-object/from16 v11, p10

    .line 32
    .line 33
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v0, "customKeys"

    .line 37
    .line 38
    move-object/from16 v15, p14

    .line 39
    .line 40
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 44
    .line 45
    move-object/from16 v3, p2

    .line 46
    .line 47
    move-object/from16 v4, p3

    .line 48
    .line 49
    move-object/from16 v7, p6

    .line 50
    .line 51
    move-object/from16 v8, p7

    .line 52
    .line 53
    move-object/from16 v9, p8

    .line 54
    .line 55
    move-object/from16 v12, p11

    .line 56
    .line 57
    move-object/from16 v13, p12

    .line 58
    .line 59
    move-object/from16 v14, p13

    .line 60
    .line 61
    move-object/from16 v16, p15

    .line 62
    .line 63
    move-object/from16 v17, p16

    .line 64
    .line 65
    move-object/from16 v18, p17

    .line 66
    .line 67
    move-object/from16 v19, p18

    .line 68
    .line 69
    move/from16 v20, p19

    .line 70
    .line 71
    invoke-direct/range {v1 .. v20}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/Region;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/push/data/RichFeatures;Ljava/lang/String;I)V

    .line 72
    .line 73
    .line 74
    return-object v1
.end method

.method public final custom()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

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
    check-cast p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 58
    .line 59
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 60
    .line 61
    if-eq v1, v3, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 98
    .line 99
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 100
    .line 101
    if-eq v1, v3, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 105
    .line 106
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 107
    .line 108
    if-eq v1, v3, :cond_b

    .line 109
    .line 110
    return v2

    .line 111
    :cond_b
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 112
    .line 113
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    if-nez v1, :cond_c

    .line 120
    .line 121
    return v2

    .line 122
    :cond_c
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 123
    .line 124
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 125
    .line 126
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-nez v1, :cond_d

    .line 131
    .line 132
    return v2

    .line 133
    :cond_d
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 134
    .line 135
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 136
    .line 137
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-nez v1, :cond_e

    .line 142
    .line 143
    return v2

    .line 144
    :cond_e
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 145
    .line 146
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 147
    .line 148
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-nez v1, :cond_f

    .line 153
    .line 154
    return v2

    .line 155
    :cond_f
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 156
    .line 157
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 158
    .line 159
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    if-nez v1, :cond_10

    .line 164
    .line 165
    return v2

    .line 166
    :cond_10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 167
    .line 168
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 169
    .line 170
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-nez v1, :cond_11

    .line 175
    .line 176
    return v2

    .line 177
    :cond_11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 178
    .line 179
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 180
    .line 181
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    if-nez v1, :cond_12

    .line 186
    .line 187
    return v2

    .line 188
    :cond_12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 189
    .line 190
    iget-object v3, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 191
    .line 192
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result v1

    .line 196
    if-nez v1, :cond_13

    .line 197
    .line 198
    return v2

    .line 199
    :cond_13
    iget p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 200
    .line 201
    iget p1, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 202
    .line 203
    if-eq p0, p1, :cond_14

    .line 204
    .line 205
    return v2

    .line 206
    :cond_14
    return v0
.end method

.method public final getNotificationId$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 2
    .line 3
    return p0
.end method

.method public final getPropertyBag$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 24
    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    move v2, v3

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/Region;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    :goto_1
    add-int/2addr v0, v2

    .line 34
    mul-int/2addr v0, v1

    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    add-int/2addr v2, v0

    .line 48
    mul-int/2addr v2, v1

    .line 49
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 50
    .line 51
    if-nez v0, :cond_2

    .line 52
    .line 53
    move v0, v3

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    :goto_2
    add-int/2addr v2, v0

    .line 60
    mul-int/2addr v2, v1

    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 62
    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    move v0, v3

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    :goto_3
    add-int/2addr v2, v0

    .line 72
    mul-int/2addr v2, v1

    .line 73
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v0, :cond_4

    .line 76
    .line 77
    move v0, v3

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    :goto_4
    add-int/2addr v2, v0

    .line 84
    mul-int/2addr v2, v1

    .line 85
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    add-int/2addr v0, v2

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 94
    .line 95
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    add-int/2addr v2, v0

    .line 100
    mul-int/2addr v2, v1

    .line 101
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v0, :cond_5

    .line 104
    .line 105
    move v0, v3

    .line 106
    goto :goto_5

    .line 107
    :cond_5
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    :goto_5
    add-int/2addr v2, v0

    .line 112
    mul-int/2addr v2, v1

    .line 113
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 114
    .line 115
    if-nez v0, :cond_6

    .line 116
    .line 117
    move v0, v3

    .line 118
    goto :goto_6

    .line 119
    :cond_6
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    :goto_6
    add-int/2addr v2, v0

    .line 124
    mul-int/2addr v2, v1

    .line 125
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 126
    .line 127
    if-nez v0, :cond_7

    .line 128
    .line 129
    move v0, v3

    .line 130
    goto :goto_7

    .line 131
    :cond_7
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    :goto_7
    add-int/2addr v2, v0

    .line 136
    mul-int/2addr v2, v1

    .line 137
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 138
    .line 139
    invoke-static {v2, v1, v0}, Lp3/m;->a(IILjava/util/Map;)I

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 144
    .line 145
    if-nez v2, :cond_8

    .line 146
    .line 147
    move v2, v3

    .line 148
    goto :goto_8

    .line 149
    :cond_8
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    :goto_8
    add-int/2addr v0, v2

    .line 154
    mul-int/2addr v0, v1

    .line 155
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 156
    .line 157
    if-nez v2, :cond_9

    .line 158
    .line 159
    move v2, v3

    .line 160
    goto :goto_9

    .line 161
    :cond_9
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    :goto_9
    add-int/2addr v0, v2

    .line 166
    mul-int/2addr v0, v1

    .line 167
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 168
    .line 169
    if-nez v2, :cond_a

    .line 170
    .line 171
    move v2, v3

    .line 172
    goto :goto_a

    .line 173
    :cond_a
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->hashCode()I

    .line 174
    .line 175
    .line 176
    move-result v2

    .line 177
    :goto_a
    add-int/2addr v0, v2

    .line 178
    mul-int/2addr v0, v1

    .line 179
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 180
    .line 181
    if-nez v2, :cond_b

    .line 182
    .line 183
    goto :goto_b

    .line 184
    :cond_b
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 185
    .line 186
    .line 187
    move-result v3

    .line 188
    :goto_b
    add-int/2addr v0, v3

    .line 189
    mul-int/2addr v0, v1

    .line 190
    iget p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 191
    .line 192
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 193
    .line 194
    .line 195
    move-result p0

    .line 196
    add-int/2addr p0, v0

    .line 197
    return p0
.end method

.method public final id()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final mediaAltText()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final mediaUrl()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final notificationId()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 2
    .line 3
    return p0
.end method

.method public final payload()Ljava/util/Map;
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final propertyBag()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final region()Lcom/salesforce/marketingcloud/messages/Region;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 2
    .line 3
    return-object p0
.end method

.method public final requestId()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final richFeatures()Lcom/salesforce/marketingcloud/push/data/RichFeatures;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setNotificationId$sdk_release(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 2
    .line 3
    return-void
.end method

.method public final sound()Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 2
    .line 3
    return-object p0
.end method

.method public final soundName()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final subtitle()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final title()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toJson$sdk_release()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "id"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    const-string v2, "requestId"

    .line 18
    .line 19
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 20
    .line 21
    .line 22
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 23
    .line 24
    const-string v2, "alert"

    .line 25
    .line 26
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    const-string v2, "sound"

    .line 36
    .line 37
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 38
    .line 39
    .line 40
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 41
    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 45
    .line 46
    .line 47
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 48
    .line 49
    if-eqz v1, :cond_2

    .line 50
    .line 51
    const-string v2, "title"

    .line 52
    .line 53
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 54
    .line 55
    .line 56
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 57
    .line 58
    if-eqz v1, :cond_3

    .line 59
    .line 60
    const-string v2, "subtitle"

    .line 61
    .line 62
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 63
    .line 64
    .line 65
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 66
    .line 67
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    const-string v2, "type"

    .line 72
    .line 73
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 74
    .line 75
    .line 76
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 77
    .line 78
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    const-string v2, "trigger"

    .line 83
    .line 84
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 85
    .line 86
    .line 87
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 88
    .line 89
    if-eqz v1, :cond_4

    .line 90
    .line 91
    const-string v2, "url"

    .line 92
    .line 93
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 94
    .line 95
    .line 96
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 97
    .line 98
    if-eqz v1, :cond_6

    .line 99
    .line 100
    new-instance v2, Lorg/json/JSONObject;

    .line 101
    .line 102
    invoke-direct {v2}, Lorg/json/JSONObject;-><init>()V

    .line 103
    .line 104
    .line 105
    const-string v3, "androidUrl"

    .line 106
    .line 107
    invoke-virtual {v2, v3, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 108
    .line 109
    .line 110
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 111
    .line 112
    if-eqz v1, :cond_5

    .line 113
    .line 114
    const-string v3, "alt"

    .line 115
    .line 116
    invoke-virtual {v2, v3, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 117
    .line 118
    .line 119
    :cond_5
    const-string v1, "media"

    .line 120
    .line 121
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 122
    .line 123
    .line 124
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 125
    .line 126
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-nez v1, :cond_7

    .line 131
    .line 132
    new-instance v1, Lorg/json/JSONObject;

    .line 133
    .line 134
    iget-object v2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 135
    .line 136
    invoke-direct {v1, v2}, Lorg/json/JSONObject;-><init>(Ljava/util/Map;)V

    .line 137
    .line 138
    .line 139
    const-string v2, "keys"

    .line 140
    .line 141
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 142
    .line 143
    .line 144
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 145
    .line 146
    if-eqz v1, :cond_8

    .line 147
    .line 148
    const-string v2, "custom"

    .line 149
    .line 150
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 151
    .line 152
    .line 153
    :cond_8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 154
    .line 155
    if-eqz p0, :cond_9

    .line 156
    .line 157
    const-string v1, "richFeatures"

    .line 158
    .line 159
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 160
    .line 161
    .line 162
    :cond_9
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 8
    .line 9
    iget-object v4, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 12
    .line 13
    iget-object v6, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v7, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v9, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 20
    .line 21
    iget-object v10, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 22
    .line 23
    iget-object v11, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v12, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v13, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v14, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 30
    .line 31
    iget-object v15, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 32
    .line 33
    move-object/from16 v16, v15

    .line 34
    .line 35
    iget-object v15, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 36
    .line 37
    move-object/from16 v17, v15

    .line 38
    .line 39
    iget-object v15, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 40
    .line 41
    move-object/from16 v18, v15

    .line 42
    .line 43
    iget-object v15, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 44
    .line 45
    iget v0, v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 46
    .line 47
    move/from16 p0, v0

    .line 48
    .line 49
    const-string v0, ", requestId="

    .line 50
    .line 51
    move-object/from16 v19, v15

    .line 52
    .line 53
    const-string v15, ", region="

    .line 54
    .line 55
    move-object/from16 v20, v14

    .line 56
    .line 57
    const-string v14, "NotificationMessage(id="

    .line 58
    .line 59
    invoke-static {v14, v1, v0, v2, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", alert="

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, ", sound="

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", soundName="

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, ", title="

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v1, ", subtitle="

    .line 96
    .line 97
    const-string v2, ", type="

    .line 98
    .line 99
    invoke-static {v0, v7, v1, v8, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", trigger="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", url="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    const-string v1, ", mediaUrl="

    .line 119
    .line 120
    const-string v2, ", mediaAltText="

    .line 121
    .line 122
    invoke-static {v0, v11, v1, v12, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", customKeys="

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    move-object/from16 v1, v20

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v1, ", custom="

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    move-object/from16 v1, v16

    .line 144
    .line 145
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    const-string v1, ", payload="

    .line 149
    .line 150
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    move-object/from16 v1, v17

    .line 154
    .line 155
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    const-string v1, ", richFeatures="

    .line 159
    .line 160
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    move-object/from16 v1, v18

    .line 164
    .line 165
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    const-string v1, ", propertyBag="

    .line 169
    .line 170
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    move-object/from16 v1, v19

    .line 174
    .line 175
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    const-string v1, ", notificationId="

    .line 179
    .line 180
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v1, ")"

    .line 184
    .line 185
    move/from16 v2, p0

    .line 186
    .line 187
    invoke-static {v2, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    return-object v0
.end method

.method public final trigger()Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 2
    .line 3
    return-object p0
.end method

.method public final type()Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final url()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 5

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region:Lcom/salesforce/marketingcloud/messages/Region;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/messages/Region;->writeToParcel(Landroid/os/Parcel;I)V

    .line 30
    .line 31
    .line 32
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->alert:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->sound:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Sound;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->soundName:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->title:Ljava/lang/String;

    .line 52
    .line 53
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->subtitle:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->type:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Type;

    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->trigger:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaUrl:Ljava/lang/String;

    .line 85
    .line 86
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->mediaAltText:Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->customKeys:Ljava/util/Map;

    .line 95
    .line 96
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    invoke-virtual {p1, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 101
    .line 102
    .line 103
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    if-eqz v3, :cond_1

    .line 116
    .line 117
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    check-cast v3, Ljava/util/Map$Entry;

    .line 122
    .line 123
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    check-cast v4, Ljava/lang/String;

    .line 128
    .line 129
    invoke-virtual {p1, v4}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    check-cast v3, Ljava/lang/String;

    .line 137
    .line 138
    invoke-virtual {p1, v3}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->custom:Ljava/lang/String;

    .line 143
    .line 144
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->payload:Ljava/util/Map;

    .line 148
    .line 149
    if-nez v0, :cond_2

    .line 150
    .line 151
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 152
    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_2
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 156
    .line 157
    .line 158
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 159
    .line 160
    .line 161
    move-result v3

    .line 162
    invoke-virtual {p1, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 163
    .line 164
    .line 165
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    if-eqz v3, :cond_3

    .line 178
    .line 179
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    check-cast v3, Ljava/util/Map$Entry;

    .line 184
    .line 185
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    check-cast v4, Ljava/lang/String;

    .line 190
    .line 191
    invoke-virtual {p1, v4}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    check-cast v3, Ljava/lang/String;

    .line 199
    .line 200
    invoke-virtual {p1, v3}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_3
    :goto_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    .line 205
    .line 206
    if-nez v0, :cond_4

    .line 207
    .line 208
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 209
    .line 210
    .line 211
    goto :goto_4

    .line 212
    :cond_4
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->writeToParcel(Landroid/os/Parcel;I)V

    .line 216
    .line 217
    .line 218
    :goto_4
    iget-object p2, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag:Ljava/lang/String;

    .line 219
    .line 220
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    iget p0, p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->notificationId:I

    .line 224
    .line 225
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 226
    .line 227
    .line 228
    return-void
.end method
