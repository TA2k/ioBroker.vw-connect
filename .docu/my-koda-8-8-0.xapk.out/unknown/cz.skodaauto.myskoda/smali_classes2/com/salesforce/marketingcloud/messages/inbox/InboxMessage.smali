.class public final Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;,
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;,
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;,
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;
    }
.end annotation


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

.field private deleted:Z

.field private dirty:Z

.field public final endDateUtc:Ljava/util/Date;

.field public final id:Ljava/lang/String;

.field public final inboxMessage:Ljava/lang/String;

.field public final inboxSubtitle:Ljava/lang/String;

.field public final media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

.field private final messageHash:Ljava/lang/String;

.field public final messageType:Ljava/lang/Integer;

.field public notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

.field private read:Z

.field private final requestId:Ljava/lang/String;

.field public final sendDateUtc:Ljava/util/Date;

.field public final sound:Ljava/lang/String;

.field public final startDateUtc:Ljava/util/Date;

.field public final subject:Ljava/lang/String;

.field public final subtitle:Ljava/lang/String;

.field public final title:Ljava/lang/String;

.field public final url:Ljava/lang/String;

.field private final viewCount:I


# direct methods
.method public constructor <init>(Landroid/os/Bundle;)V
    .locals 26

    move-object/from16 v0, p1

    const-string v1, "bundle"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    const-string v1, "_m"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_13

    .line 25
    const-string v1, "_r"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    .line 26
    const-string v1, "_h"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    .line 27
    const-string v1, "title"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    .line 28
    const-string v1, "alert"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    .line 29
    const-string v1, "sound"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    .line 30
    const-string v1, "_mediaUrl"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 31
    const-string v2, "_mediaAlt"

    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 32
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v6

    const/4 v10, 0x0

    if-nez v6, :cond_0

    .line 33
    new-instance v6, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    invoke-direct {v6, v1, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    move-object v6, v10

    .line 34
    :goto_0
    const-string v1, "_x"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_1

    .line 35
    const-string v1, "_od"

    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    :cond_1
    move-object v14, v1

    .line 36
    invoke-virtual {v0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    move-result-object v1

    const-string v2, "keySet(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 38
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_2
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v11

    const/4 v12, 0x0

    if-eqz v11, :cond_4

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v11

    move-object v13, v11

    check-cast v13, Ljava/lang/String;

    .line 39
    sget-object v15, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->Companion:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a()[Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_3

    invoke-static {v13}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    const-string v15, ".google"

    .line 40
    invoke-static {v13, v15, v12}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v12

    if-eqz v12, :cond_2

    .line 41
    :cond_3
    invoke-virtual {v2, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    .line 42
    :cond_4
    new-instance v1, Ljava/util/LinkedHashMap;

    const/16 v11, 0xa

    invoke-static {v2, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    move-result v11

    invoke-static {v11}, Lmx0/x;->k(I)I

    move-result v11

    const/16 v13, 0x10

    if-ge v11, v13, :cond_5

    move v11, v13

    :cond_5
    invoke-direct {v1, v11}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 43
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v11

    if-eqz v11, :cond_6

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v11

    .line 44
    move-object v13, v11

    check-cast v13, Ljava/lang/String;

    .line 45
    invoke-virtual {v0, v13}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-static {v13}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v13

    .line 46
    invoke-interface {v1, v11, v13}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_2

    .line 47
    :cond_6
    const-string v2, "subtitle"

    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v17

    .line 48
    const-string v2, "inboxMessage"

    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v18

    .line 49
    const-string v11, "inboxSubtitle"

    invoke-virtual {v0, v11}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v19

    .line 50
    const-string v13, "_mt"

    invoke-virtual {v0, v13}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    const-string v15, "8"

    .line 51
    invoke-virtual {v15, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_a

    .line 52
    const-string v13, "_ct"

    invoke-virtual {v0, v13}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    .line 53
    sget-object v15, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->toString()Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    const/16 v16, 0x1

    if-eqz v15, :cond_7

    move/from16 v15, v16

    goto :goto_3

    :cond_7
    sget-object v15, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->toString()Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    :goto_3
    if-eqz v15, :cond_8

    move/from16 v15, v16

    goto :goto_4

    :cond_8
    sget-object v15, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->h:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->toString()Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    :goto_4
    if-eqz v15, :cond_9

    move/from16 v15, v16

    goto :goto_5

    :cond_9
    sget-object v15, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->i:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->toString()Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    :goto_5
    if-eqz v15, :cond_b

    sget-object v2, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->ADV:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    :cond_a
    :goto_6
    move-object/from16 v22, v10

    goto :goto_b

    .line 54
    :cond_b
    sget-object v15, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->f:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->toString()Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_c

    move/from16 v15, v16

    goto :goto_7

    :cond_c
    sget-object v15, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->g:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->toString()Ljava/lang/String;

    move-result-object v15

    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    :goto_7
    if-eqz v15, :cond_d

    goto :goto_8

    :cond_d
    if-nez v13, :cond_e

    :goto_8
    move/from16 v12, v16

    :cond_e
    if-eqz v12, :cond_a

    .line 55
    invoke-virtual {v0, v11}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    move-result v10

    if-nez v10, :cond_10

    .line 56
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_f

    goto :goto_9

    .line 57
    :cond_f
    sget-object v2, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->LEGACY:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v2

    goto :goto_a

    .line 58
    :cond_10
    :goto_9
    sget-object v2, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->ADV:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v2

    :goto_a
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    goto :goto_6

    :goto_b
    if-eqz v22, :cond_12

    .line 59
    const-string v2, "_endDt"

    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_11

    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/o;->b(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_11

    invoke-static {v0}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v12

    if-eqz v12, :cond_11

    const v24, 0x141508

    const/16 v25, 0x0

    move-object v10, v6

    const/4 v6, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v15, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v23, 0x0

    move-object/from16 v2, p0

    move-object/from16 v16, v1

    .line 60
    invoke-direct/range {v2 .. v25}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;ZILkotlin/jvm/internal/g;)V

    return-void

    .line 61
    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Missing or empty _endDt"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 62
    :cond_12
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Unknown Message- or Content Type."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 63
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Required value was null."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;Z)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;",
            "I",
            "Ljava/lang/Integer;",
            "Z)V"
        }
    .end annotation

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 7
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 8
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 9
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 10
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 11
    iput-object p10, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 12
    iput-object p11, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 13
    iput-object p12, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 14
    iput-object p13, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    .line 15
    iput-object p14, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    move-object/from16 p1, p15

    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    move-object/from16 p1, p16

    .line 17
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    move-object/from16 p1, p17

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    move-object/from16 p1, p18

    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move/from16 p1, p19

    .line 20
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    move-object/from16 p1, p20

    .line 21
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    move/from16 p1, p21

    .line 22
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;ZILkotlin/jvm/internal/g;)V
    .locals 25

    move/from16 v0, p22

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
    and-int/lit8 v1, v0, 0x8

    if-eqz v1, :cond_2

    move-object v7, v2

    goto :goto_2

    :cond_2
    move-object/from16 v7, p4

    :goto_2
    and-int/lit8 v1, v0, 0x10

    if-eqz v1, :cond_3

    move-object v8, v2

    goto :goto_3

    :cond_3
    move-object/from16 v8, p5

    :goto_3
    and-int/lit8 v1, v0, 0x20

    if-eqz v1, :cond_4

    move-object v9, v2

    goto :goto_4

    :cond_4
    move-object/from16 v9, p6

    :goto_4
    and-int/lit8 v1, v0, 0x40

    if-eqz v1, :cond_5

    move-object v10, v2

    goto :goto_5

    :cond_5
    move-object/from16 v10, p7

    :goto_5
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_6

    move-object v11, v2

    goto :goto_6

    :cond_6
    move-object/from16 v11, p8

    :goto_6
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_7

    move-object v12, v2

    goto :goto_7

    :cond_7
    move-object/from16 v12, p9

    :goto_7
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_8

    move-object v13, v2

    goto :goto_8

    :cond_8
    move-object/from16 v13, p10

    :goto_8
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_9

    move-object v14, v2

    goto :goto_9

    :cond_9
    move-object/from16 v14, p11

    :goto_9
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_a

    move-object/from16 v16, v2

    goto :goto_a

    :cond_a
    move-object/from16 v16, p13

    :goto_a
    and-int/lit16 v1, v0, 0x2000

    if-eqz v1, :cond_b

    move-object/from16 v17, v2

    goto :goto_b

    :cond_b
    move-object/from16 v17, p14

    :goto_b
    and-int/lit16 v1, v0, 0x4000

    if-eqz v1, :cond_c

    move-object/from16 v18, v2

    goto :goto_c

    :cond_c
    move-object/from16 v18, p15

    :goto_c
    const v1, 0x8000

    and-int/2addr v1, v0

    if-eqz v1, :cond_d

    move-object/from16 v19, v2

    goto :goto_d

    :cond_d
    move-object/from16 v19, p16

    :goto_d
    const/high16 v1, 0x10000

    and-int/2addr v1, v0

    if-eqz v1, :cond_e

    move-object/from16 v20, v2

    goto :goto_e

    :cond_e
    move-object/from16 v20, p17

    :goto_e
    const/high16 v1, 0x20000

    and-int/2addr v1, v0

    if-eqz v1, :cond_f

    move-object/from16 v21, v2

    goto :goto_f

    :cond_f
    move-object/from16 v21, p18

    :goto_f
    const/high16 v1, 0x40000

    and-int/2addr v1, v0

    const/4 v2, 0x0

    if-eqz v1, :cond_10

    move/from16 v22, v2

    goto :goto_10

    :cond_10
    move/from16 v22, p19

    :goto_10
    const/high16 v1, 0x100000

    and-int/2addr v0, v1

    if-eqz v0, :cond_11

    move/from16 v24, v2

    :goto_11
    move-object/from16 v3, p0

    move-object/from16 v4, p1

    move-object/from16 v15, p12

    move-object/from16 v23, p20

    goto :goto_12

    :cond_11
    move/from16 v24, p21

    goto :goto_11

    .line 23
    :goto_12
    invoke-direct/range {v3 .. v24}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;Z)V

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;Z)V
    .locals 29

    move-object/from16 v0, p1

    const-string v1, "inboxMessage"

    const-string v2, "inboxSubtitle"

    const-string v3, "contentType"

    const-string v4, "messageType"

    const-string v5, "calculatedType"

    const-string v6, "json"

    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    const-string v6, "id"

    invoke-virtual {v0, v6}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    .line 66
    const-string v6, "requestId"

    const-string v7, "optString(...)"

    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    .line 67
    const-string v6, "hash"

    .line 68
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    .line 69
    const-string v6, "isDeleted"

    invoke-virtual {v0, v6}, Lorg/json/JSONObject;->optBoolean(Ljava/lang/String;)Z

    move-result v28

    .line 70
    const-string v6, "startDateUtc"

    .line 71
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_1

    .line 72
    invoke-static {v6}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v6

    if-nez v6, :cond_0

    goto :goto_1

    :cond_0
    :goto_0
    move-object/from16 v16, v6

    goto :goto_2

    :cond_1
    :goto_1
    new-instance v6, Ljava/util/Date;

    invoke-direct {v6}, Ljava/util/Date;-><init>()V

    goto :goto_0

    .line 73
    :goto_2
    const-string v6, "endDateUtc"

    .line 74
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_2

    .line 75
    invoke-static {v6}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v6

    move-object/from16 v17, v6

    goto :goto_3

    :cond_2
    const/16 v17, 0x0

    .line 76
    :goto_3
    const-string v6, "sendDateUtc"

    .line 77
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_3

    .line 78
    invoke-static {v6}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v6

    move-object/from16 v18, v6

    goto :goto_4

    :cond_3
    const/16 v18, 0x0

    .line 79
    :goto_4
    const-string v6, "viewCount"

    const/4 v12, 0x0

    invoke-virtual {v0, v6, v12}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v26

    const/4 v6, 0x1

    const/4 v12, -0x1

    .line 80
    :try_start_0
    invoke-virtual {v0, v5, v12}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v13

    if-eq v13, v12, :cond_4

    invoke-virtual {v0, v5}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v12

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    goto/16 :goto_a

    .line 81
    :cond_4
    const-string v12, "8"

    invoke-static {v12}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v12

    invoke-virtual {v0, v4}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v13

    if-ne v12, v13, :cond_c

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v12

    .line 82
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c()I

    move-result v13

    if-ne v12, v13, :cond_5

    goto :goto_5

    :cond_5
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c()I

    move-result v13

    if-ne v12, v13, :cond_6

    goto :goto_5

    :cond_6
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->h:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c()I

    move-result v13

    if-ne v12, v13, :cond_7

    goto :goto_5

    :cond_7
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->i:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c()I

    move-result v13

    if-ne v12, v13, :cond_8

    :goto_5
    sget-object v12, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->ADV:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v12

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    goto :goto_a

    .line 83
    :cond_8
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->f:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c()I

    move-result v13

    if-ne v12, v13, :cond_9

    goto :goto_6

    :cond_9
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->g:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$a;->c()I

    move-result v13

    if-ne v12, v13, :cond_e

    .line 84
    :goto_6
    invoke-virtual {v0, v2}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    move-result v12

    if-nez v12, :cond_b

    .line 85
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    move-result v12

    if-eqz v12, :cond_a

    goto :goto_7

    .line 86
    :cond_a
    sget-object v12, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->LEGACY:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    goto :goto_8

    .line 87
    :cond_b
    :goto_7
    sget-object v12, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->ADV:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    .line 88
    :goto_8
    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v12

    .line 89
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    goto :goto_a

    .line 90
    :cond_c
    invoke-virtual {v0, v4}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v12

    if-ne v6, v12, :cond_e

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v12

    .line 91
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->c()I

    move-result v13

    if-ne v12, v13, :cond_d

    goto :goto_9

    :cond_d
    sget-object v13, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->c()I

    move-result v13

    if-ne v12, v13, :cond_e

    :goto_9
    sget-object v12, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->PCTI:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v12

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    goto :goto_a

    :cond_e
    const/4 v12, 0x0

    :goto_a
    if-eqz v12, :cond_f

    .line 92
    invoke-virtual {v12}, Ljava/lang/Integer;->intValue()I

    move-result v12

    goto :goto_b

    .line 93
    :cond_f
    new-instance v12, Ljava/lang/IllegalArgumentException;

    const-string v13, "Unknown Message/Content Type combination."

    invoke-direct {v12, v13}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v12
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 94
    :catch_0
    sget-object v12, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->LEGACY:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v12}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v12

    :goto_b
    if-eqz p2, :cond_10

    const/4 v13, 0x0

    goto :goto_c

    .line 95
    :cond_10
    const-string v13, "subject"

    .line 96
    invoke-static {v0, v13, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    :goto_c
    if-eqz p2, :cond_11

    const/4 v14, 0x0

    goto :goto_d

    .line 97
    :cond_11
    const-string v14, "title"

    .line 98
    invoke-static {v0, v14, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v14

    :goto_d
    if-eqz p2, :cond_12

    const/4 v15, 0x0

    goto :goto_e

    .line 99
    :cond_12
    const-string v15, "alert"

    .line 100
    invoke-static {v0, v15, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v15

    :goto_e
    if-eqz p2, :cond_13

    const/4 v11, 0x0

    goto :goto_f

    .line 101
    :cond_13
    const-string v11, "sound"

    .line 102
    invoke-static {v0, v11, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    :goto_f
    if-eqz p2, :cond_14

    goto :goto_10

    .line 103
    :cond_14
    const-string v6, "media"

    invoke-virtual {v0, v6}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v6

    if-eqz v6, :cond_15

    invoke-static {v6}, Lcom/salesforce/marketingcloud/messages/inbox/b;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    move-result-object v6

    goto :goto_11

    :cond_15
    :goto_10
    const/4 v6, 0x0

    :goto_11
    if-eqz p2, :cond_16

    move-object/from16 v21, v6

    const/4 v6, 0x0

    goto :goto_12

    :cond_16
    move-object/from16 v21, v6

    .line 104
    const-string v6, "url"

    .line 105
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    :goto_12
    if-eqz p2, :cond_17

    move-object/from16 v22, v6

    const/4 v6, 0x0

    goto :goto_13

    :cond_17
    move-object/from16 v22, v6

    .line 106
    const-string v6, "custom"

    .line 107
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    :goto_13
    if-eqz p2, :cond_18

    move-object/from16 v23, v6

    goto :goto_14

    :cond_18
    move-object/from16 v23, v6

    .line 108
    const-string v6, "keys"

    invoke-virtual {v0, v6}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object v6

    if-eqz v6, :cond_19

    invoke-static {v6}, Lcom/salesforce/marketingcloud/internal/o;->b(Lorg/json/JSONArray;)Ljava/util/Map;

    move-result-object v6

    goto :goto_15

    :cond_19
    :goto_14
    const/4 v6, 0x0

    :goto_15
    if-eqz p2, :cond_1a

    move-object/from16 v24, v6

    const/4 v6, 0x0

    goto :goto_16

    :cond_1a
    move-object/from16 v24, v6

    .line 109
    const-string v6, "subtitle"

    .line 110
    invoke-static {v0, v6, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    :goto_16
    if-eqz p2, :cond_1b

    const/4 v1, 0x0

    goto :goto_17

    .line 111
    :cond_1b
    invoke-static {v0, v1, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    :goto_17
    if-eqz p2, :cond_1c

    const/4 v2, 0x0

    goto :goto_18

    .line 112
    :cond_1c
    invoke-static {v0, v2, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    :goto_18
    if-eqz p2, :cond_1d

    goto :goto_1b

    .line 113
    :cond_1d
    :try_start_1
    sget-object v7, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->PCTI:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    move-result v7

    invoke-virtual {v0, v5}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    move-result v5

    if-ne v7, v5, :cond_1e

    sget-object v3, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->Companion:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

    invoke-virtual {v3, v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object v0

    goto :goto_1a

    .line 114
    :cond_1e
    invoke-virtual {v0, v4}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v4

    const/4 v5, 0x1

    if-ne v5, v4, :cond_20

    invoke-virtual {v0, v3}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    move-result v3

    .line 115
    sget-object v4, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->c()I

    move-result v4

    if-ne v3, v4, :cond_1f

    goto :goto_19

    :cond_1f
    sget-object v4, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->c()I

    move-result v4

    if-ne v3, v4, :cond_20

    :goto_19
    sget-object v3, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->Companion:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;

    invoke-virtual {v3, v0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    move-result-object v0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    :goto_1a
    move-object/from16 v25, v0

    goto :goto_1c

    :catch_1
    :cond_20
    :goto_1b
    const/16 v25, 0x0

    .line 116
    :goto_1c
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 117
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v27

    move-object/from16 v7, p0

    move-object v12, v14

    move-object/from16 v19, v22

    move-object/from16 v20, v23

    move-object/from16 v23, v1

    move-object/from16 v22, v6

    move-object v14, v11

    move-object v11, v13

    move-object v13, v15

    move-object/from16 v15, v21

    move-object/from16 v21, v24

    move-object/from16 v24, v2

    .line 118
    invoke-direct/range {v7 .. v28}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;Z)V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/json/JSONObject;ZILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 64
    :cond_0
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Lorg/json/JSONObject;Z)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;ZILjava/lang/Object;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p22

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-object v5, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-object v7, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    goto :goto_5

    :cond_5
    move-object/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-object v8, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    goto :goto_6

    :cond_6
    move-object/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-object v9, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    goto :goto_7

    :cond_7
    move-object/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-object v10, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    goto :goto_8

    :cond_8
    move-object/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-object v11, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    goto :goto_9

    :cond_9
    move-object/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget-object v12, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    goto :goto_a

    :cond_a
    move-object/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-object v13, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    goto :goto_b

    :cond_b
    move-object/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget-object v14, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    goto :goto_c

    :cond_c
    move-object/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    goto :goto_d

    :cond_d
    move-object/from16 v15, p14

    :goto_d
    move-object/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    goto :goto_f

    :cond_f
    move-object/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p22, v16

    move-object/from16 p2, v1

    if-eqz v16, :cond_10

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    goto :goto_10

    :cond_10
    move-object/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p22, v16

    move-object/from16 p3, v1

    if-eqz v16, :cond_11

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    goto :goto_11

    :cond_11
    move-object/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p22, v16

    move-object/from16 p4, v1

    if-eqz v16, :cond_12

    iget v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    goto :goto_12

    :cond_12
    move/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p22, v16

    move/from16 p5, v1

    if-eqz v16, :cond_13

    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    goto :goto_13

    :cond_13
    move-object/from16 v1, p20

    :goto_13
    const/high16 v16, 0x100000

    and-int v16, p22, v16

    if-eqz v16, :cond_14

    move-object/from16 p6, v1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    move-object/from16 p21, p6

    move/from16 p22, v1

    :goto_14
    move-object/from16 p17, p2

    move-object/from16 p18, p3

    move-object/from16 p19, p4

    move/from16 p20, p5

    move-object/from16 p16, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move-object/from16 p7, v7

    move-object/from16 p8, v8

    move-object/from16 p9, v9

    move-object/from16 p10, v10

    move-object/from16 p11, v11

    move-object/from16 p12, v12

    move-object/from16 p13, v13

    move-object/from16 p14, v14

    move-object/from16 p15, v15

    move-object/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_15

    :cond_14
    move/from16 p22, p21

    move-object/from16 p21, v1

    goto :goto_14

    :goto_15
    invoke-virtual/range {p1 .. p22}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;Z)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final alert()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component16()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component17()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18()Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component21()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;Z)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
    .locals 23
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "Ljava/util/Date;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcom/salesforce/marketingcloud/notifications/NotificationMessage;",
            "I",
            "Ljava/lang/Integer;",
            "Z)",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;"
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
    new-instance v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 9
    .line 10
    move-object/from16 v3, p2

    .line 11
    .line 12
    move-object/from16 v4, p3

    .line 13
    .line 14
    move-object/from16 v5, p4

    .line 15
    .line 16
    move-object/from16 v6, p5

    .line 17
    .line 18
    move-object/from16 v7, p6

    .line 19
    .line 20
    move-object/from16 v8, p7

    .line 21
    .line 22
    move-object/from16 v9, p8

    .line 23
    .line 24
    move-object/from16 v10, p9

    .line 25
    .line 26
    move-object/from16 v11, p10

    .line 27
    .line 28
    move-object/from16 v12, p11

    .line 29
    .line 30
    move-object/from16 v13, p12

    .line 31
    .line 32
    move-object/from16 v14, p13

    .line 33
    .line 34
    move-object/from16 v15, p14

    .line 35
    .line 36
    move-object/from16 v16, p15

    .line 37
    .line 38
    move-object/from16 v17, p16

    .line 39
    .line 40
    move-object/from16 v18, p17

    .line 41
    .line 42
    move-object/from16 v19, p18

    .line 43
    .line 44
    move/from16 v20, p19

    .line 45
    .line 46
    move-object/from16 v21, p20

    .line 47
    .line 48
    move/from16 v22, p21

    .line 49
    .line 50
    invoke-direct/range {v1 .. v22}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;Ljava/util/Date;Ljava/util/Date;Ljava/util/Date;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/Integer;Z)V

    .line 51
    .line 52
    .line 53
    return-object v1
.end method

.method public final custom()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final deleted()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 2
    .line 3
    return p0
.end method

.method public final endDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

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
    check-cast p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 80
    .line 81
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 91
    .line 92
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 102
    .line 103
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 113
    .line 114
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 115
    .line 116
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 124
    .line 125
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 126
    .line 127
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-nez v1, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 135
    .line 136
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_d

    .line 143
    .line 144
    return v2

    .line 145
    :cond_d
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    .line 146
    .line 147
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    .line 148
    .line 149
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_e

    .line 154
    .line 155
    return v2

    .line 156
    :cond_e
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 157
    .line 158
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 159
    .line 160
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-nez v1, :cond_f

    .line 165
    .line 166
    return v2

    .line 167
    :cond_f
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    .line 168
    .line 169
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    .line 170
    .line 171
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    if-nez v1, :cond_10

    .line 176
    .line 177
    return v2

    .line 178
    :cond_10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    .line 179
    .line 180
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v1

    .line 186
    if-nez v1, :cond_11

    .line 187
    .line 188
    return v2

    .line 189
    :cond_11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    .line 190
    .line 191
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    .line 192
    .line 193
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    if-nez v1, :cond_12

    .line 198
    .line 199
    return v2

    .line 200
    :cond_12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 201
    .line 202
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 203
    .line 204
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v1

    .line 208
    if-nez v1, :cond_13

    .line 209
    .line 210
    return v2

    .line 211
    :cond_13
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 212
    .line 213
    iget v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 214
    .line 215
    if-eq v1, v3, :cond_14

    .line 216
    .line 217
    return v2

    .line 218
    :cond_14
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 219
    .line 220
    iget-object v3, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 221
    .line 222
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v1

    .line 226
    if-nez v1, :cond_15

    .line 227
    .line 228
    return v2

    .line 229
    :cond_15
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 230
    .line 231
    iget-boolean p1, p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 232
    .line 233
    if-eq p0, p1, :cond_16

    .line 234
    .line 235
    return v2

    .line 236
    :cond_16
    return v0
.end method

.method public final getDeleted()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getDirty$sdk_release()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->dirty:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getMessageHash$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRead()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->read:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getRequestId$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getViewCount$sdk_release()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

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
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 36
    .line 37
    if-nez v2, :cond_2

    .line 38
    .line 39
    move v2, v3

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_2
    add-int/2addr v0, v2

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 48
    .line 49
    if-nez v2, :cond_3

    .line 50
    .line 51
    move v2, v3

    .line 52
    goto :goto_3

    .line 53
    :cond_3
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    :goto_3
    add-int/2addr v0, v2

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 60
    .line 61
    if-nez v2, :cond_4

    .line 62
    .line 63
    move v2, v3

    .line 64
    goto :goto_4

    .line 65
    :cond_4
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    :goto_4
    add-int/2addr v0, v2

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 72
    .line 73
    if-nez v2, :cond_5

    .line 74
    .line 75
    move v2, v3

    .line 76
    goto :goto_5

    .line 77
    :cond_5
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    :goto_5
    add-int/2addr v0, v2

    .line 82
    mul-int/2addr v0, v1

    .line 83
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 84
    .line 85
    if-nez v2, :cond_6

    .line 86
    .line 87
    move v2, v3

    .line 88
    goto :goto_6

    .line 89
    :cond_6
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    :goto_6
    add-int/2addr v0, v2

    .line 94
    mul-int/2addr v0, v1

    .line 95
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 96
    .line 97
    if-nez v2, :cond_7

    .line 98
    .line 99
    move v2, v3

    .line 100
    goto :goto_7

    .line 101
    :cond_7
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    :goto_7
    add-int/2addr v0, v2

    .line 106
    mul-int/2addr v0, v1

    .line 107
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 108
    .line 109
    if-nez v2, :cond_8

    .line 110
    .line 111
    move v2, v3

    .line 112
    goto :goto_8

    .line 113
    :cond_8
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    :goto_8
    add-int/2addr v0, v2

    .line 118
    mul-int/2addr v0, v1

    .line 119
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 120
    .line 121
    if-nez v2, :cond_9

    .line 122
    .line 123
    move v2, v3

    .line 124
    goto :goto_9

    .line 125
    :cond_9
    invoke-virtual {v2}, Ljava/util/Date;->hashCode()I

    .line 126
    .line 127
    .line 128
    move-result v2

    .line 129
    :goto_9
    add-int/2addr v0, v2

    .line 130
    mul-int/2addr v0, v1

    .line 131
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 132
    .line 133
    if-nez v2, :cond_a

    .line 134
    .line 135
    move v2, v3

    .line 136
    goto :goto_a

    .line 137
    :cond_a
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    :goto_a
    add-int/2addr v0, v2

    .line 142
    mul-int/2addr v0, v1

    .line 143
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    .line 144
    .line 145
    if-nez v2, :cond_b

    .line 146
    .line 147
    move v2, v3

    .line 148
    goto :goto_b

    .line 149
    :cond_b
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    :goto_b
    add-int/2addr v0, v2

    .line 154
    mul-int/2addr v0, v1

    .line 155
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 156
    .line 157
    if-nez v2, :cond_c

    .line 158
    .line 159
    move v2, v3

    .line 160
    goto :goto_c

    .line 161
    :cond_c
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    :goto_c
    add-int/2addr v0, v2

    .line 166
    mul-int/2addr v0, v1

    .line 167
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    .line 168
    .line 169
    if-nez v2, :cond_d

    .line 170
    .line 171
    move v2, v3

    .line 172
    goto :goto_d

    .line 173
    :cond_d
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 174
    .line 175
    .line 176
    move-result v2

    .line 177
    :goto_d
    add-int/2addr v0, v2

    .line 178
    mul-int/2addr v0, v1

    .line 179
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    .line 180
    .line 181
    if-nez v2, :cond_e

    .line 182
    .line 183
    move v2, v3

    .line 184
    goto :goto_e

    .line 185
    :cond_e
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 186
    .line 187
    .line 188
    move-result v2

    .line 189
    :goto_e
    add-int/2addr v0, v2

    .line 190
    mul-int/2addr v0, v1

    .line 191
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    .line 192
    .line 193
    if-nez v2, :cond_f

    .line 194
    .line 195
    move v2, v3

    .line 196
    goto :goto_f

    .line 197
    :cond_f
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 198
    .line 199
    .line 200
    move-result v2

    .line 201
    :goto_f
    add-int/2addr v0, v2

    .line 202
    mul-int/2addr v0, v1

    .line 203
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 204
    .line 205
    if-nez v2, :cond_10

    .line 206
    .line 207
    move v2, v3

    .line 208
    goto :goto_10

    .line 209
    :cond_10
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->hashCode()I

    .line 210
    .line 211
    .line 212
    move-result v2

    .line 213
    :goto_10
    add-int/2addr v0, v2

    .line 214
    mul-int/2addr v0, v1

    .line 215
    iget v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 216
    .line 217
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 218
    .line 219
    .line 220
    move-result v0

    .line 221
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 222
    .line 223
    if-nez v2, :cond_11

    .line 224
    .line 225
    goto :goto_11

    .line 226
    :cond_11
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    :goto_11
    add-int/2addr v0, v3

    .line 231
    mul-int/2addr v0, v1

    .line 232
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 233
    .line 234
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 235
    .line 236
    .line 237
    move-result p0

    .line 238
    add-int/2addr p0, v0

    .line 239
    return p0
.end method

.method public final id()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final media()Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 2
    .line 3
    return-object p0
.end method

.method public final read()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->read:Z

    .line 2
    .line 3
    return p0
.end method

.method public final sendDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setDeleted(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 2
    .line 3
    return-void
.end method

.method public final setDirty$sdk_release(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->dirty:Z

    .line 2
    .line 3
    return-void
.end method

.method public final synthetic setRead(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->read:Z

    .line 2
    .line 3
    return-void
.end method

.method public final sound()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final startDateUtc()Ljava/util/Date;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final subject()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final title()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toJson$sdk_release()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "id"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 14
    .line 15
    const-string v2, "calculatedType"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    iget v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 21
    .line 22
    const-string v2, "viewCount"

    .line 23
    .line 24
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 25
    .line 26
    .line 27
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 28
    .line 29
    const-string v2, "isDeleted"

    .line 30
    .line 31
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 32
    .line 33
    .line 34
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 35
    .line 36
    const-string v2, "messageType"

    .line 37
    .line 38
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 39
    .line 40
    .line 41
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 42
    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    const-string v2, "url"

    .line 46
    .line 47
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 48
    .line 49
    .line 50
    :cond_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    .line 51
    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    const-string v2, "hash"

    .line 55
    .line 56
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 57
    .line 58
    .line 59
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    .line 60
    .line 61
    if-eqz v1, :cond_2

    .line 62
    .line 63
    const-string v2, "requestId"

    .line 64
    .line 65
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 66
    .line 67
    .line 68
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 69
    .line 70
    if-eqz v1, :cond_3

    .line 71
    .line 72
    const-string v2, "subject"

    .line 73
    .line 74
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 75
    .line 76
    .line 77
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 78
    .line 79
    if-eqz v1, :cond_4

    .line 80
    .line 81
    const-string v2, "title"

    .line 82
    .line 83
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 84
    .line 85
    .line 86
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 87
    .line 88
    if-eqz v1, :cond_5

    .line 89
    .line 90
    const-string v2, "alert"

    .line 91
    .line 92
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 93
    .line 94
    .line 95
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 96
    .line 97
    if-eqz v1, :cond_6

    .line 98
    .line 99
    const-string v2, "sound"

    .line 100
    .line 101
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 102
    .line 103
    .line 104
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 105
    .line 106
    if-eqz v1, :cond_7

    .line 107
    .line 108
    invoke-static {v1}, Lcom/salesforce/marketingcloud/messages/inbox/b;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;)Lorg/json/JSONObject;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    const-string v2, "media"

    .line 113
    .line 114
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 115
    .line 116
    .line 117
    :cond_7
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 118
    .line 119
    if-eqz v1, :cond_8

    .line 120
    .line 121
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    const-string v2, "startDateUtc"

    .line 126
    .line 127
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 128
    .line 129
    .line 130
    :cond_8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 131
    .line 132
    if-eqz v1, :cond_9

    .line 133
    .line 134
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    const-string v2, "endDateUtc"

    .line 139
    .line 140
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 141
    .line 142
    .line 143
    :cond_9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 144
    .line 145
    if-eqz v1, :cond_a

    .line 146
    .line 147
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    const-string v2, "sendDateUtc"

    .line 152
    .line 153
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 154
    .line 155
    .line 156
    :cond_a
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    .line 157
    .line 158
    if-eqz v1, :cond_b

    .line 159
    .line 160
    const-string v2, "custom"

    .line 161
    .line 162
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 163
    .line 164
    .line 165
    :cond_b
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 166
    .line 167
    if-eqz v1, :cond_c

    .line 168
    .line 169
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/o;->a(Ljava/util/Map;)Lorg/json/JSONArray;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    const-string v2, "keys"

    .line 174
    .line 175
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 176
    .line 177
    .line 178
    :cond_c
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    .line 179
    .line 180
    if-eqz v1, :cond_d

    .line 181
    .line 182
    const-string v2, "subtitle"

    .line 183
    .line 184
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 185
    .line 186
    .line 187
    :cond_d
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    .line 188
    .line 189
    if-eqz v1, :cond_e

    .line 190
    .line 191
    const-string v2, "inboxSubtitle"

    .line 192
    .line 193
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 194
    .line 195
    .line 196
    :cond_e
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    .line 197
    .line 198
    if-eqz v1, :cond_f

    .line 199
    .line 200
    const-string v2, "inboxMessage"

    .line 201
    .line 202
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 203
    .line 204
    .line 205
    :cond_f
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 206
    .line 207
    if-eqz p0, :cond_10

    .line 208
    .line 209
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    const-string v1, "notificationMessage"

    .line 214
    .line 215
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 216
    .line 217
    .line 218
    :cond_10
    return-object v0
.end method

.method public final toJsonString()Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->toJson$sdk_release()Lorg/json/JSONObject;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 6
    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->Companion:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType$a;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-virtual {v1, p0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType$a;->a(I)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    :goto_0
    const-string v1, "messageType"

    .line 28
    .line 29
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 30
    .line 31
    .line 32
    :cond_1
    const/4 p0, 0x2

    .line 33
    invoke-virtual {v0, p0}, Lorg/json/JSONObject;->toString(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string v0, "toString(...)"

    .line 38
    .line 39
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->id:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->requestId:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageHash:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subject:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->title:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v6, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->alert:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v7, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sound:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->media:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$Media;

    .line 18
    .line 19
    iget-object v9, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->startDateUtc:Ljava/util/Date;

    .line 20
    .line 21
    iget-object v10, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->endDateUtc:Ljava/util/Date;

    .line 22
    .line 23
    iget-object v11, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->sendDateUtc:Ljava/util/Date;

    .line 24
    .line 25
    iget-object v12, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v13, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->custom:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v14, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->customKeys:Ljava/util/Map;

    .line 30
    .line 31
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->subtitle:Ljava/lang/String;

    .line 32
    .line 33
    move-object/from16 v16, v15

    .line 34
    .line 35
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxMessage:Ljava/lang/String;

    .line 36
    .line 37
    move-object/from16 v17, v15

    .line 38
    .line 39
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->inboxSubtitle:Ljava/lang/String;

    .line 40
    .line 41
    move-object/from16 v18, v15

    .line 42
    .line 43
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->notificationMessage:Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 44
    .line 45
    move-object/from16 v19, v15

    .line 46
    .line 47
    iget v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->viewCount:I

    .line 48
    .line 49
    move/from16 v20, v15

    .line 50
    .line 51
    iget-object v15, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->messageType:Ljava/lang/Integer;

    .line 52
    .line 53
    iget-boolean v0, v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->deleted:Z

    .line 54
    .line 55
    move/from16 p0, v0

    .line 56
    .line 57
    const-string v0, ", requestId="

    .line 58
    .line 59
    move-object/from16 v21, v15

    .line 60
    .line 61
    const-string v15, ", messageHash="

    .line 62
    .line 63
    move-object/from16 v22, v14

    .line 64
    .line 65
    const-string v14, "InboxMessage(id="

    .line 66
    .line 67
    invoke-static {v14, v1, v0, v2, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    const-string v1, ", subject="

    .line 72
    .line 73
    const-string v2, ", title="

    .line 74
    .line 75
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v1, ", alert="

    .line 79
    .line 80
    const-string v2, ", sound="

    .line 81
    .line 82
    invoke-static {v0, v5, v1, v6, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string v1, ", media="

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v1, ", startDateUtc="

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string v1, ", endDateUtc="

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v1, ", sendDateUtc="

    .line 113
    .line 114
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string v1, ", url="

    .line 121
    .line 122
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string v1, ", custom="

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    const-string v1, ", customKeys="

    .line 137
    .line 138
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    move-object/from16 v1, v22

    .line 142
    .line 143
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    const-string v1, ", subtitle="

    .line 147
    .line 148
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    const-string v1, ", inboxMessage="

    .line 152
    .line 153
    const-string v2, ", inboxSubtitle="

    .line 154
    .line 155
    move-object/from16 v3, v16

    .line 156
    .line 157
    move-object/from16 v4, v17

    .line 158
    .line 159
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    move-object/from16 v1, v18

    .line 163
    .line 164
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    const-string v1, ", notificationMessage="

    .line 168
    .line 169
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    move-object/from16 v1, v19

    .line 173
    .line 174
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    const-string v1, ", viewCount="

    .line 178
    .line 179
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    move/from16 v1, v20

    .line 183
    .line 184
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    const-string v1, ", messageType="

    .line 188
    .line 189
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 190
    .line 191
    .line 192
    move-object/from16 v1, v21

    .line 193
    .line 194
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 195
    .line 196
    .line 197
    const-string v1, ", deleted="

    .line 198
    .line 199
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 200
    .line 201
    .line 202
    const-string v1, ")"

    .line 203
    .line 204
    move/from16 v2, p0

    .line 205
    .line 206
    invoke-static {v0, v2, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    return-object v0
.end method

.method public final url()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;->url:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
