.class public final enum Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/notifications/NotificationMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Trigger"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

.field public static final enum BEACON:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

.field public static final enum DOWNLOAD:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

.field public static final enum GEOFENCE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

.field public static final enum PUSH:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->PUSH:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->GEOFENCE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->BEACON:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->DOWNLOAD:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 2
    .line 3
    const-string v1, "PUSH"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->PUSH:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 12
    .line 13
    const-string v1, "GEOFENCE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->GEOFENCE:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 20
    .line 21
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 22
    .line 23
    const-string v1, "BEACON"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->BEACON:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 30
    .line 31
    new-instance v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 32
    .line 33
    const-string v1, "DOWNLOAD"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->DOWNLOAD:Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 40
    .line 41
    invoke-static {}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->$values()[Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->$VALUES:[Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sput-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->$ENTRIES:Lsx0/a;

    .line 52
    .line 53
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;->$VALUES:[Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/notifications/NotificationMessage$Trigger;

    .line 8
    .line 9
    return-object v0
.end method
