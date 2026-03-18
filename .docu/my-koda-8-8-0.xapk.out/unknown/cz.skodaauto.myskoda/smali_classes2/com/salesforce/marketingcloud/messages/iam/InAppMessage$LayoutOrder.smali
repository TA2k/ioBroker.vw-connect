.class public final enum Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "LayoutOrder"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

.field public static final enum ImageTitleBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

.field public static final enum TitleImageBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->ImageTitleBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->TitleImageBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 2
    .line 3
    const-string v1, "ImageTitleBody"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->ImageTitleBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 12
    .line 13
    const-string v1, "TitleImageBody"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->TitleImageBody:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 20
    .line 21
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->$values()[Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->$VALUES:[Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->$ENTRIES:Lsx0/a;

    .line 32
    .line 33
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
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;->$VALUES:[Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$LayoutOrder;

    .line 8
    .line 9
    return-object v0
.end method
