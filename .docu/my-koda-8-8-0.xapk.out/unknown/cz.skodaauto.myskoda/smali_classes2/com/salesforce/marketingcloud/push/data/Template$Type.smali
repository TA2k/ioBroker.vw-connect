.class public final enum Lcom/salesforce/marketingcloud/push/data/Template$Type;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/Template;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Type"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/push/data/Template$Type;",
        ">;",
        "Landroid/os/Parcelable;"
    }
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/salesforce/marketingcloud/push/data/Template$Type;

.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/data/Template$Type;",
            ">;"
        }
    .end annotation
.end field

.field public static final enum CarouselFull:Lcom/salesforce/marketingcloud/push/data/Template$Type;

.field public static final enum RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lcom/salesforce/marketingcloud/push/data/Template$Type;
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/push/data/Template$Type;->CarouselFull:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "-1"

    .line 5
    .line 6
    const-string v3, "RichButtons"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/push/data/Template$Type;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->RichButtons:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 12
    .line 13
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    const-string v2, "0"

    .line 17
    .line 18
    const-string v3, "CarouselFull"

    .line 19
    .line 20
    invoke-direct {v0, v3, v1, v2}, Lcom/salesforce/marketingcloud/push/data/Template$Type;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->CarouselFull:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 24
    .line 25
    invoke-static {}, Lcom/salesforce/marketingcloud/push/data/Template$Type;->$values()[Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->$VALUES:[Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 30
    .line 31
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->$ENTRIES:Lsx0/a;

    .line 36
    .line 37
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/Template$Type$a;

    .line 38
    .line 39
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/Template$Type$a;-><init>()V

    .line 40
    .line 41
    .line 42
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 43
    .line 44
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->value:Ljava/lang/String;

    .line 5
    .line 6
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
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/Template$Type;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/push/data/Template$Type;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->$VALUES:[Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/push/data/Template$Type;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final getValue()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/Template$Type;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    const-string p2, "out"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
