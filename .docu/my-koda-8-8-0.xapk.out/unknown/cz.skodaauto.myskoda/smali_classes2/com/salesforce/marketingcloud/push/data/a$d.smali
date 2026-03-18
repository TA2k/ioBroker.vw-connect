.class public final Lcom/salesforce/marketingcloud/push/data/a$d;
.super Lcom/salesforce/marketingcloud/push/data/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "d"
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/data/a$d;",
            ">;"
        }
    .end annotation
.end field

.field public static final d:Lcom/salesforce/marketingcloud/push/data/a$d;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/a$d;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/a$d;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/a$d;->d:Lcom/salesforce/marketingcloud/push/data/a$d;

    .line 7
    .line 8
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/a$d$a;

    .line 9
    .line 10
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/a$d$a;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/a$d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 14
    .line 15
    return-void
.end method

.method private constructor <init>()V
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/a$f;->f:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/push/data/a;-><init>(ILkotlin/jvm/internal/g;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    const-string p0, "out"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
