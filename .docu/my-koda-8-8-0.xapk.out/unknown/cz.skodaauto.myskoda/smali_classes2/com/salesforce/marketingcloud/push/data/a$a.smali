.class public final Lcom/salesforce/marketingcloud/push/data/a$a;
.super Lcom/salesforce/marketingcloud/push/data/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/data/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/push/data/a$a;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/data/a$a$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/push/data/a$a$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/push/data/a$a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lcom/salesforce/marketingcloud/push/data/a$f;->e:Lcom/salesforce/marketingcloud/push/data/a$f;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/push/data/a;-><init>(ILkotlin/jvm/internal/g;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 17
    .line 18
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/push/data/a$a;Ljava/lang/String;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/push/data/a$a;
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    :cond_0
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/push/data/a$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/a$a;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/push/data/a$a;
    .locals 0

    .line 1
    const-string p0, "url"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Lcom/salesforce/marketingcloud/push/data/a$a;

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/data/a$a;-><init>(Ljava/lang/String;)V

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
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/push/data/a$a;

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
    check-cast p1, Lcom/salesforce/marketingcloud/push/data/a$a;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p1, p1, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final k()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "CloudPage(url="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/data/a$a;->d:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
