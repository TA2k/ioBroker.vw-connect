.class public Lcom/salesforce/marketingcloud/messages/iam/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/iam/j$b;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/iam/j;",
            ">;"
        }
    .end annotation
.end field

.field public static final f:Ljava/lang/String; = "buttonClicked"

.field public static final g:Ljava/lang/String; = "dismissed"

.field public static final h:Ljava/lang/String; = "autoDismissed"

.field public static final i:Ljava/lang/String; = "unknown"


# instance fields
.field final b:Ljava/lang/String;

.field final c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

.field final d:J

.field final e:Ljava/util/Date;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/j$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/iam/j$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 3

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->b:Ljava/lang/String;

    .line 8
    const-class v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 9
    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v0

    iput-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->d:J

    .line 10
    new-instance v0, Ljava/util/Date;

    invoke-virtual {p1}, Landroid/os/Parcel;->readLong()J

    move-result-wide v1

    invoke-direct {v0, v1, v2}, Ljava/util/Date;-><init>(J)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->e:Ljava/util/Date;

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->b:Ljava/lang/String;

    .line 3
    iput-wide p3, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->d:J

    .line 4
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 5
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->e:Ljava/util/Date;

    return-void
.end method

.method public static a(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;
    .locals 6

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/j;

    const-string v1, "autoDismissed"

    const/4 v5, 0x0

    move-object v2, p0

    move-wide v3, p1

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/iam/j;-><init>(Ljava/lang/String;Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    return-object v0
.end method

.method public static a(Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)Lcom/salesforce/marketingcloud/messages/iam/j;
    .locals 6

    .line 2
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/j;

    const-string v1, "buttonClicked"

    move-object v2, p0

    move-wide v3, p1

    move-object v5, p3

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/iam/j;-><init>(Ljava/lang/String;Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    return-object v0
.end method

.method public static b(Ljava/util/Date;J)Lcom/salesforce/marketingcloud/messages/iam/j;
    .locals 6

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 2
    .line 3
    const-string v1, "dismissed"

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    move-object v2, p0

    .line 7
    move-wide v3, p1

    .line 8
    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/iam/j;-><init>(Ljava/lang/String;Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static m()Lcom/salesforce/marketingcloud/messages/iam/j;
    .locals 6

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/j;

    .line 2
    .line 3
    new-instance v2, Ljava/util/Date;

    .line 4
    .line 5
    invoke-direct {v2}, Ljava/util/Date;-><init>()V

    .line 6
    .line 7
    .line 8
    const-wide/16 v3, -0x1

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    const-string v1, "unknown"

    .line 12
    .line 13
    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/messages/iam/j;-><init>(Ljava/lang/String;Ljava/util/Date;JLcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;)V

    .line 14
    .line 15
    .line 16
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

.method public h()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 2
    .line 3
    return-object p0
.end method

.method public j()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->d:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public k()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->e:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public l()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->b:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->c:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Button;

    .line 7
    .line 8
    invoke-virtual {p1, v0, p2}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->d:J

    .line 12
    .line 13
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/j;->e:Ljava/util/Date;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/util/Date;->getTime()J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
