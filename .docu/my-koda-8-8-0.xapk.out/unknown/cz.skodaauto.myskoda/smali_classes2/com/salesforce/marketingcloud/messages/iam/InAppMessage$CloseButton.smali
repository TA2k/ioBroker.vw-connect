.class public final Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "CloseButton"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;


# instance fields
.field public final alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->Companion:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x0

    const/4 v1, 0x1

    .line 1
    invoke-direct {p0, v0, v1, v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;-><init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)V
    .locals 1

    const-string v0, "alignment"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    return-void
.end method

.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    .line 4
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;->end:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 5
    :cond_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;-><init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->copy(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public static final defaultCloseButton()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->Companion:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton$a;->a()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method


# virtual methods
.method public final alignment()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;
    .locals 0

    .line 1
    const-string p0, "alignment"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;-><init>(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;)V

    .line 9
    .line 10
    .line 11
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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

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
    check-cast p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 14
    .line 15
    iget-object p1, p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toJson$sdk_release()Lorg/json/JSONObject;
    .locals 2

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v1, "alignment"

    .line 13
    .line 14
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "CloseButton(alignment="

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
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
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$CloseButton;->alignment:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Alignment;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
