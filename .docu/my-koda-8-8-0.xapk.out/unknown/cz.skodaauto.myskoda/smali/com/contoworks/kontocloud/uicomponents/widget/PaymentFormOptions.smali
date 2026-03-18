.class public Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private apiURL:Ljava/lang/String;

.field private mode:Ljava/lang/Integer;

.field private paymentProvider:Ljava/lang/String;

.field private paymentProviderMode:Ljava/lang/Integer;

.field private redirectUrl:Ljava/lang/String;

.field private showStorePaymentMethod:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private constructor <init>(Landroid/os/Parcel;)V
    .locals 2

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    const-class v0, Ljava/lang/Integer;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    invoke-virtual {p1, v1}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    iput-object v1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->mode:Ljava/lang/Integer;

    .line 5
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProviderMode:Ljava/lang/Integer;

    .line 6
    const-class v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    iput-boolean v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->showStorePaymentMethod:Z

    .line 7
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->redirectUrl:Ljava/lang/String;

    .line 8
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProvider:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;-><init>(Landroid/os/Parcel;)V

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

.method public getApiUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->apiURL:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMode()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->mode:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPaymentProvider()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProvider:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "Payon"

    .line 7
    .line 8
    return-object p0
.end method

.method public getPaymentProviderMode()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProviderMode:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRedirectUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->redirectUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public isShowStorePaymentMethod()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->showStorePaymentMethod:Z

    .line 2
    .line 3
    return p0
.end method

.method public setApiUrl(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "/"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    :cond_0
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->apiURL:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public setMode(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->mode:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public setPaymentProvider(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProvider:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setPaymentProviderMode(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProviderMode:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public setRedirectUrl(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->redirectUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public setShowStorePaymentMethod(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->showStorePaymentMethod:Z

    .line 2
    .line 3
    return-void
.end method

.method public validateState(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getMode()Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_6

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProvider()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-eqz v0, :cond_5

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getPaymentProviderMode()Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-eqz v0, :cond_4

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Ljava/lang/String;

    .line 25
    .line 26
    const-string v0, "PAYU"

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->getRedirectUrl()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    if-eqz p1, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "The \'redirectUrl\' property must be set if PayU payment option selected."

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    :goto_0
    iget-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->mode:Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->isShowStorePaymentMethod()Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-nez p0, :cond_3

    .line 63
    .line 64
    :goto_1
    return-void

    .line 65
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p1, "The \'showStorePaymentMethod\' property is not supported in Registration mode."

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string p1, "The \'paymentProviderMode\' property must be set."

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string p1, "The \'paymentProvider\' property must be set."

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "The \'mode\' property must be set."

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->mode:Ljava/lang/Integer;

    .line 2
    .line 3
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProviderMode:Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeValue(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-boolean p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->showStorePaymentMethod:Z

    .line 12
    .line 13
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeValue(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->redirectUrl:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentFormOptions;->paymentProvider:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
