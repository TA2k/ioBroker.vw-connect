.class public Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private buttonColor:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

.field private buttonLabel:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

.field private buttonShape:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

.field private buttonSize:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

.field private buttonTagline:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->SMALL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonSize:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 3
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;->GOLD:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonColor:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    .line 4
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;->RECT:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonShape:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    .line 5
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->PAYPAL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonLabel:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 6
    sget-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;->WITHOUTTAGLINE:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonTagline:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 2

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    move-result-object v0

    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    aget-object v0, v0, v1

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonSize:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 15
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    move-result-object v0

    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    aget-object v0, v0, v1

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonColor:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    .line 16
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    move-result-object v0

    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    aget-object v0, v0, v1

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonShape:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    .line 17
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    move-result-object v0

    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v1

    aget-object v0, v0, v1

    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonLabel:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 18
    invoke-static {}, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;->values()[Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    move-result-object v0

    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result p1

    aget-object p1, v0, p1

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonTagline:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    return-void
.end method

.method public constructor <init>(Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;)V
    .locals 0

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonSize:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 9
    iput-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonColor:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    .line 10
    iput-object p3, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonShape:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    .line 11
    iput-object p4, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonLabel:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 12
    iput-object p5, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonTagline:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

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

.method public getButtonColor()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonColor:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;->GOLD:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method

.method public getButtonLabel()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonLabel:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;->PAYPAL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method

.method public getButtonShape()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonShape:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;->RECT:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method

.method public getButtonSize()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonSize:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;->SMALL:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method

.method public getButtonTagline()Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonTagline:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;->WITHOUTTAGLINE:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 0

    .line 1
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonSize:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonSize;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 8
    .line 9
    .line 10
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonColor:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonColor;

    .line 11
    .line 12
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 17
    .line 18
    .line 19
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonShape:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonShape;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 26
    .line 27
    .line 28
    iget-object p2, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonLabel:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonLabel;

    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CWPayPalButtonStyle;->buttonTagline:Lcom/contoworks/kontocloud/uicomponents/widget/PaypalButtonTagline;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 44
    .line 45
    .line 46
    return-void
.end method
