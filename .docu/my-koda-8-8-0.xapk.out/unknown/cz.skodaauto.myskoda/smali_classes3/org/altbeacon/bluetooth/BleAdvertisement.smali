.class public Lorg/altbeacon/bluetooth/BleAdvertisement;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "BleAdvertisement"


# instance fields
.field private mBytes:[B

.field private mPdus:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lorg/altbeacon/bluetooth/Pdu;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>([B)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BleAdvertisement;->mBytes:[B

    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    array-length v1, p1

    .line 12
    const/16 v2, 0x1f

    .line 13
    .line 14
    if-ge v1, v2, :cond_0

    .line 15
    .line 16
    array-length v1, p1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v1, v2

    .line 19
    :goto_0
    const/4 v3, 0x0

    .line 20
    invoke-direct {p0, v3, v1, v0}, Lorg/altbeacon/bluetooth/BleAdvertisement;->parsePdus(IILjava/util/ArrayList;)V

    .line 21
    .line 22
    .line 23
    array-length v1, p1

    .line 24
    if-le v1, v2, :cond_1

    .line 25
    .line 26
    array-length p1, p1

    .line 27
    invoke-direct {p0, v2, p1, v0}, Lorg/altbeacon/bluetooth/BleAdvertisement;->parsePdus(IILjava/util/ArrayList;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    iput-object v0, p0, Lorg/altbeacon/bluetooth/BleAdvertisement;->mPdus:Ljava/util/List;

    .line 31
    .line 32
    return-void
.end method

.method private parsePdus(IILjava/util/ArrayList;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(II",
            "Ljava/util/ArrayList<",
            "Lorg/altbeacon/bluetooth/Pdu;",
            ">;)V"
        }
    .end annotation

    .line 1
    :cond_0
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BleAdvertisement;->mBytes:[B

    .line 2
    .line 3
    invoke-static {v0, p1}, Lorg/altbeacon/bluetooth/Pdu;->parse([BI)Lorg/altbeacon/bluetooth/Pdu;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    invoke-virtual {v0}, Lorg/altbeacon/bluetooth/Pdu;->getDeclaredLength()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, p1

    .line 14
    add-int/lit8 v1, v1, 0x1

    .line 15
    .line 16
    invoke-virtual {p3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move p1, v1

    .line 20
    :cond_1
    if-eqz v0, :cond_2

    .line 21
    .line 22
    if-lt p1, p2, :cond_0

    .line 23
    .line 24
    :cond_2
    return-void
.end method


# virtual methods
.method public getPdus()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lorg/altbeacon/bluetooth/Pdu;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BleAdvertisement;->mPdus:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method
