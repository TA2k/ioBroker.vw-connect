.class public Lorg/altbeacon/bluetooth/Pdu;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final GATT_SERVICE_COMPLETE_UUID_128_BIT_AD_TYPE:B = 0x7t

.field public static final GATT_SERVICE_DATA_UUID_128_BIT_AD_TYPE:B = 0x21t

.field public static final GATT_SERVICE_DATA_UUID_16_BIT_AD_TYPE:B = 0x16t

.field public static final GATT_SERVICE_DATA_UUID_32_BIT_AD_TYPE:B = 0x20t

.field public static final MANUFACTURER_DATA_AD_TYPE:B = -0x1t

.field private static final TAG:Ljava/lang/String; = "Pdu"


# instance fields
.field private mBytes:[B

.field private mDeclaredLength:I

.field private mEndIndex:I

.field private mStartIndex:I

.field private mType:B


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static parse([BI)Lorg/altbeacon/bluetooth/Pdu;
    .locals 5
    .annotation build Landroid/annotation/TargetApi;
        value = 0x9
    .end annotation

    .line 1
    array-length v0, p0

    .line 2
    sub-int/2addr v0, p1

    .line 3
    const/4 v1, 0x2

    .line 4
    if-lt v0, v1, :cond_1

    .line 5
    .line 6
    aget-byte v0, p0, p1

    .line 7
    .line 8
    if-lez v0, :cond_1

    .line 9
    .line 10
    add-int/lit8 v1, p1, 0x1

    .line 11
    .line 12
    aget-byte v1, p0, v1

    .line 13
    .line 14
    add-int/lit8 v2, p1, 0x2

    .line 15
    .line 16
    array-length v3, p0

    .line 17
    if-ge v2, v3, :cond_1

    .line 18
    .line 19
    new-instance v3, Lorg/altbeacon/bluetooth/Pdu;

    .line 20
    .line 21
    invoke-direct {v3}, Lorg/altbeacon/bluetooth/Pdu;-><init>()V

    .line 22
    .line 23
    .line 24
    add-int/2addr p1, v0

    .line 25
    iput p1, v3, Lorg/altbeacon/bluetooth/Pdu;->mEndIndex:I

    .line 26
    .line 27
    array-length v4, p0

    .line 28
    if-lt p1, v4, :cond_0

    .line 29
    .line 30
    array-length p1, p0

    .line 31
    add-int/lit8 p1, p1, -0x1

    .line 32
    .line 33
    iput p1, v3, Lorg/altbeacon/bluetooth/Pdu;->mEndIndex:I

    .line 34
    .line 35
    :cond_0
    iput-byte v1, v3, Lorg/altbeacon/bluetooth/Pdu;->mType:B

    .line 36
    .line 37
    iput v0, v3, Lorg/altbeacon/bluetooth/Pdu;->mDeclaredLength:I

    .line 38
    .line 39
    iput v2, v3, Lorg/altbeacon/bluetooth/Pdu;->mStartIndex:I

    .line 40
    .line 41
    iput-object p0, v3, Lorg/altbeacon/bluetooth/Pdu;->mBytes:[B

    .line 42
    .line 43
    return-object v3

    .line 44
    :cond_1
    const/4 p0, 0x0

    .line 45
    return-object p0
.end method


# virtual methods
.method public getActualLength()I
    .locals 1

    .line 1
    iget v0, p0, Lorg/altbeacon/bluetooth/Pdu;->mEndIndex:I

    .line 2
    .line 3
    iget p0, p0, Lorg/altbeacon/bluetooth/Pdu;->mStartIndex:I

    .line 4
    .line 5
    sub-int/2addr v0, p0

    .line 6
    add-int/lit8 v0, v0, 0x1

    .line 7
    .line 8
    return v0
.end method

.method public getDeclaredLength()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/bluetooth/Pdu;->mDeclaredLength:I

    .line 2
    .line 3
    return p0
.end method

.method public getEndIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/bluetooth/Pdu;->mEndIndex:I

    .line 2
    .line 3
    return p0
.end method

.method public getStartIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/bluetooth/Pdu;->mStartIndex:I

    .line 2
    .line 3
    return p0
.end method

.method public getType()B
    .locals 0

    .line 1
    iget-byte p0, p0, Lorg/altbeacon/bluetooth/Pdu;->mType:B

    .line 2
    .line 3
    return p0
.end method
