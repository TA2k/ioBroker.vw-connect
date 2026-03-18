.class public Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private length:I

.field private value:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    const/4 v0, -0x1

    .line 1
    invoke-direct {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;-><init>(II)V

    return-void
.end method

.method public constructor <init>(II)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->value:I

    .line 4
    iput p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->length:I

    return-void
.end method


# virtual methods
.method public getEncodedLength()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->length:I

    .line 2
    .line 3
    return p0
.end method

.method public getValue()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/VariableByteInteger;->value:I

    .line 2
    .line 3
    return p0
.end method
