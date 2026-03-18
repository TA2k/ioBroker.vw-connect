.class public Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;
.super Ljava/io/InputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private counter:I

.field private inputStream:Ljava/io/InputStream;


# direct methods
.method public constructor <init>(Ljava/io/InputStream;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/io/InputStream;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->inputStream:Ljava/io/InputStream;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->counter:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public getCounter()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->counter:I

    .line 2
    .line 3
    return p0
.end method

.method public read()I
    .locals 2

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->inputStream:Ljava/io/InputStream;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/io/InputStream;->read()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, -0x1

    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->counter:I

    .line 11
    .line 12
    add-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    iput v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->counter:I

    .line 15
    .line 16
    :cond_0
    return v0
.end method

.method public resetCounter()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/util/CountingInputStream;->counter:I

    .line 3
    .line 4
    return-void
.end method
