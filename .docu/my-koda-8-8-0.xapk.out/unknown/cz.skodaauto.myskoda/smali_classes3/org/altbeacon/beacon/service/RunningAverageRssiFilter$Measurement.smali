.class Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Measurement"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/lang/Comparable<",
        "Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;",
        ">;"
    }
.end annotation


# instance fields
.field rssi:Ljava/lang/Integer;

.field final synthetic this$0:Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;

.field timestamp:J


# direct methods
.method private constructor <init>(Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;)V
    .locals 0

    .line 2
    iput-object p1, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->this$0:Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;-><init>(Lorg/altbeacon/beacon/service/RunningAverageRssiFilter;)V

    return-void
.end method


# virtual methods
.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;

    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->compareTo(Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;)I

    move-result p0

    return p0
.end method

.method public compareTo(Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;)I
    .locals 0

    .line 2
    iget-object p0, p0, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->rssi:Ljava/lang/Integer;

    iget-object p1, p1, Lorg/altbeacon/beacon/service/RunningAverageRssiFilter$Measurement;->rssi:Ljava/lang/Integer;

    invoke-virtual {p0, p1}, Ljava/lang/Integer;->compareTo(Ljava/lang/Integer;)I

    move-result p0

    return p0
.end method
