.class public abstract Lv81/a;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-wide v0, Lu81/b;->e:J

    .line 5
    .line 6
    iput-wide v0, p0, Lv81/a;->a:J

    .line 7
    .line 8
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 9
    .line 10
    const/16 v1, 0x10

    .line 11
    .line 12
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lv81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final getTickInterval-UwyO8pc$remoteparkassistcoremeb_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lv81/a;->a:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "PPESubStateMachine"

    .line 2
    .line 3
    return-object p0
.end method
