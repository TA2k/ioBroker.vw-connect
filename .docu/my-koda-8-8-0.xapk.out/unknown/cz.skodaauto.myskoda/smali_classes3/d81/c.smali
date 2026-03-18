.class public abstract Ld81/c;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;-><init>()V

    .line 2
    .line 3
    .line 4
    sget v0, La81/a;->c:I

    .line 5
    .line 6
    sget-wide v0, La81/a;->a:J

    .line 7
    .line 8
    iput-wide v0, p0, Ld81/c;->a:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final getTickInterval-UwyO8pc$remoteparkassistcoremeb_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ld81/c;->a:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "RPASubStateMachine"

    .line 2
    .line 3
    return-object p0
.end method
