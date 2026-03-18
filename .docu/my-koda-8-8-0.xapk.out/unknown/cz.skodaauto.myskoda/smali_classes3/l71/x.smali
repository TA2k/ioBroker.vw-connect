.class public interface abstract Ll71/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static synthetic b(Ll71/x;ZLjava/lang/Boolean;ZZLjava/lang/Boolean;I)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 3

    .line 1
    and-int/lit8 v0, p6, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p6, 0x2

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move-object p2, v2

    .line 13
    :cond_1
    and-int/lit8 v0, p6, 0x8

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    move p4, v1

    .line 18
    :cond_2
    and-int/lit8 p6, p6, 0x10

    .line 19
    .line 20
    if-eqz p6, :cond_3

    .line 21
    .line 22
    move-object p5, v2

    .line 23
    :cond_3
    invoke-interface/range {p0 .. p5}, Ll71/x;->a(ZLjava/lang/Boolean;ZZLjava/lang/Boolean;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method


# virtual methods
.method public a(ZLjava/lang/Boolean;ZZLjava/lang/Boolean;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method
