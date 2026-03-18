.class public final Lq51/h;
.super Lq51/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/Exception;I)V
    .locals 2

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p1, v1

    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    move-object p2, v1

    .line 12
    :cond_1
    invoke-static {p1}, Lkp/y5;->d(Ljava/lang/String;)Le91/b;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-eqz p2, :cond_2

    .line 17
    .line 18
    sget-object p3, Le91/c;->c:Le91/c;

    .line 19
    .line 20
    invoke-virtual {p1, p3, p2}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    :cond_2
    invoke-direct {p0, p1}, Lq51/p;-><init>(Le91/b;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
