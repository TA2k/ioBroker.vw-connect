.class public final Lq51/f;
.super Lq51/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    new-instance v0, Le91/b;

    .line 2
    .line 3
    invoke-direct {v0}, Le91/b;-><init>()V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    sget-object v1, Le91/c;->c:Le91/c;

    .line 9
    .line 10
    invoke-virtual {v0, v1, p1}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    invoke-direct {p0, v0}, Lq51/p;-><init>(Le91/b;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
