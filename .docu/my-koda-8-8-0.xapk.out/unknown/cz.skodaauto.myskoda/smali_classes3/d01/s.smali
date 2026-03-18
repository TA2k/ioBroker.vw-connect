.class public final Ld01/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/n;


# instance fields
.field public final d:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ld01/s;->d:Ljava/util/List;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Laq/k;

    .line 2
    .line 3
    check-cast p1, Lgp/f;

    .line 4
    .line 5
    iget-object p0, p0, Ld01/s;->d:Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    xor-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    const-string v1, "Geofences must contains at least one id."

    .line 14
    .line 15
    invoke-static {v0, v1}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Lgp/l;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    const-string v2, ""

    .line 22
    .line 23
    invoke-direct {v0, p0, v1, v2}, Lgp/l;-><init>(Ljava/util/List;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, v0, p2}, Lgp/f;->C(Lgp/l;Laq/k;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
